use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::error::{AegisError, ExecutionClassification};
use crate::net_proxy::validate_and_fetch;
use crate::policy::{PolicyTier, SandboxPolicy};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use uuid::Uuid;
use wasmtime::{Linker, ResourceLimiter, Store, Trap};
use wasmtime_wasi::I32Exit;
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

pub struct AegisResourceLimiter {
    max_memory_bytes: usize,
    max_table_elements: usize,
    pub peak_memory_bytes: usize,
    pub memory_limit_hit: bool,
}

impl AegisResourceLimiter {
    pub fn new(max_memory_bytes: usize, max_table_elements: usize) -> Self {
        Self {
            max_memory_bytes,
            max_table_elements,
            peak_memory_bytes: 0,
            memory_limit_hit: false,
        }
    }
}

impl ResourceLimiter for AegisResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_memory_bytes {
            self.memory_limit_hit = true;
            return Ok(false);
        }
        if desired > self.peak_memory_bytes {
            self.peak_memory_bytes = desired;
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.max_table_elements)
    }
}

struct HostState {
    wasi: WasiP1Ctx,
    limiter: AegisResourceLimiter,
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub run_id: String,
    pub ok: bool,
    pub status: String,
    pub classification: ExecutionClassification,
    pub tier: PolicyTier,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_us: u64,
    pub cache_hit: bool,
    pub truncated_output: bool,
    pub stdout: String,
    pub stderr: String,
    pub parsed_result: Option<serde_json::Value>,
    pub console_logs: Vec<String>,
    pub trap_reason: Option<String>,
    pub diagnostic: Option<serde_json::Value>,
    pub scratchpad_files_written: Vec<String>,
}

#[derive(Deserialize)]
struct GuestJsEnvelope {
    ok: bool,
    result: serde_json::Value,
    #[serde(default)]
    console_logs: Vec<String>,
    error: Option<String>,
}

fn dir_total_bytes_and_files(root: &Path) -> anyhow::Result<(usize, Vec<String>)> {
    let mut total = 0usize;
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = entry.metadata()?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len() as usize);
                if let Ok(rel) = path.strip_prefix(root) {
                    files.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    files.sort();
    Ok((total, files))
}

fn error_outcome(
    run_id: String,
    policy: &SandboxPolicy,
    classification: ExecutionClassification,
    err: &AegisError,
    started: Instant,
    cache_hit: bool,
) -> ExecutionOutcome {
    ExecutionOutcome {
        run_id,
        ok: false,
        status: classification.status_label().to_string(),
        classification,
        tier: policy.tier,
        fuel_consumed: 0,
        fuel_budget: policy.max_fuel,
        peak_memory_bytes: 0,
        duration_us: started.elapsed().as_micros() as u64,
        cache_hit,
        truncated_output: false,
        stdout: String::new(),
        stderr: String::new(),
        parsed_result: None,
        console_logs: Vec::new(),
        trap_reason: Some(err.to_string()),
        diagnostic: Some(err.to_llm_diagnostic()),
        scratchpad_files_written: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_isolated_js(
    engine: &AegisEngine,
    cfg: &AegisConfig,
    policy: &SandboxPolicy,
    code: &str,
    input: serde_json::Value,
    scratchpad_seed_files: Option<HashMap<String, String>>,
    readonly_mount_path: Option<&Path>,
    fetch_url: Option<&str>,
) -> ExecutionOutcome {
    let started = Instant::now();
    let run_id = Uuid::new_v4().to_string();

    if scratchpad_seed_files.is_some() && policy.tier != PolicyTier::ScopedScratchpad {
        let err = AegisError::PolicyViolation(
            "files parameter requires scoped_scratchpad policy tier".into(),
        );
        return error_outcome(
            run_id,
            policy,
            ExecutionClassification::CapabilityDenied,
            &err,
            started,
            false,
        );
    }

    if readonly_mount_path.is_some() && policy.tier != PolicyTier::ReadonlyData {
        let err = AegisError::PolicyViolation(
            "readonly_dir parameter requires readonly_data policy tier".into(),
        );
        return error_outcome(
            run_id,
            policy,
            ExecutionClassification::CapabilityDenied,
            &err,
            started,
            false,
        );
    }

    let mut effective_input = input;
    if let Some(url) = fetch_url {
        match validate_and_fetch(url, "GET", None, policy).await {
            Ok(resp) => {
                effective_input = serde_json::json!({
                    "input": effective_input,
                    "fetched_url": resp.final_url,
                    "fetched_status": resp.status,
                    "fetched_bytes": resp.bytes,
                    "fetched_body": resp.body,
                });
            }
            Err(err) => {
                return error_outcome(
                    run_id,
                    policy,
                    ExecutionClassification::CapabilityDenied,
                    &err,
                    started,
                    false,
                );
            }
        }
    }

    let scratch_temp = if policy.tier == PolicyTier::ScopedScratchpad {
        match tempfile::tempdir() {
            Ok(dir) => {
                if let Some(files) = scratchpad_seed_files {
                    let mut total_seed = 0usize;
                    for (rel_name, contents) in files {
                        let clean_rel =
                            match SandboxPolicy::validate_scratchpad_relative_path(&rel_name) {
                                Ok(p) => p,
                                Err(err) => {
                                    return error_outcome(
                                        run_id,
                                        policy,
                                        ExecutionClassification::CapabilityDenied,
                                        &err,
                                        started,
                                        false,
                                    );
                                }
                            };
                        total_seed = total_seed.saturating_add(contents.len());
                        if total_seed > policy.max_scratch_bytes {
                            let err = AegisError::PolicyViolation(format!(
                                "Scratchpad seed files exceed quota ({} bytes)",
                                policy.max_scratch_bytes
                            ));
                            return error_outcome(
                                run_id,
                                policy,
                                ExecutionClassification::CapabilityDenied,
                                &err,
                                started,
                                false,
                            );
                        }
                        let dest = dir.path().join(clean_rel);
                        if let Some(parent) = dest.parent()
                            && let Err(e) = std::fs::create_dir_all(parent)
                        {
                            let err = AegisError::GuestRuntimeError(format!(
                                "Failed creating scratchpad dir: {e}"
                            ));
                            return error_outcome(
                                run_id,
                                policy,
                                ExecutionClassification::GuestRuntimeError,
                                &err,
                                started,
                                false,
                            );
                        }
                        if let Err(e) = std::fs::write(&dest, contents.as_bytes()) {
                            let err = AegisError::GuestRuntimeError(format!(
                                "Failed writing seed file: {e}"
                            ));
                            return error_outcome(
                                run_id,
                                policy,
                                ExecutionClassification::GuestRuntimeError,
                                &err,
                                started,
                                false,
                            );
                        }
                    }
                }
                Some(dir)
            }
            Err(e) => {
                let err = AegisError::EngineError(format!("Failed allocating scratchpad: {e}"));
                return error_outcome(
                    run_id,
                    policy,
                    ExecutionClassification::GuestRuntimeError,
                    &err,
                    started,
                    false,
                );
            }
        }
    } else {
        None
    };

    let validated_ro = if let Some(req_path) = readonly_mount_path {
        match policy.validate_readonly_mount(req_path) {
            Ok(p) => Some(p),
            Err(err) => {
                return error_outcome(
                    run_id,
                    policy,
                    ExecutionClassification::CapabilityDenied,
                    &err,
                    started,
                    false,
                );
            }
        }
    } else {
        None
    };

    let guest_path = cfg.resolve_guest_wasm_path();
    let wasm_bytes = match std::fs::read(&guest_path) {
        Ok(b) => b,
        Err(e) => {
            let err = AegisError::ModuleNotFound(format!(
                "Guest Wasm runtime not found at {}: {e}. Build crates/aegis-guest-js for wasm32-wasip1 first.",
                guest_path.display()
            ));
            return error_outcome(
                run_id,
                policy,
                ExecutionClassification::GuestRuntimeError,
                &err,
                started,
                false,
            );
        }
    };

    let envelope = serde_json::json!({
        "code": code,
        "input": effective_input,
        "tier": policy.tier.as_str(),
    });
    let stdin_bytes = serde_json::to_vec(&envelope).unwrap_or_default();

    let mut outcome = execute_wasm_core(
        run_id,
        engine,
        policy,
        "aegis-guest-js",
        &wasm_bytes,
        &stdin_bytes,
        scratch_temp.as_ref().map(|d| d.path()),
        validated_ro.as_deref(),
        started,
    )
    .await;

    if let Some(dir) = scratch_temp
        && let Ok((total_bytes, files)) = dir_total_bytes_and_files(dir.path())
    {
        outcome.scratchpad_files_written = files;
        if total_bytes > policy.max_scratch_bytes {
            let err = AegisError::PolicyViolation(format!(
                "Scratchpad quota exceeded: {total_bytes} > {} bytes",
                policy.max_scratch_bytes
            ));
            outcome.ok = false;
            outcome.classification = ExecutionClassification::CapabilityDenied;
            outcome.status = outcome.classification.status_label().to_string();
            outcome.trap_reason = Some(err.to_string());
            outcome.diagnostic = Some(err.to_llm_diagnostic());
        }
    }

    if outcome.ok {
        match serde_json::from_str::<GuestJsEnvelope>(outcome.stdout.trim()) {
            Ok(parsed) => {
                outcome.ok = parsed.ok;
                outcome.parsed_result = Some(parsed.result);
                outcome.console_logs = parsed.console_logs;
                if !parsed.ok {
                    let msg = parsed.error.unwrap_or_else(|| "Guest JS error".into());
                    let lower = msg.to_lowercase();
                    let (classification, aegis_err) = if lower.contains("capabilitydenied")
                        || lower.contains("permission")
                        || lower.contains("capability")
                        || lower.contains("not permitted")
                        || lower.contains("read-only")
                        || lower.contains("bad file descriptor")
                    {
                        (
                            ExecutionClassification::CapabilityDenied,
                            AegisError::CapabilityDenied(msg),
                        )
                    } else {
                        (
                            ExecutionClassification::GuestRuntimeError,
                            AegisError::GuestRuntimeError(msg),
                        )
                    };
                    outcome.classification = classification;
                    outcome.status = classification.status_label().to_string();
                    outcome.trap_reason = Some(aegis_err.to_string());
                    outcome.diagnostic = Some(aegis_err.to_llm_diagnostic());
                }
            }
            Err(_) => {
                if outcome.truncated_output {
                    outcome.parsed_result = Some(serde_json::json!({
                        "truncated_at_bytes": policy.max_output_bytes,
                        "preview": outcome.stdout.chars().take(256).collect::<String>(),
                    }));
                } else {
                    let err = AegisError::GuestRuntimeError(
                        "Guest produced malformed JSON output".into(),
                    );
                    outcome.ok = false;
                    outcome.classification = ExecutionClassification::GuestRuntimeError;
                    outcome.status = outcome.classification.status_label().to_string();
                    outcome.trap_reason = Some(err.to_string());
                    outcome.diagnostic = Some(err.to_llm_diagnostic());
                }
            }
        }
    }

    outcome
}

pub async fn run_wasm_bytes(
    engine: &AegisEngine,
    policy: &SandboxPolicy,
    artifact_name: &str,
    wasm_bytes: &[u8],
    stdin_bytes: &[u8],
    readonly_mount_path: Option<&Path>,
) -> ExecutionOutcome {
    let started = Instant::now();
    let run_id = Uuid::new_v4().to_string();

    if readonly_mount_path.is_some() && policy.tier != PolicyTier::ReadonlyData {
        let err = AegisError::PolicyViolation(
            "readonly_dir parameter requires readonly_data policy tier".into(),
        );
        return error_outcome(
            run_id,
            policy,
            ExecutionClassification::CapabilityDenied,
            &err,
            started,
            false,
        );
    }

    let validated_ro = if let Some(req_path) = readonly_mount_path {
        match policy.validate_readonly_mount(req_path) {
            Ok(p) => Some(p),
            Err(err) => {
                return error_outcome(
                    run_id,
                    policy,
                    ExecutionClassification::CapabilityDenied,
                    &err,
                    started,
                    false,
                );
            }
        }
    } else {
        None
    };

    let scratch_temp = if policy.tier == PolicyTier::ScopedScratchpad {
        tempfile::tempdir().ok()
    } else {
        None
    };

    let mut outcome = execute_wasm_core(
        run_id,
        engine,
        policy,
        artifact_name,
        wasm_bytes,
        stdin_bytes,
        scratch_temp.as_ref().map(|d| d.path()),
        validated_ro.as_deref(),
        started,
    )
    .await;

    if let Some(dir) = scratch_temp
        && let Ok((total_bytes, files)) = dir_total_bytes_and_files(dir.path())
    {
        outcome.scratchpad_files_written = files;
        if total_bytes > policy.max_scratch_bytes {
            let err = AegisError::PolicyViolation(format!(
                "Scratchpad quota exceeded: {total_bytes} > {} bytes",
                policy.max_scratch_bytes
            ));
            outcome.ok = false;
            outcome.classification = ExecutionClassification::CapabilityDenied;
            outcome.status = outcome.classification.status_label().to_string();
            outcome.trap_reason = Some(err.to_string());
            outcome.diagnostic = Some(err.to_llm_diagnostic());
        }
    }

    outcome
}

#[allow(clippy::too_many_arguments)]
async fn execute_wasm_core(
    run_id: String,
    engine: &AegisEngine,
    policy: &SandboxPolicy,
    artifact_name: &str,
    wasm_bytes: &[u8],
    stdin_bytes: &[u8],
    scratch_dir: Option<&Path>,
    readonly_dir: Option<&Path>,
    started: Instant,
) -> ExecutionOutcome {
    let (module, cache_hit) = match engine.load_or_compile_bytes(artifact_name, wasm_bytes) {
        Ok(res) => res,
        Err(err) => {
            return error_outcome(
                run_id,
                policy,
                ExecutionClassification::GuestRuntimeError,
                &err,
                started,
                false,
            );
        }
    };

    let stdin_pipe = MemoryInputPipe::new(stdin_bytes.to_vec());
    let stdout_pipe = MemoryOutputPipe::new(policy.max_output_bytes);
    let stderr_pipe = MemoryOutputPipe::new(policy.max_output_bytes);

    let wasi = match policy.build_wasi_p1(
        stdin_pipe,
        stdout_pipe.clone(),
        stderr_pipe.clone(),
        scratch_dir,
        readonly_dir,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            let err = AegisError::CapabilityDenied(format!("WASI policy setup failed: {e}"));
            return error_outcome(
                run_id,
                policy,
                ExecutionClassification::CapabilityDenied,
                &err,
                started,
                cache_hit,
            );
        }
    };

    let limiter = AegisResourceLimiter::new(policy.max_memory_bytes, policy.max_table_elements);
    let mut store = Store::new(&engine.engine, HostState { wasi, limiter });
    store.limiter(|state| &mut state.limiter);

    if let Err(e) = store.set_fuel(policy.max_fuel) {
        let err = AegisError::EngineError(format!("Fuel setup failed: {e}"));
        return error_outcome(
            run_id,
            policy,
            ExecutionClassification::GuestRuntimeError,
            &err,
            started,
            cache_hit,
        );
    }
    let _ = store.fuel_async_yield_interval(Some(engine.fuel_yield_interval()));
    store.set_epoch_deadline(policy.max_epoch_ticks);
    store.epoch_deadline_trap();

    let mut linker: Linker<HostState> = Linker::new(&engine.engine);
    if let Err(e) = wasmtime_wasi::p1::add_to_linker_async(&mut linker, |state| &mut state.wasi) {
        let err = AegisError::EngineError(format!("Linker initialization failed: {e}"));
        return error_outcome(
            run_id,
            policy,
            ExecutionClassification::GuestRuntimeError,
            &err,
            started,
            cache_hit,
        );
    }

    let exec_result: wasmtime::Result<()> = async {
        let instance = linker.instantiate_async(&mut store, &module).await?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        start.call_async(&mut store, ()).await?;
        Ok(())
    }
    .await;

    let remaining_fuel = store.get_fuel().unwrap_or(0);
    let fuel_consumed = policy.max_fuel.saturating_sub(remaining_fuel);
    let peak_memory_bytes = store.data().limiter.peak_memory_bytes;
    let mem_exceeded = store.data().limiter.memory_limit_hit;

    drop(store);

    let stdout_raw = stdout_pipe.contents();
    let stderr_raw = stderr_pipe.contents();
    let truncated_output =
        stdout_raw.len() >= policy.max_output_bytes || stderr_raw.len() >= policy.max_output_bytes;
    let stdout = String::from_utf8_lossy(&stdout_raw).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_raw).into_owned();
    let duration_us = started.elapsed().as_micros() as u64;

    if mem_exceeded {
        let err = AegisError::MemoryLimitExceeded {
            limit_bytes: policy.max_memory_bytes,
        };
        return ExecutionOutcome {
            run_id,
            ok: false,
            status: ExecutionClassification::MemoryLimitExceeded
                .status_label()
                .to_string(),
            classification: ExecutionClassification::MemoryLimitExceeded,
            tier: policy.tier,
            fuel_consumed,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes,
            duration_us,
            cache_hit,
            truncated_output,
            stdout,
            stderr,
            parsed_result: None,
            console_logs: Vec::new(),
            trap_reason: Some(err.to_string()),
            diagnostic: Some(err.to_llm_diagnostic()),
            scratchpad_files_written: Vec::new(),
        };
    }

    match exec_result {
        Ok(()) => ExecutionOutcome {
            run_id,
            ok: true,
            status: ExecutionClassification::Success.status_label().to_string(),
            classification: ExecutionClassification::Success,
            tier: policy.tier,
            fuel_consumed,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes,
            duration_us,
            cache_hit,
            truncated_output,
            stdout,
            stderr,
            parsed_result: None,
            console_logs: Vec::new(),
            trap_reason: None,
            diagnostic: None,
            scratchpad_files_written: Vec::new(),
        },
        Err(err) => {
            if let Some(exit) = err.downcast_ref::<I32Exit>()
                && exit.0 == 0
            {
                return ExecutionOutcome {
                    run_id,
                    ok: true,
                    status: ExecutionClassification::Success.status_label().to_string(),
                    classification: ExecutionClassification::Success,
                    tier: policy.tier,
                    fuel_consumed,
                    fuel_budget: policy.max_fuel,
                    peak_memory_bytes,
                    duration_us,
                    cache_hit,
                    truncated_output,
                    stdout,
                    stderr,
                    parsed_result: None,
                    console_logs: Vec::new(),
                    trap_reason: None,
                    diagnostic: None,
                    scratchpad_files_written: Vec::new(),
                };
            }

            let (classification, aegis_err) = if let Some(trap) = err.downcast_ref::<Trap>() {
                match trap {
                    Trap::OutOfFuel => (
                        ExecutionClassification::OutOfFuel,
                        AegisError::OutOfFuel {
                            budget: policy.max_fuel,
                        },
                    ),
                    Trap::Interrupt => (
                        ExecutionClassification::EpochTimeout,
                        AegisError::EpochTimeout {
                            ticks: policy.max_epoch_ticks,
                        },
                    ),
                    _ => (
                        ExecutionClassification::GuestRuntimeError,
                        AegisError::GuestRuntimeError(format!("Wasm trap: {trap}")),
                    ),
                }
            } else {
                let msg = format!("{err:#}");
                let lower = msg.to_lowercase();
                if lower.contains("out of fuel") {
                    (
                        ExecutionClassification::OutOfFuel,
                        AegisError::OutOfFuel {
                            budget: policy.max_fuel,
                        },
                    )
                } else if lower.contains("interrupt") || lower.contains("epoch") {
                    (
                        ExecutionClassification::EpochTimeout,
                        AegisError::EpochTimeout {
                            ticks: policy.max_epoch_ticks,
                        },
                    )
                } else if lower.contains("memory") && lower.contains("grow") {
                    (
                        ExecutionClassification::MemoryLimitExceeded,
                        AegisError::MemoryLimitExceeded {
                            limit_bytes: policy.max_memory_bytes,
                        },
                    )
                } else if lower.contains("permission")
                    || lower.contains("denied")
                    || lower.contains("capability")
                    || lower.contains("bad file descriptor")
                    || lower.contains("not permitted")
                    || lower.contains("read-only")
                {
                    (
                        ExecutionClassification::CapabilityDenied,
                        AegisError::CapabilityDenied(msg),
                    )
                } else {
                    (
                        ExecutionClassification::GuestRuntimeError,
                        AegisError::GuestRuntimeError(msg),
                    )
                }
            };

            ExecutionOutcome {
                run_id,
                ok: false,
                status: classification.status_label().to_string(),
                classification,
                tier: policy.tier,
                fuel_consumed,
                fuel_budget: policy.max_fuel,
                peak_memory_bytes,
                duration_us,
                cache_hit,
                truncated_output,
                stdout,
                stderr,
                parsed_result: None,
                console_logs: Vec::new(),
                trap_reason: Some(aegis_err.to_string()),
                diagnostic: Some(aegis_err.to_llm_diagnostic()),
                scratchpad_files_written: Vec::new(),
            }
        }
    }
}
