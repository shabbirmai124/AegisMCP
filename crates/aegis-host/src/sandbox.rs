use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::error::{AegisError, ExecutionClassification};
use crate::net_proxy::fetch_allowlisted_get;
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
    pub memory_limit_exceeded: bool,
}

impl AegisResourceLimiter {
    pub fn new(max_memory_bytes: usize, max_table_elements: usize) -> Self {
        Self {
            max_memory_bytes,
            max_table_elements,
            peak_memory_bytes: 0,
            memory_limit_exceeded: false,
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
            self.memory_limit_exceeded = true;
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
pub struct SandboxOutcome {
    pub execution_id: String,
    pub ok: bool,
    pub classification: ExecutionClassification,
    pub policy_tier: PolicyTier,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_ms: u64,
    pub wasm_cold_compile: bool,
    pub stdout: String,
    pub stderr: String,
    pub parsed_result: Option<serde_json::Value>,
    pub console_logs: Vec<String>,
    pub error: Option<String>,
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

fn denied_outcome(
    execution_id: String,
    policy: &SandboxPolicy,
    err: AegisError,
    started: Instant,
) -> SandboxOutcome {
    SandboxOutcome {
        execution_id,
        ok: false,
        classification: ExecutionClassification::CapabilityDenied,
        policy_tier: policy.tier,
        fuel_consumed: 0,
        fuel_budget: policy.max_fuel,
        peak_memory_bytes: 0,
        duration_ms: started.elapsed().as_millis() as u64,
        wasm_cold_compile: false,
        stdout: String::new(),
        stderr: String::new(),
        parsed_result: None,
        console_logs: Vec::new(),
        error: Some(err.to_string()),
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
) -> SandboxOutcome {
    let started = Instant::now();
    let execution_id = Uuid::new_v4().to_string();

    if scratchpad_seed_files.is_some()
        && policy.tier != PolicyTier::ScopedScratchpad
    {
        return denied_outcome(
            execution_id,
            policy,
            AegisError::CapabilityDenied(
                "scratchpad_files requires scoped_scratchpad policy tier".into(),
            ),
            started,
        );
    }

    if readonly_mount_path.is_some() && policy.tier != PolicyTier::ReadonlyData {
        return denied_outcome(
            execution_id,
            policy,
            AegisError::CapabilityDenied(
                "readonly_mount_path requires readonly_data policy tier".into(),
            ),
            started,
        );
    }

    let mut effective_input = input;
    if let Some(url) = fetch_url {
        match fetch_allowlisted_get(policy, url).await {
            Ok(body) => {
                effective_input = serde_json::json!({
                    "input": effective_input,
                    "fetched_url": url,
                    "fetched_body": body,
                });
            }
            Err(err) => {
                return denied_outcome(execution_id, policy, err, started);
            }
        }
    }

    let scratch_temp = if policy.tier == PolicyTier::ScopedScratchpad {
        match tempfile::tempdir() {
            Ok(dir) => {
                if let Some(files) = scratchpad_seed_files {
                    let mut total_seed = 0usize;
                    for (rel_name, contents) in files {
                        let clean_rel = match SandboxPolicy::validate_scratchpad_relative_path(&rel_name) {
                            Ok(p) => p,
                            Err(err) => return denied_outcome(execution_id, policy, err, started),
                        };
                        total_seed = total_seed.saturating_add(contents.len());
                        if total_seed > policy.scratchpad_quota_bytes {
                            return denied_outcome(
                                execution_id,
                                policy,
                                AegisError::CapabilityDenied(format!(
                                    "Scratchpad seed files exceed quota ({} bytes)",
                                    policy.scratchpad_quota_bytes
                                )),
                                started,
                            );
                        }
                        let dest = dir.path().join(clean_rel);
                        if let Some(parent) = dest.parent()
                            && let Err(err) = std::fs::create_dir_all(parent)
                        {
                            return denied_outcome(
                                execution_id,
                                policy,
                                AegisError::GuestRuntime(format!("Failed creating scratchpad dir: {err}")),
                                started,
                            );
                        }
                        if let Err(err) = std::fs::write(&dest, contents.as_bytes()) {
                            return denied_outcome(
                                execution_id,
                                policy,
                                AegisError::GuestRuntime(format!("Failed writing seed file: {err}")),
                                started,
                            );
                        }
                    }
                }
                Some(dir)
            }
            Err(err) => {
                return denied_outcome(
                    execution_id,
                    policy,
                    AegisError::GuestRuntime(format!("Failed allocating scratchpad: {err}")),
                    started,
                );
            }
        }
    } else {
        None
    };

    let validated_ro = if let Some(req_path) = readonly_mount_path {
        match policy.validate_readonly_mount(req_path) {
            Ok(p) => Some(p),
            Err(err) => return denied_outcome(execution_id, policy, err, started),
        }
    } else {
        None
    };

    let wasm_bytes = match std::fs::read(&cfg.engine.guest_js_wasm) {
        Ok(b) => b,
        Err(err) => {
            return SandboxOutcome {
                execution_id,
                ok: false,
                classification: ExecutionClassification::GuestRuntimeError,
                policy_tier: policy.tier,
                fuel_consumed: 0,
                fuel_budget: policy.max_fuel,
                peak_memory_bytes: 0,
                duration_ms: started.elapsed().as_millis() as u64,
                wasm_cold_compile: false,
                stdout: String::new(),
                stderr: String::new(),
                parsed_result: None,
                console_logs: Vec::new(),
                error: Some(format!(
                    "Guest Wasm runtime not found at {}: {err}. Run scripts/build_all.sh first.",
                    cfg.engine.guest_js_wasm.display()
                )),
                scratchpad_files_written: Vec::new(),
            };
        }
    };

    let tier_str = serde_json::to_value(policy.tier)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "pure_compute".to_string());

    let envelope = serde_json::json!({
        "code": code,
        "input": effective_input,
        "tier": tier_str,
    });
    let stdin_bytes = serde_json::to_vec(&envelope).unwrap_or_default();

    let mut outcome = execute_wasm_core(
        execution_id,
        engine,
        policy,
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
        if total_bytes > policy.scratchpad_quota_bytes {
            outcome.ok = false;
            outcome.classification = ExecutionClassification::CapabilityDenied;
            outcome.error = Some(format!(
                "Scratchpad quota exceeded: {total_bytes} > {} bytes",
                policy.scratchpad_quota_bytes
            ));
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
                    if lower.contains("permission")
                        || lower.contains("capability")
                        || lower.contains("not permitted")
                    {
                        outcome.classification = ExecutionClassification::CapabilityDenied;
                    } else {
                        outcome.classification = ExecutionClassification::GuestRuntimeError;
                    }
                    outcome.error = Some(msg);
                }
            }
            Err(_) => {
                if outcome.stdout.len() >= policy.max_output_bytes {
                    outcome.parsed_result = Some(serde_json::json!({
                        "truncated_at_bytes": policy.max_output_bytes,
                        "preview": outcome.stdout.chars().take(256).collect::<String>(),
                    }));
                } else {
                    outcome.ok = false;
                    outcome.classification = ExecutionClassification::GuestRuntimeError;
                    outcome.error = Some("Guest produced malformed JSON output".into());
                }
            }
        }
    }

    outcome
}

pub async fn run_wasm_bytes(
    engine: &AegisEngine,
    policy: &SandboxPolicy,
    wasm_bytes: &[u8],
    stdin_bytes: &[u8],
    readonly_mount_path: Option<&Path>,
) -> SandboxOutcome {
    let started = Instant::now();
    let execution_id = Uuid::new_v4().to_string();

    if readonly_mount_path.is_some() && policy.tier != PolicyTier::ReadonlyData {
        return denied_outcome(
            execution_id,
            policy,
            AegisError::CapabilityDenied(
                "readonly_mount_path requires readonly_data policy tier".into(),
            ),
            started,
        );
    }

    let validated_ro = if let Some(req_path) = readonly_mount_path {
        match policy.validate_readonly_mount(req_path) {
            Ok(p) => Some(p),
            Err(err) => return denied_outcome(execution_id, policy, err, started),
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
        execution_id,
        engine,
        policy,
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
        if total_bytes > policy.scratchpad_quota_bytes {
            outcome.ok = false;
            outcome.classification = ExecutionClassification::CapabilityDenied;
            outcome.error = Some(format!(
                "Scratchpad quota exceeded: {total_bytes} > {} bytes",
                policy.scratchpad_quota_bytes
            ));
        }
    }

    outcome
}

#[allow(clippy::too_many_arguments)]
async fn execute_wasm_core(
    execution_id: String,
    engine: &AegisEngine,
    policy: &SandboxPolicy,
    wasm_bytes: &[u8],
    stdin_bytes: &[u8],
    scratch_dir: Option<&Path>,
    readonly_dir: Option<&Path>,
    started: Instant,
) -> SandboxOutcome {
    let (module, cache_hit) = match engine.load_or_compile_bytes(wasm_bytes) {
        Ok(res) => res,
        Err(err) => {
            return SandboxOutcome {
                execution_id,
                ok: false,
                classification: ExecutionClassification::GuestRuntimeError,
                policy_tier: policy.tier,
                fuel_consumed: 0,
                fuel_budget: policy.max_fuel,
                peak_memory_bytes: 0,
                duration_ms: started.elapsed().as_millis() as u64,
                wasm_cold_compile: false,
                stdout: String::new(),
                stderr: String::new(),
                parsed_result: None,
                console_logs: Vec::new(),
                error: Some(format!("Invalid Wasm module: {err}")),
                scratchpad_files_written: Vec::new(),
            };
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
        Err(err) => {
            return SandboxOutcome {
                execution_id,
                ok: false,
                classification: ExecutionClassification::CapabilityDenied,
                policy_tier: policy.tier,
                fuel_consumed: 0,
                fuel_budget: policy.max_fuel,
                peak_memory_bytes: 0,
                duration_ms: started.elapsed().as_millis() as u64,
                wasm_cold_compile: !cache_hit,
                stdout: String::new(),
                stderr: String::new(),
                parsed_result: None,
                console_logs: Vec::new(),
                error: Some(format!("WASI policy setup failed: {err}")),
                scratchpad_files_written: Vec::new(),
            };
        }
    };

    let limiter = AegisResourceLimiter::new(policy.max_memory_bytes, policy.max_table_elements);
    let mut store = Store::new(&engine.engine, HostState { wasi, limiter });
    store.limiter(|state| &mut state.limiter);

    if let Err(err) = store.set_fuel(policy.max_fuel) {
        return SandboxOutcome {
            execution_id,
            ok: false,
            classification: ExecutionClassification::GuestRuntimeError,
            policy_tier: policy.tier,
            fuel_consumed: 0,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes: 0,
            duration_ms: started.elapsed().as_millis() as u64,
            wasm_cold_compile: !cache_hit,
            stdout: String::new(),
            stderr: String::new(),
            parsed_result: None,
            console_logs: Vec::new(),
            error: Some(format!("Fuel setup failed: {err}")),
            scratchpad_files_written: Vec::new(),
        };
    }
    let _ = store.fuel_async_yield_interval(Some(engine.fuel_yield_interval()));
    store.set_epoch_deadline(policy.max_epoch_ticks);
    store.epoch_deadline_trap();

    let mut linker: Linker<HostState> = Linker::new(&engine.engine);
    if let Err(err) = wasmtime_wasi::p1::add_to_linker_async(&mut linker, |state| &mut state.wasi) {
        return SandboxOutcome {
            execution_id,
            ok: false,
            classification: ExecutionClassification::GuestRuntimeError,
            policy_tier: policy.tier,
            fuel_consumed: 0,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes: 0,
            duration_ms: started.elapsed().as_millis() as u64,
            wasm_cold_compile: !cache_hit,
            stdout: String::new(),
            stderr: String::new(),
            parsed_result: None,
            console_logs: Vec::new(),
            error: Some(format!("Linker initialization failed: {err}")),
            scratchpad_files_written: Vec::new(),
        };
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
    let mem_exceeded = store.data().limiter.memory_limit_exceeded;

    drop(store);

    let stdout_raw = stdout_pipe.contents();
    let stderr_raw = stderr_pipe.contents();
    let stdout = String::from_utf8_lossy(&stdout_raw).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_raw).into_owned();
    let duration_ms = started.elapsed().as_millis() as u64;

    if mem_exceeded {
        return SandboxOutcome {
            execution_id,
            ok: false,
            classification: ExecutionClassification::MemoryLimitExceeded,
            policy_tier: policy.tier,
            fuel_consumed,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes,
            duration_ms,
            wasm_cold_compile: !cache_hit,
            stdout,
            stderr,
            parsed_result: None,
            console_logs: Vec::new(),
            error: Some(
                AegisError::MemoryLimitExceeded {
                    limit_bytes: policy.max_memory_bytes,
                }
                .to_string(),
            ),
            scratchpad_files_written: Vec::new(),
        };
    }

    match exec_result {
        Ok(()) => SandboxOutcome {
            execution_id,
            ok: true,
            classification: ExecutionClassification::Success,
            policy_tier: policy.tier,
            fuel_consumed,
            fuel_budget: policy.max_fuel,
            peak_memory_bytes,
            duration_ms,
            wasm_cold_compile: !cache_hit,
            stdout,
            stderr,
            parsed_result: None,
            console_logs: Vec::new(),
            error: None,
            scratchpad_files_written: Vec::new(),
        },
        Err(err) => {
            if let Some(exit) = err.downcast_ref::<I32Exit>()
                && exit.0 == 0
            {
                return SandboxOutcome {
                    execution_id,
                    ok: true,
                    classification: ExecutionClassification::Success,
                    policy_tier: policy.tier,
                    fuel_consumed,
                    fuel_budget: policy.max_fuel,
                    peak_memory_bytes,
                    duration_ms,
                    wasm_cold_compile: !cache_hit,
                    stdout,
                    stderr,
                    parsed_result: None,
                    console_logs: Vec::new(),
                    error: None,
                    scratchpad_files_written: Vec::new(),
                };
            }

            let (classification, aegis_err) = if mem_exceeded {
                (
                    ExecutionClassification::MemoryLimitExceeded,
                    AegisError::MemoryLimitExceeded {
                        limit_bytes: policy.max_memory_bytes,
                    },
                )
            } else if let Some(trap) = err.downcast_ref::<Trap>() {
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
                        AegisError::GuestRuntime(format!("Wasm trap: {trap}")),
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
                        AegisError::GuestRuntime(msg),
                    )
                }
            };

            SandboxOutcome {
                execution_id,
                ok: false,
                classification,
                policy_tier: policy.tier,
                fuel_consumed,
                fuel_budget: policy.max_fuel,
                peak_memory_bytes,
                duration_ms,
                wasm_cold_compile: !cache_hit,
                stdout,
                stderr,
                parsed_result: None,
                console_logs: Vec::new(),
                error: Some(aegis_err.to_string()),
                scratchpad_files_written: Vec::new(),
            }
        }
    }
}
