#![allow(dead_code)]

#[path = "../src/audit.rs"]
mod audit;
#[path = "../src/config.rs"]
mod config;
#[path = "../src/engine.rs"]
mod engine;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/net_proxy.rs"]
mod net_proxy;
#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/sandbox.rs"]
mod sandbox;

use audit::{AuditLedger, AuditRecordInput, sha256_hex, verify_chain};
use config::AegisConfig;
use engine::AegisEngine;
use error::{AegisError, ExecutionClassification};
use policy::{PolicyTier, SandboxPolicy};
use rusqlite::Connection;
use sandbox::{run_isolated_js, run_wasm_bytes};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn test_config(temp_root: &Path) -> AegisConfig {
    let mut cfg = AegisConfig::default();
    let workspace_guest = workspace_root().join("target/wasm32-wasip1/release/aegis-guest-js.wasm");
    let crate_guest =
        workspace_root().join("crates/aegis-guest-js/target/wasm32-wasip1/release/aegis-guest-js.wasm");
    cfg.server.guest_wasm_path = if workspace_guest.exists() {
        workspace_guest
    } else {
        crate_guest
    };
    cfg.server.cache_dir = temp_root.join("cwasm_cache");
    cfg.server.db_path = temp_root.join("audit.db");
    cfg
}

fn push_leb_u32(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn push_section(wasm: &mut Vec<u8>, id: u8, payload: &[u8]) {
    wasm.push(id);
    push_leb_u32(wasm, payload.len() as u32);
    wasm.extend_from_slice(payload);
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    push_leb_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

/// Builds a tiny valid WASI preview1 module that checks `environ_sizes_get(0, 4)`
/// and passes `count` (`i32.load(0)`) to `proc_exit(count)`.
/// Exits 0 iff 0 host env vars leaked into the WASI sandbox.
fn build_env_probe_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    let mut types = vec![3];
    types.extend_from_slice(&[0x60, 2, 0x7f, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    types.extend_from_slice(&[0x60, 0, 0]);
    push_section(&mut wasm, 1, &types);

    let mut imports = vec![2];
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "environ_sizes_get");
    imports.push(0x00);
    imports.push(0x00);
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "proc_exit");
    imports.push(0x00);
    imports.push(0x01);
    push_section(&mut wasm, 2, &imports);

    push_section(&mut wasm, 3, &[1, 2]);
    push_section(&mut wasm, 5, &[1, 0x00, 1]);

    let mut exports = vec![2];
    push_str(&mut exports, "memory");
    exports.push(0x02);
    exports.push(0x00);
    push_str(&mut exports, "_start");
    exports.push(0x00);
    exports.push(0x02);
    push_section(&mut wasm, 7, &exports);

    let mut body = vec![0];
    body.extend_from_slice(&[
        0x41, 0x00, // i32.const 0
        0x41, 0x04, // i32.const 4
        0x10, 0x00, // call environ_sizes_get
        0x1a, // drop errno
        0x41, 0x00, // i32.const 0
        0x28, 0x02, 0x00, // i32.load
        0x10, 0x01, // call proc_exit(count)
        0x0b, // end
    ]);
    let mut code = vec![1];
    push_leb_u32(&mut code, body.len() as u32);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);

    wasm
}

#[tokio::test]
async fn test_cpu_dos_infinite_loop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();
    engine
        .precompile_wasm_file(&cfg.resolve_guest_wasm_path(), false)
        .expect("precompile guest");

    let mut policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);
    policy.max_fuel = 2_000_000;
    policy.max_epoch_ticks = 200;

    let started = Instant::now();
    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "while (true) {}",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;
    let elapsed = started.elapsed();

    assert!(!outcome.ok, "Infinite loop must be terminated");
    assert_eq!(
        outcome.classification,
        ExecutionClassification::OutOfFuel,
        "Expected OutOfFuel trap, got {:?} ({:?})",
        outcome.classification,
        outcome.trap_reason
    );
    assert!(
        elapsed.as_secs_f64() < 1.0,
        "Infinite loop took too long to terminate: {:?}",
        elapsed
    );

    // Confirm host engine remains completely healthy after CPU trap.
    let healthy = run_isolated_js(
        &engine,
        &cfg,
        &SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute),
        "2 + 2",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;
    assert!(healthy.ok);
    assert_eq!(healthy.parsed_result, Some(serde_json::json!(4)));
}

#[tokio::test]
async fn test_memory_bomb_oom() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let mut policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);
    policy.max_memory_bytes = 16 * 1024 * 1024;
    policy.max_fuel = 50_000_000;

    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "const arr = []; while (true) { arr.push(new Uint8Array(1024 * 1024)); }",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    assert!(!outcome.ok, "Memory bomb must be blocked");
    assert!(
        outcome.peak_memory_bytes <= policy.max_memory_bytes,
        "Peak memory {} exceeded cap {}",
        outcome.peak_memory_bytes,
        policy.max_memory_bytes
    );
    assert!(
        matches!(
            outcome.classification,
            ExecutionClassification::MemoryLimitExceeded
                | ExecutionClassification::GuestRuntimeError
        ),
        "Unexpected classification for memory bomb: {:?}",
        outcome.classification
    );
}

#[tokio::test]
async fn test_path_traversal_escape() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let payloads = [
        r#"aegisFS.readFile("../../../../etc/passwd")"#,
        r#"aegisFS.readFile("C:\\Windows\\System32\\drivers\\etc\\hosts")"#,
    ];

    for tier in [PolicyTier::PureCompute, PolicyTier::ScopedScratchpad] {
        let policy = SandboxPolicy::from_config(&cfg, tier);
        for code in payloads {
            let outcome = run_isolated_js(
                &engine,
                &cfg,
                &policy,
                code,
                serde_json::Value::Null,
                None,
                None,
                None,
            )
            .await;

            assert!(
                !outcome.ok,
                "Path traversal '{code}' must fail in tier {:?}",
                tier
            );
            assert_eq!(
                outcome.classification,
                ExecutionClassification::CapabilityDenied,
                "Expected CapabilityDenied for '{code}' in tier {:?}, got {:?}: {:?}",
                tier,
                outcome.classification,
                outcome.trap_reason
            );
            assert!(!outcome.stdout.contains("root:x:0:0"));
        }
    }

    // Host-side seed file validation must also block traversal paths.
    let scratch_policy = SandboxPolicy::from_config(&cfg, PolicyTier::ScopedScratchpad);
    let mut bad_files = HashMap::new();
    bad_files.insert("../../etc/passwd".to_string(), "overwrite".to_string());
    let seed_outcome = run_isolated_js(
        &engine,
        &cfg,
        &scratch_policy,
        "1 + 1",
        serde_json::Value::Null,
        Some(bad_files),
        None,
        None,
    )
    .await;
    assert!(!seed_outcome.ok);
    assert_eq!(
        seed_outcome.classification,
        ExecutionClassification::CapabilityDenied
    );
}

#[tokio::test]
async fn test_secret_exfiltration_env_and_socket() {
    // SAFETY: Test-scoped environment variable used strictly to verify WASI sandbox isolation.
    unsafe {
        std::env::set_var("AEGIS_TEST_SECRET", "top_secret_123");
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);

    // 1. Verify zero host environment variables are inherited via WASI environ_sizes_get.
    let probe_wasm = build_env_probe_wasm();
    let wasm_outcome =
        run_wasm_bytes(&engine, &policy, "env-probe", &probe_wasm, &[], None).await;
    assert!(
        wasm_outcome.ok,
        "Expected 0 inherited env vars (exit 0), got {:?}: {:?}",
        wasm_outcome.classification, wasm_outcome.trap_reason
    );

    // 2. Verify JS guest has no Node/Web ambient secrets or raw socket/network APIs.
    let js_outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "({ hasProcess: typeof process !== 'undefined', hasFetch: typeof fetch !== 'undefined', hasRequire: typeof require !== 'undefined', hasWebSocket: typeof WebSocket !== 'undefined' })",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    assert!(js_outcome.ok);
    assert_eq!(
        js_outcome.parsed_result,
        Some(serde_json::json!({
            "hasProcess": false,
            "hasFetch": false,
            "hasRequire": false,
            "hasWebSocket": false
        }))
    );
    assert!(!js_outcome.stdout.contains("top_secret_123"));
}

#[tokio::test]
async fn test_stdout_log_flooding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    // Use default 1 MB output cap and generate >5 MB of guest output.
    let mut policy = SandboxPolicy::from_config(&cfg, PolicyTier::ScopedScratchpad);
    policy.max_fuel = 100_000_000;

    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "const chunk = 'A'.repeat(2048); for (let i = 0; i < 2800; i++) { console.log(chunk); } 'flood_complete'",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    assert!(
        outcome.truncated_output,
        "Expected >5 MB stdout flood to set truncated_output=true (stdout len={}, err={:?})",
        outcome.stdout.len(),
        outcome.trap_reason
    );
    assert!(
        outcome.stdout.len() <= policy.max_output_bytes,
        "Stdout grew past 1 MB cap: {} > {}",
        outcome.stdout.len(),
        policy.max_output_bytes
    );
}

#[tokio::test]
async fn test_readonly_tier_write_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ro_dir = tmp.path().join("readonly_dataset");
    std::fs::create_dir_all(&ro_dir).expect("create ro_dir");
    std::fs::write(ro_dir.join("sample.csv"), "id,val\n1,42\n").expect("seed sample.csv");

    let mut cfg = test_config(tmp.path());
    cfg.tiers.readonly_data.readonly_roots = vec![ro_dir.clone()];
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::ReadonlyData);

    // 1. Reading /data/sample.csv inside ReadonlyData tier MUST succeed.
    let read_outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        r#"aegisFS.readFile("/data/sample.csv")"#,
        serde_json::Value::Null,
        None,
        Some(&ro_dir),
        None,
    )
    .await;
    assert!(
        read_outcome.ok,
        "Expected readFile(/data/sample.csv) to succeed, got {:?}",
        read_outcome.trap_reason
    );
    assert_eq!(
        read_outcome.parsed_result,
        Some(serde_json::json!("id,val\n1,42\n"))
    );

    // 2. Writing /data/pwned.txt inside ReadonlyData tier MUST fail at WASI boundary.
    let write_outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        r#"aegisFS.writeFile("/data/pwned.txt", "x")"#,
        serde_json::Value::Null,
        None,
        Some(&ro_dir),
        None,
    )
    .await;
    assert!(
        !write_outcome.ok,
        "Write attempt in readonly_data tier must be denied"
    );
    assert_eq!(
        write_outcome.classification,
        ExecutionClassification::CapabilityDenied
    );
    assert!(
        !ro_dir.join("pwned.txt").exists(),
        "Host readonly folder must remain completely untouched"
    );
}

#[tokio::test]
async fn test_ssrf_and_domain_allowlist_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let net_policy = SandboxPolicy::from_config(&cfg, PolicyTier::AllowlistedNet);
    let pure_policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);

    let loopback_res =
        net_proxy::validate_and_fetch("http://127.0.0.1:8080", "GET", None, &net_policy).await;
    assert!(
        matches!(loopback_res, Err(AegisError::SsrfBlocked(_))),
        "Expected SsrfBlocked for 127.0.0.1, got {loopback_res:?}"
    );

    let imds_res = net_proxy::validate_and_fetch(
        "http://169.254.169.254/latest/meta-data/",
        "GET",
        None,
        &net_policy,
    )
    .await;
    assert!(
        matches!(imds_res, Err(AegisError::SsrfBlocked(_))),
        "Expected SsrfBlocked for IMDS 169.254.169.254, got {imds_res:?}"
    );

    let evil_res =
        net_proxy::validate_and_fetch("https://evil.example.com", "GET", None, &net_policy).await;
    assert!(
        matches!(evil_res, Err(AegisError::PolicyViolation(_))),
        "Expected PolicyViolation for non-allowlisted domain, got {evil_res:?}"
    );

    // PureCompute must also block outbound network access before DNS/TCP.
    let pure_res =
        net_proxy::validate_and_fetch("https://api.github.com/zen", "GET", None, &pure_policy)
            .await;
    assert!(matches!(pure_res, Err(AegisError::PolicyViolation(_))));
}

#[tokio::test]
async fn test_audit_hash_chain_tamper_detection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("audit.db");
    let ledger = AuditLedger::open(&db_path).expect("open ledger");

    let statuses = ["Pass", "Trapped", "Pass"];
    for (idx, status) in statuses.iter().enumerate() {
        let seq = (idx + 1) as u64;
        ledger
            .record(AuditRecordInput {
                run_id: format!("run-{seq}"),
                tool_name: "execute_isolated_js".into(),
                tier: "pure_compute".into(),
                input_sha256: sha256_hex(format!("code-{seq}").as_bytes()),
                output_sha256: sha256_hex(format!("out-{seq}").as_bytes()),
                fuel_consumed: 1000 * seq,
                fuel_budget: 20_000_000,
                peak_memory_bytes: 1_048_576,
                duration_us: 1_500,
                cache_hit: true,
                status: (*status).to_string(),
                trap_reason: if *status == "Trapped" {
                    Some("OutOfFuel".into())
                } else {
                    None
                },
            })
            .await
            .expect("record");
    }

    let valid_report = verify_chain(&db_path).expect("verify");
    assert!(valid_report.valid, "Initial chain must verify cleanly");
    assert_eq!(valid_report.total_records, 3);

    // Tamper directly with row 2 in SQLite.
    let conn = Connection::open(&db_path).expect("open raw sqlite");
    conn.execute("UPDATE executions SET status = 'Pass' WHERE id = 2", [])
        .expect("tamper row 2");
    drop(conn);

    let tampered_report = verify_chain(&db_path).expect("verify after tamper");
    assert!(
        !tampered_report.valid,
        "Tampered hash chain MUST be detected"
    );
    assert_eq!(tampered_report.broken_at_id, Some(2));
}
