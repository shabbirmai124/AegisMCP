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

use audit::{AuditLedger, AuditRecordInput, verify_sqlite_chain};
use config::AegisConfig;
use engine::AegisEngine;
use error::{AegisError, ExecutionClassification};
use policy::{PolicyTier, SandboxPolicy};
use rusqlite::Connection;
use sandbox::{run_isolated_js, run_wasm_bytes};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    cfg.engine.guest_js_wasm =
        workspace_root().join("target/wasm32-wasip1/release/aegis-guest-js.wasm");
    cfg.engine.cache_dir = temp_root.join("cwasm_cache");
    cfg.engine.audit_db = temp_root.join("audit.db");
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

    // Type section (3 types):
    // 0: (i32, i32) -> i32  [environ_sizes_get]
    // 1: (i32) -> ()        [proc_exit]
    // 2: () -> ()           [_start]
    let mut types = vec![3];
    types.extend_from_slice(&[0x60, 2, 0x7f, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    types.extend_from_slice(&[0x60, 0, 0]);
    push_section(&mut wasm, 1, &types);

    // Import section (2 imports):
    let mut imports = vec![2];
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "environ_sizes_get");
    imports.push(0x00); // func
    imports.push(0x00); // type 0
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "proc_exit");
    imports.push(0x00); // func
    imports.push(0x01); // type 1
    push_section(&mut wasm, 2, &imports);

    // Function section (1 local function: _start -> type 2)
    push_section(&mut wasm, 3, &[1, 2]);

    // Memory section (1 memory, min 1 page)
    push_section(&mut wasm, 5, &[1, 0x00, 1]);

    // Export section (memory + _start -> func index 2)
    let mut exports = vec![2];
    push_str(&mut exports, "memory");
    exports.push(0x02);
    exports.push(0x00);
    push_str(&mut exports, "_start");
    exports.push(0x00);
    exports.push(0x02);
    push_section(&mut wasm, 7, &exports);

    // Code section (1 body):
    let mut body = vec![0]; // 0 locals
    body.extend_from_slice(&[
        0x41, 0x00, // i32.const 0
        0x41, 0x04, // i32.const 4
        0x10, 0x00, // call 0 (environ_sizes_get)
        0x1a, // drop errno
        0x41, 0x00, // i32.const 0
        0x28, 0x02, 0x00, // i32.load align=2 offset=0
        0x10, 0x01, // call 1 (proc_exit)
        0x0b, // end
    ]);
    let mut code = vec![1];
    push_leb_u32(&mut code, body.len() as u32);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);

    wasm
}

/// Builds a tiny valid WASI preview1 module that attempts `path_open` on fd 3 (/data)
/// for `"pwned.txt"` with O_CREAT (1) and rights FD_WRITE (64), passing errno to `proc_exit`.
fn build_readonly_write_probe_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    // Type section:
    // 0: (i32, i32, i32, i32, i32, i64, i64, i32, i32) -> i32  [path_open]
    // 1: (i32) -> ()                                            [proc_exit]
    // 2: () -> ()                                               [_start]
    let mut types = vec![3];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    types.extend_from_slice(&[0x60, 0, 0]);
    push_section(&mut wasm, 1, &types);

    // Import section:
    let mut imports = vec![2];
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "path_open");
    imports.push(0x00);
    imports.push(0x00);
    push_str(&mut imports, "wasi_snapshot_preview1");
    push_str(&mut imports, "proc_exit");
    imports.push(0x00);
    imports.push(0x01);
    push_section(&mut wasm, 2, &imports);

    // Function section: _start -> type 2
    push_section(&mut wasm, 3, &[1, 2]);

    // Memory section: 1 page
    push_section(&mut wasm, 5, &[1, 0x00, 1]);

    // Export section:
    let mut exports = vec![2];
    push_str(&mut exports, "memory");
    exports.push(0x02);
    exports.push(0x00);
    push_str(&mut exports, "_start");
    exports.push(0x00);
    exports.push(0x02);
    push_section(&mut wasm, 7, &exports);

    // Code section:
    let mut body = vec![0]; // 0 locals
    body.extend_from_slice(&[
        0x41, 0x03, // fd = 3 (/data)
        0x41, 0x00, // dirflags = 0
        0x41, 0x10, // path ptr = 16
        0x41, 0x09, // path len = 9 ("pwned.txt")
        0x41, 0x01, // oflags = O_CREAT (1)
        0x42, 0x40, // fs_rights_base = 64 (FD_WRITE)
        0x42, 0x00, // fs_rights_inheriting = 0
        0x41, 0x00, // fdflags = 0
        0x41, 0x40, // opened_fd out ptr = 64
        0x10, 0x00, // call 0 (path_open)
        0x10, 0x01, // call 1 (proc_exit(errno))
        0x0b, // end
    ]);
    let mut code = vec![1];
    push_leb_u32(&mut code, body.len() as u32);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);

    // Data section: memory 0, offset 16, "pwned.txt"
    let filename = b"pwned.txt";
    let mut data = vec![1, 0x00, 0x41, 0x10, 0x0b];
    push_leb_u32(&mut data, filename.len() as u32);
    data.extend_from_slice(filename);
    push_section(&mut wasm, 11, &data);

    wasm
}

#[tokio::test]
async fn test_cpu_dos_infinite_loop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let mut policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);
    policy.max_fuel = 1_500_000;
    policy.max_epoch_ticks = 200;

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

    assert!(!outcome.ok, "Infinite loop must be terminated");
    assert!(
        matches!(
            outcome.classification,
            ExecutionClassification::OutOfFuel | ExecutionClassification::EpochTimeout
        ),
        "Expected OutOfFuel or EpochTimeout, got {:?}",
        outcome.classification
    );
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
                | ExecutionClassification::OutOfFuel
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

    assert!(SandboxPolicy::validate_scratchpad_relative_path("../../etc/passwd").is_err());
    assert!(SandboxPolicy::validate_scratchpad_relative_path("/etc/shadow").is_err());

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::ScopedScratchpad);
    let mut bad_files = HashMap::new();
    bad_files.insert("../../etc/passwd".to_string(), "overwrite".to_string());

    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "1 + 1",
        serde_json::Value::Null,
        Some(bad_files),
        None,
        None,
    )
    .await;

    assert!(!outcome.ok);
    assert_eq!(
        outcome.classification,
        ExecutionClassification::CapabilityDenied
    );

    let ro_policy = SandboxPolicy::from_config(&cfg, PolicyTier::ReadonlyData);
    assert!(matches!(
        ro_policy.validate_readonly_mount(Path::new("/etc/passwd")),
        Err(AegisError::CapabilityDenied(_))
    ));
}

#[tokio::test]
async fn test_secret_exfiltration_env_and_socket() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);

    // 1. Verify zero host environment variables are inherited via WASI environ_sizes_get.
    let probe_wasm = build_env_probe_wasm();
    let wasm_outcome = run_wasm_bytes(&engine, &policy, &probe_wasm, &[], None).await;
    assert!(
        wasm_outcome.ok,
        "Expected 0 inherited env vars (exit 0), got {:?}: {:?}",
        wasm_outcome.classification, wasm_outcome.error
    );

    // 2. Verify JS guest has no Node/Web ambient secrets or network APIs.
    let js_outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "({ hasProcess: typeof process !== 'undefined', hasFetch: typeof fetch !== 'undefined', hasRequire: typeof require !== 'undefined' })",
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
            "hasRequire": false
        }))
    );
}

#[tokio::test]
async fn test_stdout_log_flooding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cfg = test_config(tmp.path());
    cfg.engine.max_output_bytes = 64 * 1024;
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);
    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &policy,
        "for (let i = 0; i < 4000; i++) { console.log('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'); } 'done'",
        serde_json::Value::Null,
        None,
        None,
        None,
    )
    .await;

    assert!(
        outcome.stdout.len() <= policy.max_output_bytes,
        "Stdout grew past cap: {} > {}",
        outcome.stdout.len(),
        policy.max_output_bytes
    );
}

#[tokio::test]
async fn test_readonly_tier_write_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ro_dir = tmp.path().join("readonly_dataset");
    std::fs::create_dir_all(&ro_dir).expect("create ro_dir");
    std::fs::write(ro_dir.join("seed.csv"), "id,val\n1,42\n").expect("seed file");

    let mut cfg = test_config(tmp.path());
    cfg.tiers.readonly_data.readonly_roots = vec![ro_dir.clone()];
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();

    let policy = SandboxPolicy::from_config(&cfg, PolicyTier::ReadonlyData);
    let probe_wasm = build_readonly_write_probe_wasm();

    let outcome = run_wasm_bytes(&engine, &policy, &probe_wasm, &[], Some(&ro_dir)).await;
    assert!(
        !outcome.ok,
        "Write attempt in readonly_data tier must fail with non-zero errno"
    );
    assert!(
        !ro_dir.join("pwned.txt").exists(),
        "Guest must never be able to create files inside readonly_data mount"
    );
}

#[tokio::test]
async fn test_ssrf_and_domain_allowlist_blocked() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = test_config(tmp.path());
    let net_policy = SandboxPolicy::from_config(&cfg, PolicyTier::AllowlistedNet);
    let pure_policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);

    let blocked_targets = [
        "http://api.github.com/zen",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8080/admin",
        "https://localhost/secret",
        "https://evil-exfil.example.com/steal",
        "https://[::1]/secret",
    ];

    for url in blocked_targets {
        let res = net_proxy::validate_target_url(&net_policy, url).await;
        assert!(
            matches!(res, Err(AegisError::CapabilityDenied(_))),
            "Expected SSRF/allowlist block for {url}, got {res:?}"
        );
    }

    // PureCompute must reject any outbound fetch_url before DNS/network.
    let engine = AegisEngine::initialize(&cfg).expect("engine");
    let _ticker = engine.spawn_epoch_ticker();
    let outcome = run_isolated_js(
        &engine,
        &cfg,
        &pure_policy,
        "1 + 1",
        serde_json::Value::Null,
        None,
        None,
        Some("https://api.github.com/zen"),
    )
    .await;
    assert!(!outcome.ok);
    assert_eq!(
        outcome.classification,
        ExecutionClassification::CapabilityDenied
    );
}

#[tokio::test]
async fn test_audit_hash_chain_tamper_detection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("audit.db");
    let ledger = AuditLedger::open(&db_path).expect("open ledger");

    for idx in 1..=3 {
        ledger
            .record(AuditRecordInput {
                execution_id: format!("exec-{idx}"),
                tool_name: "execute_isolated_js".into(),
                policy_tier: "pure_compute".into(),
                classification: "Success".into(),
                fuel_consumed: 1000 * idx,
                fuel_budget: 20_000_000,
                peak_memory_bytes: 1_048_576,
                duration_ms: 2,
                code_sha256: format!("deadbeef{idx}"),
                summary: format!("run {idx}"),
            })
            .await
            .expect("record");
    }

    let valid_report = verify_sqlite_chain(&db_path).expect("verify");
    assert!(valid_report.valid, "Initial chain must verify cleanly");
    assert_eq!(valid_report.total_records, 3);

    // Tamper directly with row 2 in SQLite.
    let conn = Connection::open(&db_path).expect("open raw sqlite");
    conn.execute(
        "UPDATE executions SET summary = 'TAMPERED' WHERE seq = 2",
        [],
    )
    .expect("tamper row 2");
    drop(conn);

    let tampered_report = verify_sqlite_chain(&db_path).expect("verify after tamper");
    assert!(
        !tampered_report.valid,
        "Tampered hash chain MUST be detected"
    );
    assert_eq!(tampered_report.broken_at_seq, Some(2));
}
