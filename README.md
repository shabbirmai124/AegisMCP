# AegisMCP — Zero-Trust WebAssembly Sandbox Server for AI Agents

AegisMCP is a single-binary, pure-Rust **Model Context Protocol (`rmcp`)** sandbox server and native **Terminal Flight Recorder (`ratatui`)** backed by **Wasmtime (`wasmtime` + `wasmtime-wasi`)**, **Boa ECMAScript (`boa_engine`)** compiled to `wasm32-wasip1`, and a tamper-evident **SHA-256 hash-chained SQLite WAL ledger (`rusqlite`)**.

Every untrusted JavaScript or WebAssembly payload executes inside a disposable, zero-ambient-authority WASI micro-sandbox with deterministic CPU fuel metering, 10ms epoch deadlines, linear memory ceilings, bounded 1 MiB output pipes, SSRF-hardened proxying, and cryptographic audit receipts.

---

## Architecture

```text
AI Agent (Claude Desktop / Gemini CLI / Cursor / MCP Inspector)
   │  JSON-RPC 2.0 over stdio (stdout strictly pure; tracing strictly to stderr)
   ▼
mcp_gateway.rs (rmcp 3.11 — 5 typed MCP tools)
   ├── policy.rs       ── 4-tier deny-by-default WASI capability boundary (zero ambient authority)
   ├── net_proxy.rs    ── Tier 3 HTTPS-only proxy (domain allowlist + DNS/IP SSRF guard + no redirects)
   ├── engine.rs       ── Global Wasmtime Engine + SHA-256-verified .cwasm AOT cache + 10ms epoch ticker
   ├── sandbox.rs      ── Disposable Store + ResourceLimiter + Fuel/Epoch traps + 1 MiB MemoryOutputPipe
   │      └── aegis-guest-js.wasm (wasm32-wasip1 + boa_engine + INPUT + console + WASI aegisFS)
   └── audit.rs        ── Async mpsc writer -> SQLite WAL + deterministic SHA-256 receipt hash chain
          └── tui.rs   ── `aegis-mcp monitor` ratatui Flight Recorder (read-only WAL polling @ 100ms)
```

---

## 4-Tier Threat Model (`aegis.toml`)

Callers may tighten `memory_mb` or `fuel_budget` per call, but may **never** raise limits above the tier ceiling configured in `aegis.toml` (hard upper ceilings: 64 MiB RAM, 100M fuel).

| Tier | Key | Filesystem | Network | Max RAM | Max Fuel | Epoch Deadline |
|---|---|---|---|---|---|---|
| **Tier 0** | `pure_compute` | Denied | Denied | 16 MiB | 20,000,000 | 200 ticks (2.0s) |
| **Tier 1** | `scoped_scratchpad` | Ephemeral `TempDir` -> `/workspace` (RW, 4 MiB quota) | Denied | 32 MiB | 40,000,000 | 500 ticks (5.0s) |
| **Tier 2** | `readonly_data` | Allowlisted `readonly_roots` -> `/data` (Read-Only) | Denied | 32 MiB | 50,000,000 | 500 ticks (5.0s) |
| **Tier 3** | `allowlisted_net` | Denied | Host HTTPS proxy (`allowed_domains`, DNS/IP SSRF guard, 1 MiB body cap, 3s timeout) | 32 MiB | 50,000,000 | 800 ticks (8.0s) |

---

## Exposed MCP Tools

1. **`execute_isolated_js`** — Runs untrusted JS inside `aegis-guest-js.wasm` with globals `INPUT`, `console.log`/`console.error`, and WASI-backed `aegisFS` (`readFile`, `writeFile`, `readDir`). Accepts `code`, `input`, `tier`, `files`, `readonly_dir`, `memory_mb`, `fuel_budget`, and `fetch_url`.
2. **`execute_wasm_binary`** — Runs a base64-encoded WASI preview1 `.wasm` binary (`wasm_base64`) or a configured `[plugins]` binary (`plugin_name`) with optional `stdin`, `tier`, and `readonly_dir`.
3. **`inspect_sandbox_policy`** — Returns active 4-tier limits, `readonly_roots`, `allowed_domains`, configured `plugins`, and `.cwasm` AOT cache statistics.
4. **`verify_execution_receipt`** — Cryptographically verifies a `run_id` receipt and the entire SQLite SHA-256 hash chain.
5. **`list_recent_executions`** — Returns recent execution records and security blocks from `audit.db`.

---

## Build & Verification

```bash
# Linux / macOS
chmod +x scripts/build_all.sh
./scripts/build_all.sh

# Windows (PowerShell)
./scripts/build_all.ps1
```

Manual step-by-step build & verification:

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release
cargo clippy --manifest-path crates/aegis-host/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path crates/aegis-host/Cargo.toml --release
cargo test --manifest-path crates/aegis-host/Cargo.toml -- --nocapture
./target/release/aegis-mcp precompile --config aegis.toml
./target/release/aegis-mcp doctor --config aegis.toml
```

---

## CLI Usage

```bash
# 1. Start the MCP server (pure JSON-RPC on stdout; tracing logs on stderr)
./target/release/aegis-mcp serve --config aegis.toml --db audit.db --transport stdio

# 2. Launch the native ratatui Terminal Flight Recorder (polls WAL every 100ms)
./target/release/aegis-mcp monitor --db audit.db --refresh-ms 100

# 3. Precompile guest .wasm into SHA-256-verified .cwasm AOT cache
./target/release/aegis-mcp precompile --config aegis.toml --force

# 4. Verify the full SHA-256 hash chain (or a single run_id receipt)
./target/release/aegis-mcp verify --db audit.db
./target/release/aegis-mcp verify --db audit.db --run-id <uuid>

# 5. Run full environment, cache, WAL, and live 2+2 Wasmtime latency diagnostics
./target/release/aegis-mcp doctor --config aegis.toml
```

---

## Client Integration & MCP Inspector

Ready-to-paste client configurations are provided in:
- `configs/claude_desktop_config.json` — Claude Desktop
- `configs/gemini_cli_settings.json` — Gemini CLI
- `configs/cursor_mcp.json` — Cursor

Interactive verification with the official MCP Inspector:

```bash
npx @modelcontextprotocol/inspector ./target/release/aegis-mcp serve --config aegis.toml --db audit.db
```

---

## 8-Vector Red-Team Security Suite (`crates/aegis-host/tests/red_team.rs`)

1. `test_cpu_dos_infinite_loop` — Terminates `while (true) {}` via `OutOfFuel` in `< 1s`; confirms host stays healthy.
2. `test_memory_bomb_oom` — Stops `Uint8Array(1 MiB)` loop within the 16 MiB `ResourceLimiter` ceiling.
3. `test_path_traversal_escape` — Blocks `aegisFS.readFile("../../../../etc/passwd")` and Windows `hosts` paths in Tiers 0 & 1 plus seed traversal.
4. `test_secret_exfiltration_env_and_socket` — Confirms host `AEGIS_TEST_SECRET` never leaks into WASI `environ_sizes_get` or JS globals.
5. `test_stdout_log_flooding` — Truncates >5 MiB guest output cleanly at the 1 MiB `MemoryOutputPipe` (`truncated_output == true`).
6. `test_readonly_tier_write_blocked` — Allows `aegisFS.readFile("/data/sample.csv")` while blocking `aegisFS.writeFile("/data/pwned.txt", "x")`.
7. `test_ssrf_and_domain_allowlist_blocked` — Blocks `http://127.0.0.1:8080`, `http://169.254.169.254/latest/meta-data/`, and `https://evil.example.com`.
8. `test_audit_hash_chain_tamper_detection` — Mutates row 2 directly in SQLite (`UPDATE executions SET status = 'Pass' WHERE id = 2`) and proves `verify_chain()` flags `broken_at_id == Some(2)`.
