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

## Running on Windows (Step-by-Step PowerShell Guide)

### Step 1: Install Prerequisites on Windows 10 / 11

1. **Install Visual Studio C++ Build Tools** (required by Rust's MSVC linker and `rusqlite` bundled SQLite compilation):
   - Download **Build Tools for Visual Studio** from https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Run the installer and check **"Desktop development with C++"**, then click **Install**.
2. **Install Rust (`rustup` + `cargo`):**
   - Download and run `rustup-init.exe` from https://rustup.rs/ (or install via Winget in PowerShell):
     ```powershell
     winget install Rustlang.Rustup
     ```
   - Close and reopen **Windows Terminal / PowerShell** so `cargo`, `rustc`, and `rustup` are in your `PATH`.
3. **Verify your Rust toolchain in PowerShell:**
   ```powershell
   rustc --version
   cargo --version
   rustup --version
   ```
   *(Requires Rust `1.85+` for Rust Edition `2024`. Run `rustup update stable` if you have an older version.)*

### Step 2: Open the Repository Folder in PowerShell

```powershell
cd C:\path\to\aegis-mcp
```

### Step 3: One-Command Full Build, Lint, Test & Diagnostics (Recommended)

Run the bundled PowerShell build script (uses `-ExecutionPolicy Bypass` so Windows does not block local `.ps1` scripts):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_all.ps1
```

This single script automatically:
1. Installs the `wasm32-wasip1` Rust compilation target.
2. Compiles the isolated JavaScript WASI guest (`crates/aegis-guest-js`) in release mode (`target\wasm32-wasip1\release\aegis-guest-js.wasm`).
3. Runs `cargo clippy --all-targets -- -D warnings` (strict zero-warning check).
4. Compiles the native Windows host binary (`target\release\aegis-mcp.exe`).
5. Runs all **8 red-team security & tamper-detection integration tests**.
6. Precompiles the AOT `.cwasm` cache (`precompile`) and runs the live `2 + 2` Wasmtime sandbox check (`doctor`).

### Step 4: Manual Step-by-Step Windows Commands

If you prefer running each step individually in PowerShell:

```powershell
# 1. Add the WebAssembly WASI Preview 1 target
rustup target add wasm32-wasip1

# 2. Build the WASI JavaScript guest binary (.wasm)
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release

# 3. Run strict Clippy lint checks on the host crate
cargo clippy --manifest-path crates/aegis-host/Cargo.toml --all-targets -- -D warnings

# 4. Build the release Windows executable (target\release\aegis-mcp.exe)
cargo build --manifest-path crates/aegis-host/Cargo.toml --release

# 5. Run all 8 real red-team security tests
cargo test --manifest-path crates/aegis-host/Cargo.toml -- --nocapture

# 6. Precompile .wasm -> SHA-256 verified .cwasm AOT cache
.\target\release\aegis-mcp.exe precompile --config aegis.toml

# 7. Run self-diagnostics and verify sub-5ms warm Wasmtime execution
.\target\release\aegis-mcp.exe doctor --config aegis.toml
```

### Step 5: Run the MCP Server & Live Terminal Flight Recorder on Windows

Open **two Windows Terminal / PowerShell tabs** inside the project directory:

**Tab 1 — Start the Headless MCP Server (`stdio` JSON-RPC):**
```powershell
.\target\release\aegis-mcp.exe serve --config aegis.toml --db audit.db --transport stdio
```
*(All diagnostic logs go strictly to `stderr`; `stdout` is reserved exclusively for MCP JSON-RPC frames.)*

**Tab 2 — Launch the Live `ratatui` Terminal Flight Recorder:**
```powershell
.\target\release\aegis-mcp.exe monitor --db audit.db --refresh-ms 100
```
- Use `Up` / `Down` or `j` / `k` to inspect executions and SHA-256 receipts.
- Press `f` to cycle filters (`All` / `Pass` / `Trapped` / `Blocked`).
- Press `v` to run live cryptographic SHA-256 hash-chain verification.
- Press `q` or `Esc` to exit cleanly.

**Verify the Audit Hash Chain Anytime:**
```powershell
# Verify entire SQLite WAL ledger
.\target\release\aegis-mcp.exe verify --db audit.db

# Verify a specific execution receipt UUID
.\target\release\aegis-mcp.exe verify --db audit.db --run-id <run-uuid>
```

### Step 6: Connect Claude Desktop, Cursor, or Gemini CLI on Windows

Use **forward slashes (`/` or escaped `\\`)** with the full Windows path to `aegis-mcp.exe`:

- **Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`):
  ```json
  {
    "mcpServers": {
      "aegis-mcp": {
        "command": "C:\\path\\to\\aegis-mcp\\target\\release\\aegis-mcp.exe",
        "args": [
          "serve",
          "--config",
          "C:\\path\\to\\aegis-mcp\\aegis.toml",
          "--db",
          "C:\\path\\to\\aegis-mcp\\audit.db"
        ]
      }
    }
  }
  ```
- **Interactive Testing with MCP Inspector on Windows** (optional, requires Node.js on your PC only to run the external inspector tool):
  ```powershell
  npx @modelcontextprotocol/inspector .\target\release\aegis-mcp.exe serve --config aegis.toml --db audit.db
  ```

### Windows Troubleshooting

- **`linker 'link.exe' not found`:** Install Visual Studio Build Tools with the **"Desktop development with C++"** workload, then restart PowerShell.
- **`running scripts is disabled on this system`:** Run with `powershell -ExecutionPolicy Bypass -File .\scripts\build_all.ps1`.
- **Slow first compile:** The initial release build compiles `wasmtime` (Cranelift), `boa_engine`, and bundled SQLite (`rusqlite`) from source (~2–4 minutes). Subsequent incremental builds take only a few seconds.
- **TUI box characters look misaligned:** Use **Windows Terminal** (recommended) instead of legacy `cmd.exe` for full UTF-8/Unicode sparkline and border rendering.

---

## Running on Linux / macOS

```bash
# One-command build, lint, test, precompile, and doctor
chmod +x scripts/build_all.sh
./scripts/build_all.sh
```

Manual Linux / macOS commands:

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release
cargo clippy --manifest-path crates/aegis-host/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path crates/aegis-host/Cargo.toml --release
cargo test --manifest-path crates/aegis-host/Cargo.toml -- --nocapture
./target/release/aegis-mcp precompile --config aegis.toml
./target/release/aegis-mcp doctor --config aegis.toml
```

CLI usage on Linux / macOS:

```bash
# Start MCP server over stdio
./target/release/aegis-mcp serve --config aegis.toml --db audit.db --transport stdio

# Launch native ratatui Terminal Flight Recorder
./target/release/aegis-mcp monitor --db audit.db --refresh-ms 100

# Verify SHA-256 hash chain
./target/release/aegis-mcp verify --db audit.db
```

Ready-to-paste client configs are included in `configs/claude_desktop_config.json`, `configs/gemini_cli_settings.json`, and `configs/cursor_mcp.json`.

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
