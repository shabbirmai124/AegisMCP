#![deny(clippy::print_stdout)]

mod audit;
mod config;
mod engine;
mod error;
mod mcp_gateway;
mod net_proxy;
mod policy;
mod sandbox;
mod tui;

use crate::audit::{AuditLedger, verify_chain, verify_receipt};
use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::mcp_gateway::AegisMcpServer;
use crate::policy::{PolicyTier, SandboxPolicy};
use crate::sandbox::run_isolated_js;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rmcp::ServiceExt;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum TransportMode {
    Stdio,
    Http,
}

#[derive(Parser)]
#[command(
    name = "aegis-mcp",
    version,
    about = "AegisMCP: Zero-Trust WebAssembly Sandbox Server & Flight Recorder"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server (pure JSON-RPC over stdio; HTTP when built with --features http).
    Serve {
        /// Path to aegis.toml configuration file.
        #[arg(long, default_value = "aegis.toml")]
        config: PathBuf,
        /// Optional override path to SQLite audit database.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Transport mode: stdio (default) or http.
        #[arg(long, value_enum, default_value_t = TransportMode::Stdio)]
        transport: TransportMode,
        /// Bind address when using --transport http.
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Launch the real-time Terminal Flight Recorder dashboard against the SQLite WAL ledger.
    Monitor {
        /// Path to SQLite audit database.
        #[arg(long, default_value = "audit.db")]
        db: PathBuf,
        /// Polling interval in milliseconds.
        #[arg(long, default_value_t = 100)]
        refresh_ms: u64,
    },
    /// Precompile the guest WebAssembly artifact into a SHA-256 verified AOT .cwasm cache entry.
    Precompile {
        /// Path to aegis.toml configuration file.
        #[arg(long, default_value = "aegis.toml")]
        config: PathBuf,
        /// Force recompilation even if a verified cached .cwasm artifact exists.
        #[arg(long)]
        force: bool,
    },
    /// Cryptographically verify the SQLite audit ledger hash chain (or a single run_id receipt).
    Verify {
        /// Path to SQLite audit database.
        #[arg(long, default_value = "audit.db")]
        db: PathBuf,
        /// Optional run_id to verify alongside the full hash chain.
        #[arg(long)]
        run_id: Option<String>,
    },
    /// Run config, guest Wasm, AOT cache, SQLite WAL, and live sub-5ms Wasmtime sandbox diagnostics.
    Doctor {
        /// Path to aegis.toml configuration file.
        #[arg(long, default_value = "aegis.toml")]
        config: PathBuf,
    },
}

fn init_stderr_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_stderr_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            config,
            db,
            transport,
            bind,
        } => {
            let mut cfg = AegisConfig::load_or_default(&config)?;
            if let Some(db_override) = db {
                cfg.server.db_path = db_override;
            }
            let cfg = Arc::new(cfg);

            if transport == TransportMode::Http {
                #[cfg(feature = "http")]
                {
                    let engine = Arc::new(AegisEngine::initialize(&cfg)?);
                    let _ticker = engine.spawn_epoch_ticker();
                    let ledger = AuditLedger::open(&cfg.server.db_path)?;
                    let _service = mcp_gateway::build_streamable_http_service(
                        cfg.clone(),
                        engine.clone(),
                        ledger,
                    );
                    anyhow::bail!(
                        "Streamable HTTP service initialized for {bind}; attach a tower/hyper listener or run `--transport stdio`."
                    );
                }
                #[cfg(not(feature = "http"))]
                {
                    anyhow::bail!(
                        "HTTP transport requested for '{bind}', but binary was compiled without `--features http`"
                    );
                }
            }

            let engine = Arc::new(AegisEngine::initialize(&cfg)?);
            let guest_path = cfg.resolve_guest_wasm_path();
            if guest_path.exists() {
                match engine.precompile_wasm_file(&guest_path, false) {
                    Ok(rep) => tracing::info!(
                        "Guest runtime cached at {} (hit={}, {} bytes)",
                        rep.cwasm_path.display(),
                        rep.cache_hit,
                        rep.size_bytes
                    ),
                    Err(e) => tracing::warn!("Guest precompile skipped: {e}"),
                }
            }

            let ticker_token = engine.spawn_epoch_ticker();
            let ledger = AuditLedger::open(&cfg.server.db_path)?;
            let server = AegisMcpServer::new(cfg, engine, ledger);

            tracing::info!("AegisMCP stdio server listening (stdout reserved strictly for JSON-RPC)");
            let running = server.serve(rmcp::transport::io::stdio()).await?;
            running.waiting().await?;
            ticker_token.cancel();
            Ok(())
        }
        Commands::Monitor { db, refresh_ms } => {
            tui::run_monitor_tui(&db, refresh_ms)?;
            Ok(())
        }
        Commands::Precompile { config, force } => {
            let cfg = AegisConfig::load_or_default(&config)?;
            let engine = AegisEngine::initialize(&cfg)?;
            let guest_path = cfg.resolve_guest_wasm_path();
            let report = engine.precompile_wasm_file(&guest_path, force)?;
            let mut out = std::io::stdout().lock();
            writeln!(
                out,
                "Precompiled {} -> {} ({} bytes, sha256={}, cache_hit={})",
                guest_path.display(),
                report.cwasm_path.display(),
                report.size_bytes,
                &report.cwasm_sha256[..16],
                report.cache_hit
            )?;
            for (plugin_name, plugin_path) in &cfg.plugins {
                let p_rep = engine.precompile_wasm_file(plugin_path, force)?;
                writeln!(
                    out,
                    "Precompiled plugin '{plugin_name}' -> {} ({} bytes, cache_hit={})",
                    p_rep.cwasm_path.display(),
                    p_rep.size_bytes,
                    p_rep.cache_hit
                )?;
            }
            Ok(())
        }
        Commands::Verify { db, run_id } => {
            let mut out = std::io::stdout().lock();
            if let Some(id) = run_id {
                let report = verify_receipt(&db, &id)?;
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
                if !report.found || !report.receipt_valid || !report.chain_valid {
                    anyhow::bail!("Receipt or hash chain verification FAILED for run_id '{id}'");
                }
            } else {
                let report = verify_chain(&db)?;
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
                if !report.valid {
                    anyhow::bail!("Audit ledger hash chain integrity check FAILED");
                }
            }
            Ok(())
        }
        Commands::Doctor { config } => {
            let cfg = AegisConfig::load_or_default(&config)?;
            let guest_path = cfg.resolve_guest_wasm_path();
            let guest_exists = guest_path.exists();
            let guest_size = std::fs::metadata(&guest_path).map(|m| m.len()).unwrap_or(0);

            let engine = AegisEngine::initialize(&cfg)?;
            let ticker = engine.spawn_epoch_ticker();

            let (precompile_status, cwasm_size) = if guest_exists {
                let rep = engine.precompile_wasm_file(&guest_path, false)?;
                (
                    format!(
                        "OK ({}, {} bytes, sha256={}..., cache_hit={})",
                        rep.cwasm_path.display(),
                        rep.size_bytes,
                        &rep.cwasm_sha256[..12],
                        rep.cache_hit
                    ),
                    rep.size_bytes,
                )
            } else {
                (
                    "MISSING (build crates/aegis-guest-js for wasm32-wasip1)".to_string(),
                    0,
                )
            };

            let ledger = AuditLedger::open(&cfg.server.db_path)?;
            let chain = ledger.verify_chain()?;

            let mut smoke_ok = false;
            let mut warm_latency_us = 0u64;
            let mut smoke_summary = "SKIPPED (guest Wasm missing)".to_string();

            if guest_exists {
                let policy = SandboxPolicy::from_config(&cfg, PolicyTier::PureCompute);
                // First run ensures module is deserialized into hot in-memory cache.
                let _warmup = run_isolated_js(
                    &engine,
                    &cfg,
                    &policy,
                    "1 + 1",
                    serde_json::Value::Null,
                    None,
                    None,
                    None,
                )
                .await;

                // Measured warm execution of `2 + 2`.
                let probe = run_isolated_js(
                    &engine,
                    &cfg,
                    &policy,
                    "2 + 2",
                    serde_json::Value::Null,
                    None,
                    None,
                    None,
                )
                .await;

                warm_latency_us = probe.duration_us;
                smoke_ok = probe.ok && probe.parsed_result == Some(serde_json::json!(4));
                smoke_summary = format!(
                    "ok={} result={} duration={}us ({:.2}ms) fuel={} peak_ram={}B cache_hit={}",
                    probe.ok,
                    probe
                        .parsed_result
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "null".into()),
                    probe.duration_us,
                    probe.duration_us as f64 / 1000.0,
                    probe.fuel_consumed,
                    probe.peak_memory_bytes,
                    probe.cache_hit,
                );
            }

            ticker.cancel();

            let mut out = std::io::stdout().lock();
            writeln!(out, "AegisMCP Doctor Report")?;
            writeln!(out, "  Config:        {} (VALID)", config.display())?;
            writeln!(
                out,
                "  Guest Wasm:    {} (exists={}, {} bytes)",
                guest_path.display(),
                guest_exists,
                guest_size
            )?;
            writeln!(out, "  AOT Cache:     {} ({} bytes)", precompile_status, cwasm_size)?;
            writeln!(
                out,
                "  Audit DB:      {} (WAL OK, records={}, valid={})",
                ledger.db_path().display(),
                chain.total_records,
                chain.valid
            )?;
            writeln!(out, "  Head Hash:     {}", chain.head_hash)?;
            writeln!(
                out,
                "  Sandbox 2+2:   {} (warm_latency={}us)",
                smoke_summary, warm_latency_us
            )?;

            if !guest_exists || !chain.valid || !smoke_ok {
                anyhow::bail!(
                    "Doctor checks failed (guest_exists={guest_exists}, chain_valid={}, smoke_ok={smoke_ok})",
                    chain.valid
                );
            }
            Ok(())
        }
    }
}
