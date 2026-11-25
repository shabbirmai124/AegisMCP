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

use crate::audit::{AuditLedger, verify_sqlite_chain};
use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::mcp_gateway::AegisMcpServer;
use anyhow::Result;
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "aegis-mcp",
    version,
    about = "AegisMCP: Zero-Trust WebAssembly Sandbox Server & Flight Recorder"
)]
struct Cli {
    /// Path to aegis.toml configuration file.
    #[arg(long, global = true, default_value = "aegis.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server (pure JSON-RPC over stdio; HTTP when built with --features http).
    Serve {
        /// Serve over Streamable HTTP instead of stdio (requires --features http).
        #[arg(long)]
        http: Option<String>,
    },
    /// Launch the real-time Terminal Flight Recorder dashboard against the SQLite ledger.
    Monitor {
        /// Polling interval in milliseconds.
        #[arg(long, default_value_t = 100)]
        refresh_ms: u64,
    },
    /// Precompile the guest WebAssembly artifact into an AOT .cwasm cache entry.
    Precompile {
        /// Force recompilation even if a cached .cwasm artifact exists.
        #[arg(long)]
        force: bool,
    },
    /// Cryptographically verify the entire SHA-256 hash chain in the SQLite audit ledger.
    Verify,
    /// Run environment, guest artifact, AOT cache, and SQLite health diagnostics.
    Doctor,
}

fn init_stderr_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

fn load_or_default_config(path: &Path) -> Result<AegisConfig> {
    if path.exists() {
        AegisConfig::load(path)
    } else {
        tracing::warn!(
            "Config {} not found; falling back to strict built-in defaults",
            path.display()
        );
        let cfg = AegisConfig::default();
        cfg.validate()?;
        Ok(cfg)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_stderr_tracing();
    let cli = Cli::parse();
    let cfg = Arc::new(load_or_default_config(&cli.config)?);

    match cli.command {
        Commands::Serve { http } => {
            if let Some(bind_addr) = http {
                #[cfg(feature = "http")]
                {
                    let engine = Arc::new(AegisEngine::initialize(&cfg)?);
                    let _ticker = engine.spawn_epoch_ticker();
                    let ledger = AuditLedger::open(&cfg.engine.audit_db)?;
                    let _service = mcp_gateway::build_streamable_http_service(
                        cfg.clone(),
                        engine.clone(),
                        ledger,
                    );
                    anyhow::bail!(
                        "Streamable HTTP service initialized for {bind_addr}; attach a tower/hyper listener or run stdio transport."
                    );
                }
                #[cfg(not(feature = "http"))]
                {
                    anyhow::bail!(
                        "HTTP transport requested for '{bind_addr}', but binary was compiled without `--features http`"
                    );
                }
            }

            let engine = Arc::new(AegisEngine::initialize(&cfg)?);
            if cfg.engine.guest_js_wasm.exists() {
                match engine.precompile_wasm_file(&cfg.engine.guest_js_wasm, false) {
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
            let ledger = AuditLedger::open(&cfg.engine.audit_db)?;
            let server = AegisMcpServer::new(cfg, engine, ledger);

            tracing::info!("AegisMCP stdio server listening (stdout reserved strictly for JSON-RPC)");
            let running = server.serve(rmcp::transport::io::stdio()).await?;
            running.waiting().await?;
            ticker_token.cancel();
            Ok(())
        }
        Commands::Monitor { refresh_ms } => {
            tui::run_monitor_tui(&cfg.engine.audit_db, refresh_ms)?;
            Ok(())
        }
        Commands::Precompile { force } => {
            let engine = AegisEngine::initialize(&cfg)?;
            let report = engine.precompile_wasm_file(&cfg.engine.guest_js_wasm, force)?;
            let mut out = std::io::stdout().lock();
            writeln!(
                out,
                "Precompiled {} -> {} ({} bytes, cache_hit={})",
                cfg.engine.guest_js_wasm.display(),
                report.cwasm_path.display(),
                report.size_bytes,
                report.cache_hit
            )?;
            Ok(())
        }
        Commands::Verify => {
            let report = verify_sqlite_chain(&cfg.engine.audit_db)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            if !report.valid {
                anyhow::bail!("Audit ledger hash chain integrity check FAILED");
            }
            Ok(())
        }
        Commands::Doctor => {
            let mut out = std::io::stdout().lock();
            let guest_exists = cfg.engine.guest_js_wasm.exists();
            let guest_size = std::fs::metadata(&cfg.engine.guest_js_wasm)
                .map(|m| m.len())
                .unwrap_or(0);
            let engine = AegisEngine::initialize(&cfg)?;
            let precompile_status = if guest_exists {
                let rep = engine.precompile_wasm_file(&cfg.engine.guest_js_wasm, false)?;
                format!("OK ({}, {} bytes, cache_hit={})", rep.cwasm_path.display(), rep.size_bytes, rep.cache_hit)
            } else {
                "MISSING (build crates/aegis-guest-js for wasm32-wasip1)".to_string()
            };
            let ledger = AuditLedger::open(&cfg.engine.audit_db)?;
            let chain = ledger.verify_chain()?;

            writeln!(out, "AegisMCP Doctor Report")?;
            writeln!(out, "  Config:        {}", cli.config.display())?;
            writeln!(out, "  Guest Wasm:    {} (exists={}, {} bytes)", cfg.engine.guest_js_wasm.display(), guest_exists, guest_size)?;
            writeln!(out, "  AOT Cache:     {}", precompile_status)?;
            writeln!(out, "  Audit DB:      {} (records={}, valid={})", ledger.db_path().display(), chain.total_records, chain.valid)?;
            writeln!(out, "  Head Hash:     {}", chain.head_hash)?;
            if !guest_exists || !chain.valid {
                anyhow::bail!("Doctor checks detected missing artifact or broken audit chain");
            }
            Ok(())
        }
    }
}
