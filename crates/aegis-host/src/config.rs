use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AegisConfig {
    pub engine: EngineConfig,
    pub tiers: TiersConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    pub guest_js_wasm: PathBuf,
    pub cache_dir: PathBuf,
    pub audit_db: PathBuf,
    pub epoch_tick_ms: u64,
    pub fuel_yield_interval: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TiersConfig {
    pub pure_compute: TierLimitConfig,
    pub scoped_scratchpad: ScratchpadTierConfig,
    pub readonly_data: ReadOnlyTierConfig,
    pub allowlisted_net: NetworkTierConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TierLimitConfig {
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScratchpadTierConfig {
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub scratchpad_quota_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadOnlyTierConfig {
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub readonly_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkTierConfig {
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub https_only: bool,
    pub max_response_bytes: usize,
    pub allowed_domains: Vec<String>,
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            engine: EngineConfig {
                guest_js_wasm: PathBuf::from("target/wasm32-wasip1/release/aegis-guest-js.wasm"),
                cache_dir: PathBuf::from(".cache/cwasm"),
                audit_db: PathBuf::from("audit.db"),
                epoch_tick_ms: 10,
                fuel_yield_interval: 100_000,
                max_output_bytes: 1_048_576,
            },
            tiers: TiersConfig {
                pure_compute: TierLimitConfig {
                    max_memory_bytes: 16 * 1024 * 1024,
                    max_table_elements: 10_000,
                    max_fuel: 20_000_000,
                    max_epoch_ticks: 200,
                },
                scoped_scratchpad: ScratchpadTierConfig {
                    max_memory_bytes: 32 * 1024 * 1024,
                    max_table_elements: 10_000,
                    max_fuel: 40_000_000,
                    max_epoch_ticks: 500,
                    scratchpad_quota_bytes: 4 * 1024 * 1024,
                },
                readonly_data: ReadOnlyTierConfig {
                    max_memory_bytes: 32 * 1024 * 1024,
                    max_table_elements: 10_000,
                    max_fuel: 50_000_000,
                    max_epoch_ticks: 500,
                    readonly_roots: vec![PathBuf::from("./data")],
                },
                allowlisted_net: NetworkTierConfig {
                    max_memory_bytes: 32 * 1024 * 1024,
                    max_table_elements: 10_000,
                    max_fuel: 50_000_000,
                    max_epoch_ticks: 800,
                    https_only: true,
                    max_response_bytes: 1_048_576,
                    allowed_domains: vec![
                        "api.github.com".to_string(),
                        "registry.npmjs.org".to_string(),
                        "crates.io".to_string(),
                    ],
                },
            },
        }
    }
}

impl AegisConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config at {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw).context("Invalid aegis.toml schema")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.engine.epoch_tick_ms > 0, "epoch_tick_ms must be > 0");
        anyhow::ensure!(
            self.engine.max_output_bytes > 0,
            "max_output_bytes must be > 0"
        );
        anyhow::ensure!(
            self.tiers.pure_compute.max_memory_bytes >= 65_536,
            "pure_compute max_memory_bytes must be at least 1 Wasm page (65536)"
        );
        Ok(())
    }
}
