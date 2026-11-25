use crate::error::AegisError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const HARD_MAX_MEMORY_MB: u64 = 64;
pub const HARD_MAX_FUEL: u64 = 100_000_000;
pub const DEFAULT_FUEL_YIELD_INTERVAL: u64 = 100_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AegisConfig {
    pub server: ServerConfig,
    pub tiers: TiersConfig,
    #[serde(default)]
    pub plugins: HashMap<String, PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub db_path: PathBuf,
    pub cache_dir: PathBuf,
    pub guest_wasm_path: PathBuf,
    pub epoch_tick_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TiersConfig {
    pub pure_compute: PureComputeTierConfig,
    pub scoped_scratchpad: ScratchpadTierConfig,
    pub readonly_data: ReadOnlyTierConfig,
    pub allowlisted_net: NetworkTierConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PureComputeTierConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_table_elements: usize,
    #[serde(default)]
    pub allow_fs: bool,
    #[serde(default)]
    pub allow_net: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScratchpadTierConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_table_elements: usize,
    pub max_scratch_bytes: usize,
    #[serde(default)]
    pub allow_net: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadOnlyTierConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_table_elements: usize,
    #[serde(default)]
    pub readonly_roots: Vec<PathBuf>,
    #[serde(default)]
    pub allow_net: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkTierConfig {
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_table_elements: usize,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allow_http_plaintext: bool,
    pub max_response_bytes: usize,
    pub request_timeout_ms: u64,
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                db_path: PathBuf::from("audit.db"),
                cache_dir: PathBuf::from(".cache/cwasm"),
                guest_wasm_path: PathBuf::from(
                    "target/wasm32-wasip1/release/aegis-guest-js.wasm",
                ),
                epoch_tick_ms: 10,
                max_output_bytes: 1_048_576,
            },
            tiers: TiersConfig {
                pure_compute: PureComputeTierConfig {
                    max_memory_mb: 16,
                    max_fuel: 20_000_000,
                    max_epoch_ticks: 200,
                    max_table_elements: 10_000,
                    allow_fs: false,
                    allow_net: false,
                },
                scoped_scratchpad: ScratchpadTierConfig {
                    max_memory_mb: 32,
                    max_fuel: 40_000_000,
                    max_epoch_ticks: 500,
                    max_table_elements: 10_000,
                    max_scratch_bytes: 4_194_304,
                    allow_net: false,
                },
                readonly_data: ReadOnlyTierConfig {
                    max_memory_mb: 32,
                    max_fuel: 50_000_000,
                    max_epoch_ticks: 500,
                    max_table_elements: 10_000,
                    readonly_roots: Vec::new(),
                    allow_net: false,
                },
                allowlisted_net: NetworkTierConfig {
                    max_memory_mb: 32,
                    max_fuel: 50_000_000,
                    max_epoch_ticks: 800,
                    max_table_elements: 10_000,
                    allowed_domains: vec!["api.github.com".to_string()],
                    allow_http_plaintext: false,
                    max_response_bytes: 1_048_576,
                    request_timeout_ms: 3_000,
                },
            },
            plugins: HashMap::new(),
        }
    }
}

impl AegisConfig {
    pub fn load(path: &Path) -> Result<Self, AegisError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            AegisError::ConfigError(format!("Failed to read config at {}: {e}", path.display()))
        })?;
        let cfg: Self = toml::from_str(&raw)
            .map_err(|e| AegisError::ConfigError(format!("Invalid aegis.toml schema: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_or_default(path: &Path) -> Result<Self, AegisError> {
        if path.exists() {
            Self::load(path)
        } else {
            let cfg = Self::default();
            cfg.validate()?;
            Ok(cfg)
        }
    }

    pub fn resolve_guest_wasm_path(&self) -> PathBuf {
        if self.server.guest_wasm_path.exists() {
            return self.server.guest_wasm_path.clone();
        }
        let candidates = [
            PathBuf::from("target/wasm32-wasip1/release/aegis-guest-js.wasm"),
            PathBuf::from("crates/aegis-guest-js/target/wasm32-wasip1/release/aegis-guest-js.wasm"),
        ];
        for candidate in candidates {
            if candidate.exists() {
                return candidate;
            }
        }
        self.server.guest_wasm_path.clone()
    }

    pub fn validate(&self) -> Result<(), AegisError> {
        if self.server.epoch_tick_ms == 0 {
            return Err(AegisError::ConfigError(
                "server.epoch_tick_ms must be > 0".into(),
            ));
        }
        if self.server.max_output_bytes == 0 || self.server.max_output_bytes > 16 * 1024 * 1024 {
            return Err(AegisError::ConfigError(
                "server.max_output_bytes must be between 1 and 16 MiB".into(),
            ));
        }

        validate_tier_bounds(
            "pure_compute",
            self.tiers.pure_compute.max_memory_mb,
            self.tiers.pure_compute.max_fuel,
            self.tiers.pure_compute.max_epoch_ticks,
            self.tiers.pure_compute.max_table_elements,
        )?;
        validate_tier_bounds(
            "scoped_scratchpad",
            self.tiers.scoped_scratchpad.max_memory_mb,
            self.tiers.scoped_scratchpad.max_fuel,
            self.tiers.scoped_scratchpad.max_epoch_ticks,
            self.tiers.scoped_scratchpad.max_table_elements,
        )?;
        validate_tier_bounds(
            "readonly_data",
            self.tiers.readonly_data.max_memory_mb,
            self.tiers.readonly_data.max_fuel,
            self.tiers.readonly_data.max_epoch_ticks,
            self.tiers.readonly_data.max_table_elements,
        )?;
        validate_tier_bounds(
            "allowlisted_net",
            self.tiers.allowlisted_net.max_memory_mb,
            self.tiers.allowlisted_net.max_fuel,
            self.tiers.allowlisted_net.max_epoch_ticks,
            self.tiers.allowlisted_net.max_table_elements,
        )?;

        if self.tiers.pure_compute.allow_fs || self.tiers.pure_compute.allow_net {
            return Err(AegisError::ConfigError(
                "pure_compute tier must never enable allow_fs or allow_net".into(),
            ));
        }
        if self.tiers.scoped_scratchpad.allow_net || self.tiers.readonly_data.allow_net {
            return Err(AegisError::ConfigError(
                "scoped_scratchpad and readonly_data tiers must not enable allow_net".into(),
            ));
        }
        if self.tiers.allowlisted_net.request_timeout_ms == 0 {
            return Err(AegisError::ConfigError(
                "allowlisted_net.request_timeout_ms must be > 0".into(),
            ));
        }
        if self.tiers.allowlisted_net.max_response_bytes == 0 {
            return Err(AegisError::ConfigError(
                "allowlisted_net.max_response_bytes must be > 0".into(),
            ));
        }
        Ok(())
    }
}

fn validate_tier_bounds(
    name: &str,
    max_memory_mb: u64,
    max_fuel: u64,
    max_epoch_ticks: u64,
    max_table_elements: usize,
) -> Result<(), AegisError> {
    if max_memory_mb == 0 || max_memory_mb > HARD_MAX_MEMORY_MB {
        return Err(AegisError::ConfigError(format!(
            "tiers.{name}.max_memory_mb ({max_memory_mb}) must be in 1..={HARD_MAX_MEMORY_MB}"
        )));
    }
    if max_fuel == 0 || max_fuel > HARD_MAX_FUEL {
        return Err(AegisError::ConfigError(format!(
            "tiers.{name}.max_fuel ({max_fuel}) must be in 1..={HARD_MAX_FUEL}"
        )));
    }
    if max_epoch_ticks == 0 {
        return Err(AegisError::ConfigError(format!(
            "tiers.{name}.max_epoch_ticks must be > 0"
        )));
    }
    if max_table_elements == 0 {
        return Err(AegisError::ConfigError(format!(
            "tiers.{name}.max_table_elements must be > 0"
        )));
    }
    Ok(())
}
