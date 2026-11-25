use crate::config::AegisConfig;
use crate::error::AegisError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTier {
    PureCompute,
    ScopedScratchpad,
    ReadonlyData,
    AllowlistedNet,
}

impl PolicyTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PureCompute => "pure_compute",
            Self::ScopedScratchpad => "scoped_scratchpad",
            Self::ReadonlyData => "readonly_data",
            Self::AllowlistedNet => "allowlisted_net",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxPolicy {
    pub tier: PolicyTier,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_output_bytes: usize,
    pub max_scratch_bytes: usize,
    pub readonly_roots: Vec<PathBuf>,
    pub allowed_domains: Vec<String>,
    pub allow_http_plaintext: bool,
    pub max_response_bytes: usize,
    pub request_timeout_ms: u64,
}

impl SandboxPolicy {
    pub fn from_config(cfg: &AegisConfig, tier: PolicyTier) -> Self {
        match tier {
            PolicyTier::PureCompute => Self {
                tier,
                max_memory_bytes: (cfg.tiers.pure_compute.max_memory_mb as usize) * 1024 * 1024,
                max_table_elements: cfg.tiers.pure_compute.max_table_elements,
                max_fuel: cfg.tiers.pure_compute.max_fuel,
                max_epoch_ticks: cfg.tiers.pure_compute.max_epoch_ticks,
                max_output_bytes: cfg.server.max_output_bytes,
                max_scratch_bytes: 0,
                readonly_roots: Vec::new(),
                allowed_domains: Vec::new(),
                allow_http_plaintext: false,
                max_response_bytes: 0,
                request_timeout_ms: 0,
            },
            PolicyTier::ScopedScratchpad => Self {
                tier,
                max_memory_bytes: (cfg.tiers.scoped_scratchpad.max_memory_mb as usize)
                    * 1024
                    * 1024,
                max_table_elements: cfg.tiers.scoped_scratchpad.max_table_elements,
                max_fuel: cfg.tiers.scoped_scratchpad.max_fuel,
                max_epoch_ticks: cfg.tiers.scoped_scratchpad.max_epoch_ticks,
                max_output_bytes: cfg.server.max_output_bytes,
                max_scratch_bytes: cfg.tiers.scoped_scratchpad.max_scratch_bytes,
                readonly_roots: Vec::new(),
                allowed_domains: Vec::new(),
                allow_http_plaintext: false,
                max_response_bytes: 0,
                request_timeout_ms: 0,
            },
            PolicyTier::ReadonlyData => Self {
                tier,
                max_memory_bytes: (cfg.tiers.readonly_data.max_memory_mb as usize) * 1024 * 1024,
                max_table_elements: cfg.tiers.readonly_data.max_table_elements,
                max_fuel: cfg.tiers.readonly_data.max_fuel,
                max_epoch_ticks: cfg.tiers.readonly_data.max_epoch_ticks,
                max_output_bytes: cfg.server.max_output_bytes,
                max_scratch_bytes: 0,
                readonly_roots: cfg.tiers.readonly_data.readonly_roots.clone(),
                allowed_domains: Vec::new(),
                allow_http_plaintext: false,
                max_response_bytes: 0,
                request_timeout_ms: 0,
            },
            PolicyTier::AllowlistedNet => Self {
                tier,
                max_memory_bytes: (cfg.tiers.allowlisted_net.max_memory_mb as usize) * 1024 * 1024,
                max_table_elements: cfg.tiers.allowlisted_net.max_table_elements,
                max_fuel: cfg.tiers.allowlisted_net.max_fuel,
                max_epoch_ticks: cfg.tiers.allowlisted_net.max_epoch_ticks,
                max_output_bytes: cfg.server.max_output_bytes,
                max_scratch_bytes: 0,
                readonly_roots: Vec::new(),
                allowed_domains: cfg.tiers.allowlisted_net.allowed_domains.clone(),
                allow_http_plaintext: cfg.tiers.allowlisted_net.allow_http_plaintext,
                max_response_bytes: cfg.tiers.allowlisted_net.max_response_bytes,
                request_timeout_ms: cfg.tiers.allowlisted_net.request_timeout_ms,
            },
        }
    }

    /// Callers may tighten limits strictly below the configured tier ceiling, never raise them.
    pub fn with_overrides(
        mut self,
        memory_mb: Option<u64>,
        fuel_budget: Option<u64>,
    ) -> Result<Self, AegisError> {
        if let Some(mb) = memory_mb {
            let requested_bytes = (mb as usize).saturating_mul(1024 * 1024);
            if requested_bytes < 65_536 || requested_bytes > self.max_memory_bytes {
                return Err(AegisError::PolicyViolation(format!(
                    "Requested memory_mb ({mb} MiB) exceeds tier '{}' ceiling ({} MiB) or is < 1 MiB",
                    self.tier.as_str(),
                    self.max_memory_bytes / (1024 * 1024)
                )));
            }
            self.max_memory_bytes = requested_bytes;
        }

        if let Some(fuel) = fuel_budget {
            if fuel == 0 || fuel > self.max_fuel {
                return Err(AegisError::PolicyViolation(format!(
                    "Requested fuel_budget ({fuel}) exceeds tier '{}' ceiling ({}) or is 0",
                    self.tier.as_str(),
                    self.max_fuel
                )));
            }
            self.max_fuel = fuel;
        }

        Ok(self)
    }

    pub fn validate_readonly_mount(&self, requested: &Path) -> Result<PathBuf, AegisError> {
        if self.tier != PolicyTier::ReadonlyData {
            return Err(AegisError::PolicyViolation(
                "readonly_dir mount requires readonly_data policy tier".into(),
            ));
        }
        let canon = requested
            .canonicalize()
            .map_err(|e| AegisError::CapabilityDenied(format!("Invalid mount path: {e}")))?;
        for root in &self.readonly_roots {
            if let Ok(canon_root) = root.canonicalize()
                && canon.starts_with(&canon_root)
            {
                return Ok(canon);
            }
        }
        Err(AegisError::CapabilityDenied(format!(
            "Path {} is outside allowlisted readonly_roots",
            requested.display()
        )))
    }

    pub fn validate_scratchpad_relative_path(rel: &str) -> Result<PathBuf, AegisError> {
        if rel.contains('\\') {
            return Err(AegisError::CapabilityDenied(format!(
                "Backslash path '{rel}' rejected by scratchpad policy"
            )));
        }
        let candidate = Path::new(rel);
        let mut clean = PathBuf::new();
        for comp in candidate.components() {
            match comp {
                Component::Normal(part) => clean.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(AegisError::CapabilityDenied(format!(
                        "Path traversal or absolute path '{rel}' rejected by policy"
                    )));
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(AegisError::CapabilityDenied(
                "Empty scratchpad filename rejected".into(),
            ));
        }
        Ok(clean)
    }

    /// Zero ambient authority: NEVER calls inherit_env, inherit_network, or inherit_stdio.
    pub fn build_wasi_p1(
        &self,
        stdin: MemoryInputPipe,
        stdout: MemoryOutputPipe,
        stderr: MemoryOutputPipe,
        scratch_dir: Option<&Path>,
        readonly_dir: Option<&Path>,
    ) -> anyhow::Result<WasiP1Ctx> {
        let mut builder = WasiCtxBuilder::new();
        builder.stdin(stdin).stdout(stdout).stderr(stderr);

        match self.tier {
            PolicyTier::ScopedScratchpad => {
                if let Some(dir) = scratch_dir {
                    builder
                        .preopened_dir(dir, "/workspace", FsPerms::ReadWrite)
                        .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                }
            }
            PolicyTier::ReadonlyData => {
                if let Some(dir) = readonly_dir {
                    builder
                        .preopened_dir(dir, "/data", FsPerms::ReadOnly)
                        .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                }
            }
            PolicyTier::PureCompute | PolicyTier::AllowlistedNet => {}
        }

        Ok(builder.build_p1())
    }
}
