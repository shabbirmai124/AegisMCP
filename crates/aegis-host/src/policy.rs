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

#[derive(Debug, Clone, Serialize)]
pub struct SandboxPolicy {
    pub tier: PolicyTier,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub max_fuel: u64,
    pub max_epoch_ticks: u64,
    pub max_output_bytes: usize,
    pub scratchpad_quota_bytes: usize,
    pub readonly_roots: Vec<PathBuf>,
    pub allowed_domains: Vec<String>,
    pub https_only: bool,
    pub max_response_bytes: usize,
}

impl SandboxPolicy {
    pub fn from_config(cfg: &AegisConfig, tier: PolicyTier) -> Self {
        match tier {
            PolicyTier::PureCompute => Self {
                tier,
                max_memory_bytes: cfg.tiers.pure_compute.max_memory_bytes,
                max_table_elements: cfg.tiers.pure_compute.max_table_elements,
                max_fuel: cfg.tiers.pure_compute.max_fuel,
                max_epoch_ticks: cfg.tiers.pure_compute.max_epoch_ticks,
                max_output_bytes: cfg.engine.max_output_bytes,
                scratchpad_quota_bytes: 0,
                readonly_roots: Vec::new(),
                allowed_domains: Vec::new(),
                https_only: true,
                max_response_bytes: 0,
            },
            PolicyTier::ScopedScratchpad => Self {
                tier,
                max_memory_bytes: cfg.tiers.scoped_scratchpad.max_memory_bytes,
                max_table_elements: cfg.tiers.scoped_scratchpad.max_table_elements,
                max_fuel: cfg.tiers.scoped_scratchpad.max_fuel,
                max_epoch_ticks: cfg.tiers.scoped_scratchpad.max_epoch_ticks,
                max_output_bytes: cfg.engine.max_output_bytes,
                scratchpad_quota_bytes: cfg.tiers.scoped_scratchpad.scratchpad_quota_bytes,
                readonly_roots: Vec::new(),
                allowed_domains: Vec::new(),
                https_only: true,
                max_response_bytes: 0,
            },
            PolicyTier::ReadonlyData => Self {
                tier,
                max_memory_bytes: cfg.tiers.readonly_data.max_memory_bytes,
                max_table_elements: cfg.tiers.readonly_data.max_table_elements,
                max_fuel: cfg.tiers.readonly_data.max_fuel,
                max_epoch_ticks: cfg.tiers.readonly_data.max_epoch_ticks,
                max_output_bytes: cfg.engine.max_output_bytes,
                scratchpad_quota_bytes: 0,
                readonly_roots: cfg.tiers.readonly_data.readonly_roots.clone(),
                allowed_domains: Vec::new(),
                https_only: true,
                max_response_bytes: 0,
            },
            PolicyTier::AllowlistedNet => Self {
                tier,
                max_memory_bytes: cfg.tiers.allowlisted_net.max_memory_bytes,
                max_table_elements: cfg.tiers.allowlisted_net.max_table_elements,
                max_fuel: cfg.tiers.allowlisted_net.max_fuel,
                max_epoch_ticks: cfg.tiers.allowlisted_net.max_epoch_ticks,
                max_output_bytes: cfg.engine.max_output_bytes,
                scratchpad_quota_bytes: 0,
                readonly_roots: Vec::new(),
                allowed_domains: cfg.tiers.allowlisted_net.allowed_domains.clone(),
                https_only: cfg.tiers.allowlisted_net.https_only,
                max_response_bytes: cfg.tiers.allowlisted_net.max_response_bytes,
            },
        }
    }

    pub fn validate_readonly_mount(&self, requested: &Path) -> Result<PathBuf, AegisError> {
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

    /// Zero ambient authority: never calls inherit_env, inherit_network, or inherit_stdio.
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
