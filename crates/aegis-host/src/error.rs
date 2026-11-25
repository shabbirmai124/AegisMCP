use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionClassification {
    Success,
    OutOfFuel,
    EpochTimeout,
    MemoryLimitExceeded,
    CapabilityDenied,
    GuestRuntimeError,
}

impl ExecutionClassification {
    pub fn status_label(self) -> &'static str {
        match self {
            Self::Success => "Pass",
            Self::OutOfFuel | Self::EpochTimeout | Self::MemoryLimitExceeded => "Trapped",
            Self::CapabilityDenied => "Blocked",
            Self::GuestRuntimeError => "Trapped",
        }
    }
}

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("ConfigError: {0}")]
    ConfigError(String),
    #[error("EngineError: {0}")]
    EngineError(String),
    #[error("ModuleNotFound: {0}")]
    ModuleNotFound(String),
    #[error("CacheIntegrityError: {0}")]
    CacheIntegrityError(String),
    #[error("PolicyViolation: {0}")]
    PolicyViolation(String),
    #[error("SsrfBlocked: {0}")]
    SsrfBlocked(String),
    #[error("OutOfFuel: guest exhausted {budget} instruction fuel units")]
    OutOfFuel { budget: u64 },
    #[error("EpochTimeout: guest exceeded wall-clock deadline ({ticks} ticks)")]
    EpochTimeout { ticks: u64 },
    #[error("MemoryLimitExceeded: guest attempted allocation above {limit_bytes} bytes")]
    MemoryLimitExceeded { limit_bytes: usize },
    #[error("CapabilityDenied: {0}")]
    CapabilityDenied(String),
    #[error("GuestRuntimeError: {0}")]
    GuestRuntimeError(String),
    #[error("AuditError: {0}")]
    AuditError(String),
}

impl AegisError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigError(_) => "CONFIG_ERROR",
            Self::EngineError(_) => "ENGINE_ERROR",
            Self::ModuleNotFound(_) => "MODULE_NOT_FOUND",
            Self::CacheIntegrityError(_) => "CACHE_INTEGRITY_ERROR",
            Self::PolicyViolation(_) => "POLICY_VIOLATION",
            Self::SsrfBlocked(_) => "SSRF_BLOCKED",
            Self::OutOfFuel { .. } => "OUT_OF_FUEL",
            Self::EpochTimeout { .. } => "EPOCH_TIMEOUT",
            Self::MemoryLimitExceeded { .. } => "MEMORY_LIMIT_EXCEEDED",
            Self::CapabilityDenied(_) => "CAPABILITY_DENIED",
            Self::GuestRuntimeError(_) => "GUEST_RUNTIME_ERROR",
            Self::AuditError(_) => "AUDIT_ERROR",
        }
    }

    pub fn to_llm_diagnostic(&self) -> serde_json::Value {
        let (category, remediation) = match self {
            Self::OutOfFuel { .. } => (
                "resource_trap",
                "Eliminate infinite loops or reduce algorithmic complexity to stay within the tier fuel budget.",
            ),
            Self::EpochTimeout { .. } => (
                "resource_trap",
                "Reduce execution time so the script completes within the tier wall-clock deadline.",
            ),
            Self::MemoryLimitExceeded { .. } => (
                "resource_trap",
                "Stream or chunk large buffers so total Wasm linear memory stays below the tier ceiling.",
            ),
            Self::SsrfBlocked(_) => (
                "security_block",
                "Only public HTTPS endpoints on configured allowlisted domains are permitted in allowlisted_net tier.",
            ),
            Self::PolicyViolation(_) | Self::CapabilityDenied(_) => (
                "security_block",
                "Inspect active capabilities via inspect_sandbox_policy and request only permitted paths, tiers, or limits.",
            ),
            Self::ModuleNotFound(_) => (
                "configuration",
                "Build the WASI guest binary or verify the plugin path in aegis.toml.",
            ),
            Self::CacheIntegrityError(_) => (
                "integrity",
                "Run `aegis-mcp precompile --force` to rebuild verified .cwasm artifacts.",
            ),
            Self::ConfigError(_) | Self::EngineError(_) | Self::AuditError(_) => (
                "host_error",
                "Run `aegis-mcp doctor` to inspect configuration, cache, and SQLite ledger health.",
            ),
            Self::GuestRuntimeError(_) => (
                "guest_error",
                "Fix the syntax or runtime exception inside the submitted JavaScript or Wasm payload.",
            ),
        };

        serde_json::json!({
            "code": self.code(),
            "category": category,
            "message": self.to_string(),
            "remediation": remediation,
        })
    }
}
