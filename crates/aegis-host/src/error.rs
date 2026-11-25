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

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("OutOfFuel: guest exhausted {budget} instruction fuel units")]
    OutOfFuel { budget: u64 },
    #[error("EpochTimeout: guest exceeded wall-clock deadline ({ticks} ticks)")]
    EpochTimeout { ticks: u64 },
    #[error("MemoryLimitExceeded: guest attempted allocation above {limit_bytes} bytes")]
    MemoryLimitExceeded { limit_bytes: usize },
    #[error("CapabilityDenied: {0}")]
    CapabilityDenied(String),
    #[error("GuestRuntimeError: {0}")]
    GuestRuntime(String),
}
