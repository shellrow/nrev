use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NrevError {
    #[error("invalid target expression: {0}")]
    InvalidTarget(String),
    #[error("invalid port expression: {0}")]
    InvalidPortSpec(String),
    #[error("unknown recipe: {0}")]
    InvalidRecipe(String),
    #[error("invalid task: {0}")]
    InvalidTask(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("unsupported file extension for {0}")]
    UnsupportedFileExtension(PathBuf),
    #[error("failed to resolve {0}")]
    ResolutionFailed(String),
    #[error(
        "target expansion exceeds the safety limit of {limit} addresses (while processing {input})"
    )]
    TargetLimitExceeded { input: String, limit: usize },
    #[error(
        "scan expansion exceeds the safety limit of {limit} endpoint assignments (while processing {input})"
    )]
    EndpointLimitExceeded { input: String, limit: usize },
    #[error("external data file exceeds the {limit_bytes}-byte safety limit: {path}")]
    DataFileTooLarge { path: PathBuf, limit_bytes: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TLS error: {0}")]
    Tls(String),
}

pub type Result<T> = std::result::Result<T, NrevError>;
