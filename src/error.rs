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
    #[error("unsupported file extension for {0}")]
    UnsupportedFileExtension(PathBuf),
    #[error("failed to resolve {0}")]
    ResolutionFailed(String),
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
