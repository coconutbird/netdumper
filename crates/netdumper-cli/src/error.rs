//! Error types for netdumper.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Runtime not found")]
    RuntimeNotFound,

    #[error("Failed to attach to runtime: {0}")]
    AttachFailed(String),

    #[error("Failed to enumerate assemblies: {0}")]
    EnumerationFailed(String),

    #[error("Windows API error: {0}")]
    WindowsError(#[from] windows::core::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
