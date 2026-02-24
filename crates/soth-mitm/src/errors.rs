use thiserror::Error;

#[derive(Debug, Error)]
pub enum MitmError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("certificate authority load failed: {0}")]
    CaLoadFailed(String),
    #[error("certificate authority operation failed: {0}")]
    CaOperationFailed(String),
    #[error("runtime I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, Error)]
pub enum CaError {
    #[error("permission denied while performing {operation}: {detail}")]
    PermissionDenied { operation: String, detail: String },
    #[error("certificate authority operation failed: {0}")]
    OperationFailed(String),
    #[error("invalid certificate authority material: {0}")]
    InvalidMaterial(String),
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
