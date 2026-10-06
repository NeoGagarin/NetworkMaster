#[derive(Debug, thiserror::Error)]
pub enum NmError {
    #[error("store: {0}")]
    Store(String),
    #[error("credentials: {0}")]
    Creds(String),
    #[error("collection: {0}")]
    Collect(String),
    #[error("analysis: {0}")]
    Analyze(String),
    #[error("AI: {0}")]
    Ai(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, NmError>;
