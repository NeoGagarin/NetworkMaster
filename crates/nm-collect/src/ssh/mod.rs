mod algos;
mod client;
pub mod hostkeys {
    pub use nm_store::repo::hostkeys::{HostKeyCheck, HostKeyStore};
}
mod runner;
pub use algos::preferred;
pub use client::{SshSession, SshTransport};
pub use runner::CommandOutput;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH host key changed: expected {expected}, got {got}")]
    HostKeyChanged { expected: String, got: String },
    #[error("deprecated SSH algorithms require per-device opt-in: {0:?}")]
    LegacyAlgorithmsRequired(Vec<String>),
    #[error("SSH authentication failed or session credential is unavailable")]
    AuthFailed,
    #[error("SSH command timed out")]
    Timeout,
    #[error("collection cancelled")]
    Cancelled,
    #[error(transparent)]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] nm_store::StoreError),
}
