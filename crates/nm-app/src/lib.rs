#![doc = include_str!("../README.md")]
pub mod events;
pub mod inventory;
pub mod jobs;
pub mod scan;
pub mod service;
pub use events::*;
pub use jobs::*;
pub use nm_creds::{CredArena, CredsError, SecretMaterial, SecretString, SecretVec};
pub use nm_store::AuditSink;
pub use service::*;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Invalid(String),
    #[error("duplicate address and port")]
    Duplicate,
    #[error(transparent)]
    Store(#[from] nm_store::StoreError),
    #[error(transparent)]
    Creds(#[from] CredsError),
    #[error(transparent)]
    Job(#[from] JobError),
}
pub type Result<T> = std::result::Result<T, AppError>;

pub mod analyze;
pub mod report;
