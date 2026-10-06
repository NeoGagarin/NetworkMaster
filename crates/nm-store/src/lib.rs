#![doc = include_str!("../README.md")]
pub mod audit;
pub mod db;
pub mod migrations;
pub mod paths;
pub mod repo;
pub use audit::AuditSink;
pub use db::Db;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Migration(#[from] rusqlite_migration::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("database lock poisoned")]
    Poisoned,
    #[error("record not found")]
    NotFound,
    #[error("invalid persisted value: {0}")]
    Invalid(String),
    #[error("unredacted artifact rejected")]
    UnredactedArtifact,
    #[error("artifact hash does not match its bytes")]
    ArtifactHash,
    #[error("audit writer stopped")]
    AuditClosed,
    #[error("audit writer: {0}")]
    AuditWriter(String),
}
pub type Result<T> = std::result::Result<T, StoreError>;
