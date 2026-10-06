#![doc = include_str!("../README.md")]
pub mod arena;
pub mod profile;
pub mod secret;
pub use arena::CredArena;
pub use profile::*;
pub use secrecy::{ExposeSecret, SecretString, SecretVec};
pub use secret::{SecretFingerprint, SecretMaterial};

#[derive(Debug, thiserror::Error)]
pub enum CredsError {
    #[error("credential not present in this session")]
    Missing,
    #[error("credential arena lock poisoned")]
    Poisoned,
    #[error("persistent credential storage is not implemented yet (planned for M5)")]
    NotImplemented,
    #[error("secret material does not match profile kind")]
    KindMismatch,
}
