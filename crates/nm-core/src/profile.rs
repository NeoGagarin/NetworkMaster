use crate::CredentialProfileId;
use serde::{Deserialize, Serialize};

/// Credential metadata only. Secret material lives exclusively in nm-creds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProfile {
    pub id: CredentialProfileId,
    pub name: String,
    pub kind: CredentialKind,
    pub storage: StorageMode,
    pub scope_hint: String,
    /// Derived when a credential is entered; contains no secret.
    #[serde(default)]
    pub is_vendor_default: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    SshPassword {
        username: String,
    },
    SshKey {
        username: String,
        has_passphrase: bool,
    },
    ApiToken,
    HttpBasic {
        username: String,
    },
    SnmpV2c,
    SnmpV3 {
        username: String,
        auth_proto: String,
        priv_proto: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMode {
    SessionOnly,
    WindowsCredentialManager,
}
