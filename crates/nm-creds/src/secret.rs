use crate::CredentialKind;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use zeroize::{Zeroize, ZeroizeOnDrop};

// secrecy containers zeroize their allocations on drop; they are deliberately
// neither Serialize nor Clone here. No unsafe memory access is necessary.
pub enum SecretMaterial {
    SshPassword(SecretString),
    SshKey {
        key: SecretVec<u8>,
        passphrase: Option<SecretString>,
    },
    ApiToken(SecretString),
    HttpBasic(SecretString),
    SnmpV2c(SecretString),
    SnmpV3 {
        auth: SecretString,
        privacy: Option<SecretString>,
    },
}
impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl SecretMaterial {
    pub fn matches(&self, kind: &CredentialKind) -> bool {
        match (self, kind) {
            (Self::SshPassword(_), CredentialKind::SshPassword { .. })
            | (Self::ApiToken(_), CredentialKind::ApiToken)
            | (Self::HttpBasic(_), CredentialKind::HttpBasic { .. })
            | (Self::SnmpV2c(_), CredentialKind::SnmpV2c)
            | (Self::SnmpV3 { .. }, CredentialKind::SnmpV3 { .. }) => true,
            (Self::SshKey { passphrase, .. }, CredentialKind::SshKey { has_passphrase, .. }) => {
                passphrase.is_some() == *has_passphrase
            }
            _ => false,
        }
    }
    pub(crate) fn visit(&self, mut f: impl FnMut(&[u8])) {
        match self {
            Self::SshPassword(s) | Self::ApiToken(s) | Self::HttpBasic(s) | Self::SnmpV2c(s) => {
                f(s.expose_secret().as_bytes());
            }
            Self::SshKey { key, passphrase } => {
                f(key.expose_secret());
                if let Some(s) = passphrase {
                    f(s.expose_secret().as_bytes());
                }
            }
            Self::SnmpV3 { auth, privacy } => {
                f(auth.expose_secret().as_bytes());
                if let Some(s) = privacy {
                    f(s.expose_secret().as_bytes());
                }
            }
        }
    }
}
/// These are secret-derived scrub patterns, not safe-to-log identifiers.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretFingerprint {
    pub raw: Vec<u8>,
    pub sha256: [u8; 32],
    pub hashed: String,
    pub base64: String,
    pub url_encoded: String,
    pub hex: String,
}
impl std::fmt::Debug for SecretFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
