use crate::{CredsError, SecretFingerprint, SecretMaterial};
use base64::{engine::general_purpose::STANDARD, Engine};
use nm_core::CredentialProfileId;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Inner {
    secrets: Mutex<HashMap<CredentialProfileId, SecretMaterial>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        // Even poisoned locks must drop (and thus zeroize) every secrecy value.
        match self.secrets.get_mut() {
            Ok(secrets) => secrets.clear(),
            Err(e) => e.into_inner().clear(),
        }
    }
}
#[derive(Clone, Default)]
pub struct CredArena {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for CredArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredArena([REDACTED])")
    }
}
impl CredArena {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(
        &self,
        id: CredentialProfileId,
        secret: SecretMaterial,
    ) -> Result<(), CredsError> {
        self.inner
            .secrets
            .lock()
            .map_err(|_| CredsError::Poisoned)?
            .insert(id, secret);
        Ok(())
    }
    pub fn forget(&self, id: CredentialProfileId) -> Result<(), CredsError> {
        self.inner
            .secrets
            .lock()
            .map_err(|_| CredsError::Poisoned)?
            .remove(&id);
        Ok(())
    }
    pub fn forget_all(&self) -> Result<(), CredsError> {
        self.inner
            .secrets
            .lock()
            .map_err(|_| CredsError::Poisoned)?
            .clear();
        Ok(())
    }
    pub fn contains(&self, id: CredentialProfileId) -> bool {
        self.inner
            .secrets
            .lock()
            .is_ok_and(|secrets| secrets.contains_key(&id))
    }
    pub fn with_secret<R>(
        &self,
        id: CredentialProfileId,
        f: impl FnOnce(&SecretMaterial) -> R,
    ) -> Result<R, CredsError> {
        let secrets = self
            .inner
            .secrets
            .lock()
            .map_err(|_| CredsError::Poisoned)?;
        let secret = secrets.get(&id).ok_or(CredsError::Missing)?;
        Ok(f(secret))
    }
    pub fn fingerprints(&self) -> Result<Vec<SecretFingerprint>, CredsError> {
        let secrets = self
            .inner
            .secrets
            .lock()
            .map_err(|_| CredsError::Poisoned)?;
        let mut result = Vec::new();
        for secret in secrets.values() {
            secret.visit(|bytes| {
                if bytes.is_empty() {
                    return;
                }
                let sha256: [u8; 32] = Sha256::digest(bytes).into();
                result.push(SecretFingerprint {
                    raw: bytes.to_vec(),
                    sha256,
                    hashed: hex::encode(sha256),
                    base64: STANDARD.encode(bytes),
                    url_encoded: percent_encoding::percent_encode(
                        bytes,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string(),
                    hex: hex::encode(bytes),
                });
            });
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretString};
    #[test]
    fn access_forget_and_redaction() {
        let arena = CredArena::new();
        let id = CredentialProfileId::new();
        arena
            .insert(
                id,
                SecretMaterial::SshPassword(SecretString::new("p@ss word".into())),
            )
            .unwrap();
        let clone = arena.clone();
        drop(clone);
        assert!(arena.contains(id));
        arena
            .with_secret(id, |s| {
                assert_eq!(format!("{s:?}"), "[REDACTED]");
                if let SecretMaterial::SshPassword(s) = s {
                    assert_eq!(s.expose_secret(), "p@ss word");
                } else {
                    panic!("wrong kind");
                }
            })
            .unwrap();
        let fingerprints = arena.fingerprints().unwrap();
        assert_eq!(fingerprints[0].base64, "cEBzcyB3b3Jk");
        assert_eq!(fingerprints[0].url_encoded, "p%40ss%20word");
        arena.forget(id).unwrap();
        assert!(matches!(
            arena.with_secret(id, |_| ()),
            Err(CredsError::Missing)
        ));
    }
    #[test]
    fn forget_all() {
        let arena = CredArena::new();
        let id = CredentialProfileId::new();
        arena
            .insert(
                id,
                SecretMaterial::ApiToken(SecretString::new("token".into())),
            )
            .unwrap();
        arena.forget_all().unwrap();
        assert!(!arena.contains(id));
    }
}
