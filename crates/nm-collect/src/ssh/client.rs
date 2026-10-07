use super::{
    hostkeys::{HostKeyCheck, HostKeyStore},
    preferred, SshError,
};
use crate::CollectCtx;
use nm_core::{
    Actor, AuditAction, AuditEvent, CredentialKind, CredentialProfile, Device, DeviceId, Timestamp,
};
use nm_creds::SecretMaterial;
use nm_store::AuditSink;
use russh::{
    client,
    keys::{ssh_key::HashAlg, PrivateKeyWithHashAlg},
};
use secrecy::ExposeSecret;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(super) struct Handler {
    pub store: Arc<HostKeyStore>,
    pub device: DeviceId,
    pub audit: AuditSink,
    pub legacy: Arc<AtomicBool>,
}
impl client::Handler for Handler {
    type Error = SshError;
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.legacy.store(
            names.kex == russh::kex::DH_G1_SHA1
                || names.kex == russh::kex::DH_G14_SHA1
                || names.key == russh::keys::ssh_key::Algorithm::Rsa { hash: None }
                || names.cipher == russh::cipher::AES_128_CBC
                || names.cipher == russh::cipher::TRIPLE_DES_CBC
                || names.client_mac == russh::mac::HMAC_SHA1
                || names.server_mac == russh::mac::HMAC_SHA1,
            Ordering::SeqCst,
        );
        Ok(())
    }
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = key.public_key();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let first_seen =
            match self
                .store
                .check(self.device, key.algorithm().as_ref(), &fingerprint)?
            {
                HostKeyCheck::FirstSeen => true,
                HostKeyCheck::Matching => false,
                HostKeyCheck::Changed { expected } => {
                    return Err(SshError::HostKeyChanged {
                        expected,
                        got: fingerprint,
                    })
                }
            };
        self.audit.append(AuditEvent { ts:Timestamp::now(), actor:Actor::Collector, action:AuditAction::SshConnect,target:self.device.to_string(),detail:serde_json::json!({"first_seen":first_seen,"fingerprint":fingerprint,"algorithm":key.algorithm().to_string()}),bytes_out:0,bytes_in:0 }).await?;
        Ok(true)
    }
}
pub struct SshTransport {
    store: Arc<HostKeyStore>,
}
impl SshTransport {
    pub fn new(store: Arc<HostKeyStore>) -> Self {
        Self { store }
    }
    pub async fn connect(
        &self,
        ctx: &CollectCtx,
        device: &Device,
        profile: &CredentialProfile,
    ) -> Result<SshSession, SshError> {
        let ip = ctx
            .gate
            .addresses()
            .iter()
            .filter(|ip| {
                ctx.gate
                    .check_address(SocketAddr::new(**ip, device.management.port.unwrap_or(22)))
                    .is_ok_and(|id| id == device.id)
            })
            .min()
            .copied()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "device is not uniquely enrolled",
                )
            })?;
        let address = SocketAddr::new(ip, device.management.port.unwrap_or(22));
        let future = async {
            let legacy_used = Arc::new(AtomicBool::new(false));
            let stream = ctx.net.tcp_connect(address).await?;
            let config = Arc::new(client::Config {
                preferred: preferred(device.ssh_legacy_ok),
                inactivity_timeout: Some(ctx.limits.per_device_budget),
                ..client::Config::default()
            });
            let handler = Handler {
                store: self.store.clone(),
                device: device.id,
                audit: ctx.audit.clone(),
                legacy: legacy_used.clone(),
            };
            let session = client::connect_stream(config, stream, handler)
                .await
                .map_err(|e| match e {
                    SshError::Russh(russh::Error::NoCommonAlgo { theirs, .. })
                        if !device.ssh_legacy_ok
                            && theirs.iter().any(|a| {
                                [
                                    "ssh-rsa",
                                    "diffie-hellman-group1-sha1",
                                    "diffie-hellman-group14-sha1",
                                    "aes128-cbc",
                                    "3des-cbc",
                                    "hmac-sha1",
                                ]
                                .contains(&a.as_str())
                            }) =>
                    {
                        SshError::LegacyAlgorithmsRequired(theirs)
                    }
                    other => other,
                })?;
            let kind = profile.kind.clone();
            let legacy = device.ssh_legacy_ok;
            let (session, authenticated) = ctx
                .creds
                .with_secret_async(profile.id, move |secret| {
                    Box::pin(async move {
                        let mut session = session;
                        let authenticated = match (&kind, secret) {
                            (
                                CredentialKind::SshPassword { username },
                                SecretMaterial::SshPassword(password),
                            ) => session
                                .authenticate_password(username.clone(), password.expose_secret())
                                .await
                                .map(|r| r.success())
                                .map_err(SshError::from),
                            (
                                CredentialKind::SshKey { username, .. },
                                SecretMaterial::SshKey { key, passphrase },
                            ) => {
                                match std::str::from_utf8(key.expose_secret()).ok().and_then(|s| {
                                    russh::keys::decode_secret_key(
                                        s,
                                        passphrase
                                            .as_ref()
                                            .map(ExposeSecret::expose_secret)
                                            .map(String::as_str),
                                    )
                                    .ok()
                                }) {
                                    Some(key) => {
                                        let hash = if matches!(
                                            key.algorithm(),
                                            russh::keys::Algorithm::Rsa { .. }
                                        ) {
                                            session.best_supported_rsa_hash().await
                                        } else {
                                            Ok(Some(Some(HashAlg::Sha256)))
                                        };
                                        match hash {
                                            Ok(hash) => {
                                                let hash = hash.unwrap_or(Some(HashAlg::Sha256));
                                                if hash.is_none() && !legacy {
                                                    Err(SshError::AuthFailed)
                                                } else {
                                                    session
                                                        .authenticate_publickey(
                                                            username.clone(),
                                                            PrivateKeyWithHashAlg::new(
                                                                Arc::new(key),
                                                                hash,
                                                            ),
                                                        )
                                                        .await
                                                        .map(|r| r.success())
                                                        .map_err(SshError::from)
                                                }
                                            }
                                            Err(error) => Err(SshError::from(error)),
                                        }
                                    }
                                    None => Err(SshError::AuthFailed),
                                }
                            }
                            _ => Err(SshError::AuthFailed),
                        };
                        (session, authenticated)
                    })
                })
                .await
                .map_err(|_| SshError::AuthFailed)?;
            if !authenticated? {
                return Err(SshError::AuthFailed);
            }
            Ok(SshSession {
                session,
                device: device.id,
                audit: ctx.audit.clone(),
                timeout: ctx.limits.per_command_timeout,
                cancel: ctx.cancel.clone(),
                legacy: legacy_used.load(Ordering::SeqCst),
            })
        };
        tokio::select! { ()=ctx.cancel.cancelled()=>Err(SshError::Cancelled), result=tokio::time::timeout(ctx.limits.connect_timeout,future)=>result.map_err(|_|SshError::Timeout)? }
    }
}
pub struct SshSession {
    pub(super) session: client::Handle<Handler>,
    pub(super) device: DeviceId,
    pub(super) audit: AuditSink,
    pub(super) timeout: Duration,
    pub(super) cancel: CancellationToken,
    pub legacy: bool,
}
