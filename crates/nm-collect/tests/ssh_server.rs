mod support;
use nm_collect::{
    ssh::{hostkeys::HostKeyStore, SshError, SshTransport},
    *,
};
use nm_core::*;
use nm_creds::{CredArena, SecretMaterial};
use nm_store::{
    repo::{AuditRepo, DeviceRepo, ProfileRepo},
    AuditSink, Db,
};
use secrecy::SecretString;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

async fn context(
    address: std::net::SocketAddr,
) -> (Db, Device, CredentialProfile, CollectCtx, SshTransport) {
    let db = Db::open_in_memory().unwrap();
    let profile = CredentialProfile {
        id: CredentialProfileId::new(),
        name: "test".into(),
        kind: CredentialKind::SshPassword {
            username: "operator".into(),
        },
        storage: StorageMode::SessionOnly,
        scope_hint: String::new(),
        is_vendor_default: false,
    };
    ProfileRepo::new(&db).insert(&profile).unwrap();
    let device = Device {
        id: DeviceId::new(),
        display_name: "test".into(),
        management: address.to_string().parse().unwrap(),
        vendor: Vendor::Ubiquiti,
        family: DeviceFamily::AirOs,
        role: None,
        site: None,
        credential_profile: Some(profile.id),
        source: EnrollmentSource::Manual,
        enrolled: true,
        ssh_legacy_ok: false,
        interface_roles: std::collections::BTreeMap::default(),
        tags: vec![],
    };
    DeviceRepo::new(&db).insert(&device).unwrap();
    let gate = Arc::new(TargetGate::new(std::slice::from_ref(&device)).await);
    let creds = Arc::new(CredArena::new());
    creds
        .insert(
            profile.id,
            SecretMaterial::SshPassword(SecretString::new("test-password".into())),
        )
        .unwrap();
    let ctx = CollectCtx {
        gate: gate.clone(),
        net: Arc::new(RealNet::new(gate)),
        creds,
        audit: AuditSink::new(db.clone(), 128),
        limits: Limits::default(),
        cancel: CancellationToken::new(),
        events: None,
        partial: Arc::default(),
    };
    let transport = SshTransport::new(Arc::new(HostKeyStore::new(db.clone())));
    (db, device, profile, ctx, transport)
}
#[tokio::test]
async fn auth_commands_audit_and_pin_mismatch() {
    let server = support::ReplayServer::start(
        support::key(),
        false,
        Duration::ZERO,
        support::fixture_outputs(),
    )
    .await;
    let (db, mut device, profile, mut ctx, transport) = context(server.address).await;
    let mut session = transport.connect(&ctx, &device, &profile).await.unwrap();
    for command in [
        allowlist::airos::VERSION,
        allowlist::airos::MCA_STATUS,
        allowlist::airos::ARP,
    ] {
        assert_eq!(session.run(command).await.unwrap().exit, Some(0));
    }
    session.close().await.unwrap();
    ctx.audit.flush().await.unwrap();
    let audit = AuditRepo::new(&db).tail(10).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|a| a.action == AuditAction::SshCommand)
            .count(),
        3
    );
    assert_eq!(audit.last().unwrap().detail["first_seen"], true);
    let session = transport.connect(&ctx, &device, &profile).await.unwrap();
    session.close().await.unwrap();
    ctx.audit.flush().await.unwrap();
    assert_eq!(
        AuditRepo::new(&db).tail(1).unwrap()[0].detail["first_seen"],
        false
    );
    let changed = support::ReplayServer::start(
        support::key(),
        false,
        Duration::ZERO,
        support::fixture_outputs(),
    )
    .await;
    device.management = changed.address.to_string().parse().unwrap();
    let gate = Arc::new(TargetGate::new(std::slice::from_ref(&device)).await);
    ctx.gate = gate.clone();
    ctx.net = Arc::new(RealNet::new(gate));
    assert!(matches!(
        transport.connect(&ctx, &device, &profile).await,
        Err(SshError::HostKeyChanged { .. })
    ));
    assert!(changed.commands.lock().unwrap().is_empty());
    ctx.creds
        .insert(
            profile.id,
            SecretMaterial::SshPassword(SecretString::new("wrong".into())),
        )
        .unwrap();
    device.management = server.address.to_string().parse().unwrap();
    let gate = Arc::new(TargetGate::new(std::slice::from_ref(&device)).await);
    ctx.gate = gate.clone();
    ctx.net = Arc::new(RealNet::new(gate));
    assert!(matches!(
        transport.connect(&ctx, &device, &profile).await,
        Err(SshError::AuthFailed)
    ));
}
#[tokio::test]
async fn command_timeout_and_output_limit() {
    let server = support::ReplayServer::start(
        support::key(),
        false,
        Duration::from_millis(150),
        support::fixture_outputs(),
    )
    .await;
    let (_db, device, profile, mut ctx, transport) = context(server.address).await;
    ctx.limits.per_command_timeout = Duration::from_secs(5);
    let session = transport.connect(&ctx, &device, &profile).await.unwrap();
    // Establish a fresh session with a short command timeout after handshake.
    ctx.limits.per_command_timeout = Duration::from_millis(100);
    session.close().await.unwrap();
    let mut session = transport.connect(&ctx, &device, &profile).await.unwrap();
    assert!(matches!(
        session.run(allowlist::airos::VERSION).await,
        Err(SshError::Timeout)
    ));
    session.close().await.unwrap();
    let mut outputs = support::fixture_outputs();
    outputs.insert("mca-status".into(), (vec![b'x'; 4 * 1024 * 1024 + 100], 0));
    let server = support::ReplayServer::start(support::key(), false, Duration::ZERO, outputs).await;
    let (_db, device, profile, ctx, transport) = context(server.address).await;
    let mut session = transport.connect(&ctx, &device, &profile).await.unwrap();
    let output = session.run(allowlist::airos::MCA_STATUS).await.unwrap();
    assert!(output.truncated);
    assert_eq!(output.stdout.len(), 4 * 1024 * 1024);
}
#[tokio::test]
async fn legacy_requires_opt_in_then_negotiates_group1_rsa_cbc_sha1() {
    let key = russh::keys::decode_secret_key(include_str!("../../../fixtures/test-keys/rsa"), None)
        .unwrap();
    let server =
        support::ReplayServer::start(key, true, Duration::ZERO, support::fixture_outputs()).await;
    let (_db, mut device, profile, ctx, transport) = context(server.address).await;
    assert!(matches!(
        transport.connect(&ctx, &device, &profile).await,
        Err(SshError::LegacyAlgorithmsRequired(_))
    ));
    device.ssh_legacy_ok = true;
    let mut session = transport.connect(&ctx, &device, &profile).await.unwrap();
    assert!(session.legacy);
    assert_eq!(
        session.run(allowlist::airos::VERSION).await.unwrap().exit,
        Some(0)
    );
}

#[tokio::test]
async fn key_auth_stays_modern_with_legacy_opt_in_and_dropped_commands_are_audited() {
    let server = support::ReplayServer::start(
        support::key(),
        false,
        Duration::from_millis(250),
        support::fixture_outputs(),
    )
    .await;
    let (db, mut device, mut profile, ctx, transport) = context(server.address).await;
    device.ssh_legacy_ok = true;
    profile.kind = CredentialKind::SshKey {
        username: "operator".into(),
        has_passphrase: false,
    };
    ctx.creds
        .insert(
            profile.id,
            SecretMaterial::SshKey {
                key: secrecy::SecretVec::new(
                    include_bytes!("../../../fixtures/test-keys/rsa").to_vec(),
                ),
                passphrase: None,
            },
        )
        .unwrap();
    let mut session = transport.connect(&ctx, &device, &profile).await.unwrap();
    assert!(!session.legacy);
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        session.run(allowlist::airos::VERSION)
    )
    .await
    .is_err());
    session.close().await.unwrap();
    ctx.audit.flush().await.unwrap();
    let events = AuditRepo::new(&db).tail(10).unwrap();
    let command = events
        .iter()
        .find(|e| e.action == AuditAction::SshCommand)
        .unwrap();
    assert_eq!(command.detail["command"], "cat /etc/version");
    assert_eq!(command.detail["error"], "operation interrupted");
}
