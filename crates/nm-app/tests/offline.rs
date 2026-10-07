use nm_app::{AppConfig, AppService};
use nm_core::{CredentialKind, CredentialProfile, CredentialProfileId, StorageMode};
use nm_store::repo::{AuditRepo, DeviceFilter, DeviceRepo, ProfileRepo};

#[tokio::test]
async fn app_opens_and_reads_without_network_and_denies_socket_creation() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().to_path_buf()),
        deny_network: true,
    })
    .unwrap();
    assert!(DeviceRepo::new(&svc.db)
        .list(&DeviceFilter::default())
        .unwrap()
        .is_empty());
    assert!(AuditRepo::new(&svc.db).tail(100).unwrap().is_empty());
    assert!(svc.collectors.get(nm_core::DeviceFamily::AirOs).is_some());
    let addr = "127.0.0.1:22".parse().unwrap();
    assert_eq!(
        svc.net.tcp_connect(addr).await.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        svc.net.udp_bind(addr).await.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn persistent_storage_is_explicitly_unimplemented() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().to_path_buf()),
        deny_network: true,
    })
    .unwrap();
    let profile = CredentialProfile {
        id: CredentialProfileId::new(),
        name: "test".into(),
        kind: CredentialKind::ApiToken,
        storage: StorageMode::WindowsCredentialManager,
        scope_hint: String::new(),
        is_vendor_default: false,
    };
    let error = svc
        .add_credential(
            &profile,
            nm_app::SecretMaterial::ApiToken(nm_app::SecretString::new("test".into())),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        nm_app::AppError::Creds(nm_app::CredsError::NotImplemented)
    ));
    assert!(ProfileRepo::new(&svc.db).list().unwrap().is_empty());
    svc.shutdown().await.unwrap();
}

#[tokio::test]
async fn environment_override_selects_deny_all() {
    // CI runs this file again with NETMASTER_NET=deny, without the config override.
    if std::env::var("NETMASTER_NET").as_deref() != Ok("deny") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().to_path_buf()),
        deny_network: false,
    })
    .unwrap();
    let addr = "127.0.0.1:0".parse().unwrap();
    assert_eq!(
        svc.net.udp_bind(addr).await.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    svc.shutdown().await.unwrap();
}
