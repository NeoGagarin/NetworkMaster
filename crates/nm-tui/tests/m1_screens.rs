use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nm_app::{inventory::InventoryService, AppConfig, AppService};
use nm_core::*;
use nm_store::repo::{DeviceFilter, DeviceRepo, SnapshotRepo};
use nm_tui::{
    action::{Action, Effect},
    update, view, App, ScreenId,
};
use ratatui::{backend::TestBackend, Terminal};
use sha2::{Digest, Sha256};
fn key(app: &mut App, svc: &AppService, code: KeyCode) -> Vec<Effect> {
    update(
        app,
        Action::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        svc,
    )
}
fn type_text(app: &mut App, svc: &AppService, s: &str) {
    for c in s.chars() {
        key(app, svc, KeyCode::Char(c));
    }
}
#[tokio::test]
async fn keyboard_add_profile_enroll_and_forget() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let mut app = App::new(&svc).unwrap();
    app.screen = ScreenId::Inventory;
    key(&mut app, &svc, KeyCode::Char('n'));
    type_text(&mut app, &svc, "192.0.2.1");
    key(&mut app, &svc, KeyCode::Tab);
    key(&mut app, &svc, KeyCode::Tab);
    type_text(&mut app, &svc, "AP");
    key(&mut app, &svc, KeyCode::Enter);
    assert_eq!(app.inventory.devices.len(), 1);
    assert!(!app.inventory.devices[0].enrolled);
    app.screen = ScreenId::Credentials;
    key(&mut app, &svc, KeyCode::Char('n'));
    type_text(&mut app, &svc, "fleet");
    key(&mut app, &svc, KeyCode::Tab);
    key(&mut app, &svc, KeyCode::Tab);
    type_text(&mut app, &svc, "operator");
    key(&mut app, &svc, KeyCode::Tab);
    type_text(&mut app, &svc, "planted-secret");
    let effects = key(&mut app, &svc, KeyCode::Enter);
    let Effect::AddCredential { profile, secret } = effects.into_iter().next().unwrap() else {
        panic!()
    };
    let id = profile.id;
    svc.add_credential(&profile, secret).await.unwrap();
    app.refresh(&svc).unwrap();
    assert!(svc.creds.contains(id));
    app.screen = ScreenId::Inventory;
    key(&mut app, &svc, KeyCode::Char('p'));
    key(&mut app, &svc, KeyCode::Enter);
    key(&mut app, &svc, KeyCode::Char('e'));
    assert!(app.inventory.devices[0].enrolled);
    assert_eq!(app.inventory.devices[0].credential_profile, Some(id));
    app.screen = ScreenId::Credentials;
    key(&mut app, &svc, KeyCode::Char('f'));
    let effects = key(&mut app, &svc, KeyCode::Char('y'));
    assert!(matches!(effects[0], Effect::ForgetCredential(_)));
    svc.forget_credential(id).await.unwrap();
    app.refresh(&svc).unwrap();
    assert!(!svc.creds.contains(id));
    assert!(app.inventory.devices[0].credential_profile.is_none());
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn seeded_m1_screen_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let inventory = InventoryService::new(&svc.db);
    let d = inventory
        .add_manual(
            "192.0.2.1".parse().unwrap(),
            DeviceFamily::AirOs,
            Some("Tower AP".into()),
            Some("North"),
        )
        .unwrap();
    inventory.enroll(&[d.id]).unwrap();
    inventory
        .add_manual(
            "192.0.2.2".parse().unwrap(),
            DeviceFamily::AirOs,
            Some("Station candidate".into()),
            Some("North"),
        )
        .unwrap();
    let p = CredentialProfile {
        id: CredentialProfileId::new(),
        name: "fleet".into(),
        kind: CredentialKind::SshPassword {
            username: "operator".into(),
        },
        storage: StorageMode::SessionOnly,
        scope_hint: String::new(),
        is_vendor_default: false,
    };
    svc.add_credential(
        &p,
        nm_app::SecretMaterial::SshPassword(nm_app::SecretString::new("secret".into())),
    )
    .await
    .unwrap();
    inventory.assign_profile(&[d.id], Some(p.id)).unwrap();
    let mut facts = nm_collect_ubiquiti::airos::parse::mca_dump::parse(include_bytes!(
        "../../../fixtures/airos/synthetic-wa-8.7.11/mca-dump.json"
    ))
    .unwrap();
    facts.radio.as_mut().unwrap().stations = nm_collect_ubiquiti::airos::parse::wstalist::parse(
        include_bytes!("../../../fixtures/airos/synthetic-wa-8.7.11/wstalist.json"),
    )
    .unwrap();
    let config = nm_collect_ubiquiti::airos::parse::system_cfg::parse(include_bytes!(
        "../../../fixtures/airos/synthetic-wa-8.7.11/system.cfg"
    ))
    .unwrap();
    nm_collect_ubiquiti::airos::parse::merge(&mut facts, &config);
    let result = DeviceResult {
        device_id: d.id,
        outcome: Outcome::Ok,
        facts,
        raw: vec![RawArtifact {
            kind: ArtifactKind::Json,
            name: "mca-dump.json".into(),
            bytes: include_bytes!("../../../fixtures/airos/synthetic-wa-8.7.11/mca-dump.json")
                .to_vec(),
            sha256: Sha256::digest(include_bytes!(
                "../../../fixtures/airos/synthetic-wa-8.7.11/mca-dump.json"
            ))
            .into(),
            redacted: true,
        }],
        coverage: Coverage {
            expected: vec!["mca-status".into(), "mca-dump".into()],
            collected: vec!["mca-status".into(), "mca-dump".into()],
            ..Coverage::default()
        },
    };
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        started_at: Timestamp::now(),
        finished_at: Some(Timestamp::now()),
        device_results: vec![],
        findings: vec![],
    };
    let repo = SnapshotRepo::new(&svc.db);
    repo.create(&snapshot, "test", "").unwrap();
    repo.insert_device_result(snapshot.id, &result).unwrap();
    for raw in &result.raw {
        repo.insert_raw_artifact(snapshot.id, d.id, raw).unwrap();
    }
    let mut app = App::new(&svc).unwrap();
    app.ascii = true;
    app.force_no_color = true;
    app.apply_theme();
    app.scan.plan = vec![
        "14 SSH commands x 1 devices, 0 HTTP, 0 UDP".into(),
        "Tower AP 192.0.2.1".into(),
        "  192.0.2.1 Ssh mca-status".into(),
    ];
    // Row ordering is deterministic without displaying generated IDs.
    app.inventory.devices = DeviceRepo::new(&svc.db)
        .list(&DeviceFilter::default())
        .unwrap();
    for (width, height) in [(80, 24), (120, 40)] {
        for (screen, progress) in [
            (ScreenId::Inventory, false),
            (ScreenId::Credentials, false),
            (ScreenId::Scan, false),
            (ScreenId::Scan, true),
            (ScreenId::Devices, false),
        ] {
            app.status_line = "Ready. Network actions require enrollment.".into();
            app.scan.states.clear();
            if progress {
                update(
                    &mut app,
                    Action::Job(nm_app::JobEvent::Started { total: 1 }),
                    &svc,
                );
                update(
                    &mut app,
                    Action::Job(nm_app::JobEvent::DeviceState {
                        device: d.id,
                        state: "running mca-status".into(),
                    }),
                    &svc,
                );
            }
            app.screen = screen;
            for tab in if screen == ScreenId::Devices {
                vec![0, 1, 2, 3, 4, 5]
            } else {
                vec![0]
            } {
                app.devices.tab = tab;
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|f| view(&app, f)).unwrap();
                let text = terminal
                    .backend()
                    .buffer()
                    .content
                    .chunks(usize::from(width))
                    .map(|r| {
                        r.iter()
                            .map(ratatui::buffer::Cell::symbol)
                            .collect::<String>()
                            .trim_end()
                            .to_owned()
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                insta::assert_snapshot!(
                    format!(
                        "m1_{}_{tab}_{width}x{height}",
                        if progress {
                            "scan_progress".into()
                        } else {
                            screen.label().to_lowercase()
                        }
                    ),
                    text
                );
            }
        }
    }
    svc.shutdown().await.unwrap();
}

#[tokio::test]
async fn legacy_required_event_queues_the_opt_in_modal() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let mut app = App::new(&svc).unwrap();
    let device = DeviceId::new();
    update(
        &mut app,
        Action::Job(nm_app::JobEvent::LegacyRequired {
            device,
            algorithms: vec!["ssh-rsa".into(), "diffie-hellman-group1-sha1".into()],
        }),
        &svc,
    );
    update(&mut app, Action::Tick, &svc);
    assert!(matches!(app.modal, Some(nm_tui::app::Modal::Legacy(id)) if id == device));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| view(&app, f)).unwrap();
    let rendered = terminal.backend().to_string();
    assert!(
        rendered.contains("diffie-hellman-group1-sha1"),
        "{rendered}"
    );
}
