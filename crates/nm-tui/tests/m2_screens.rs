use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nm_app::{analyze::AnalyzeService, inventory::InventoryService, AppConfig, AppService};
use nm_core::*;
use nm_store::repo::SnapshotRepo;
use nm_tui::{
    action::Action,
    app::{update, view},
    App, ScreenId,
};
use ratatui::{backend::TestBackend, Terminal};
fn key(app: &mut App, svc: &AppService, code: KeyCode) {
    update(
        app,
        Action::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        svc,
    );
}
#[tokio::test]
async fn m2_screens_filters_disable_export_and_device_navigation() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let d = InventoryService::new(&svc.db)
        .add_manual(
            "10.0.0.1".parse().unwrap(),
            DeviceFamily::AirOs,
            Some("North AP".into()),
            Some("North Site"),
        )
        .unwrap();
    let ts = serde_json::from_str("\"2026-10-06T04:00:00Z\"").unwrap();
    let s = Snapshot {
        id: "00000000000000000000000001".parse().unwrap(),
        started_at: ts,
        finished_at: Some(ts),
        device_results: vec![],
        findings: vec![],
    };
    let repo = SnapshotRepo::new(&svc.db);
    repo.create(&s, "test", "").unwrap();
    repo.insert_device_result(s.id,&DeviceResult{device_id:d.id,outcome:Outcome::Ok,facts:serde_json::from_value(serde_json::json!({"system":{"hostname":"North AP","model":"R5AC-Lite"},"radio":{"mode":"Ap","frequency_mhz":5800,"channel_width_mhz":20,"stations":[{"mac":"02:00:00:00:00:02","signal_dbm":-76,"chains":[{"rssi_dbm":-55},{"rssi_dbm":-65}]}]}})).unwrap(),raw:vec![],coverage:Coverage::default()}).unwrap();
    AnalyzeService::new(&svc.db, dir.path()).run(s.id).unwrap();
    let mut app = App::new(&svc).unwrap();
    app.ascii = true;
    for screen in [ScreenId::Findings, ScreenId::Topology] {
        app.screen = screen;
        for (width, height) in [(80, 24), (120, 40)] {
            let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
            term.draw(|f| view(&app, f)).unwrap();
            insta::assert_snapshot!(
                format!("m2_{}_{}x{}", screen.label(), width, height),
                term.backend()
                    .buffer()
                    .content
                    .chunks(usize::from(width))
                    .map(|row| row
                        .iter()
                        .map(ratatui::buffer::Cell::symbol)
                        .collect::<String>()
                        .trim_end()
                        .to_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
    app.screen = ScreenId::Findings;
    key(&mut app, &svc, KeyCode::Char('/'));
    for c in "UBNT-RF-001".chars() {
        key(&mut app, &svc, KeyCode::Char(c));
    }
    key(&mut app, &svc, KeyCode::Enter);
    assert_eq!(app.findings.visible(&app.devices.snapshots[0]).len(), 1);
    key(&mut app, &svc, KeyCode::Char('E'));
    let report = std::fs::read_to_string(dir.path().join(format!("report-{}.md", s.id))).unwrap();
    assert!(report.contains("UBNT-RF-001"));
    assert!(!report.contains("UBNT-RF-004"));
    key(&mut app, &svc, KeyCode::Enter);
    assert_eq!(app.screen, ScreenId::Devices);
    assert_eq!(app.devices.cursor, 0);
    app.screen = ScreenId::Findings;
    key(&mut app, &svc, KeyCode::Char('D'));
    assert!(app.findings.visible(&app.devices.snapshots[0]).is_empty());
    assert!(std::fs::read_to_string(dir.path().join("rules.toml"))
        .unwrap()
        .contains("UBNT-RF-001 = false"));
    svc.shutdown().await.unwrap();
}
