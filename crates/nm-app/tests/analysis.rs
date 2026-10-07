use nm_app::{
    analyze::AnalyzeService,
    inventory::InventoryService,
    report::{render_report, ReportOptions},
    AppConfig, AppService,
};
use nm_core::*;
use nm_store::repo::{FindingFilter, FindingsRepo, ProfileRepo, SnapshotRepo};

fn snapshot(device: DeviceId) -> Snapshot {
    let ts: Timestamp = serde_json::from_str("\"2026-10-06T04:00:00Z\"").unwrap();
    Snapshot{id:"00000000000000000000000001".parse().unwrap(),started_at:ts,finished_at:Some(ts),device_results:vec![DeviceResult{device_id:device,outcome:Outcome::Partial(vec!["show interfaces".into()]),facts:serde_json::from_value(serde_json::json!({"system":{"hostname":"CustomerRouter","serial":"private-serial","model":"ER-X","offload":{"ipv4_forwarding":false}},"interfaces":[{"name":"eth0","role":"Wan","addresses":["203.0.113.17/24"]}],"config":{"text":"set interfaces ethernet eth0 description WAN"}})).unwrap(),raw:vec![],coverage:Coverage{expected:vec!["show interfaces".into()],missing:vec!["show interfaces".into()],..Default::default()}}],findings:vec![]}
}
#[tokio::test]
async fn analysis_is_idempotent_filters_and_disabling_refresh_persisted_rows() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let d = InventoryService::new(&svc.db)
        .add_manual(
            "10.0.0.1".parse().unwrap(),
            DeviceFamily::EdgeOs,
            Some("Private Name".into()),
            Some("Private Site"),
        )
        .unwrap();
    let s = snapshot(d.id);
    SnapshotRepo::new(&svc.db).create(&s, "test", "").unwrap();
    SnapshotRepo::new(&svc.db)
        .insert_device_result(s.id, &s.device_results[0])
        .unwrap();
    let analyze = AnalyzeService::new(&svc.db, dir.path());
    let a = analyze.run(s.id).unwrap();
    assert!(!a.is_empty());
    assert_eq!(a, analyze.run(s.id).unwrap());
    let repo = FindingsRepo::new(&svc.db);
    assert_eq!(
        a,
        repo.query(&FindingFilter {
            snapshot: Some(s.id),
            ..Default::default()
        })
        .unwrap()
    );
    let id = RuleId::new("UBNT-PERF-001").unwrap();
    let filtered = repo
        .query(&FindingFilter {
            snapshot: Some(s.id),
            rule: Some(id.clone()),
            device: Some(d.id),
            category: Some(Category::Performance),
            severity_min: Some(Severity::High),
        })
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert!(repo
        .query(&FindingFilter {
            severity_min: Some(Severity::Critical),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    analyze.set_enabled(id.clone(), false, Some(s.id)).unwrap();
    assert!(repo
        .query(&FindingFilter {
            snapshot: Some(s.id),
            rule: Some(id),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn entered_default_credential_stores_only_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    for (username, password, expected) in [
        ("ubnt", "ubnt", true),
        ("ubnt", "different-password", false),
        ("operator", "ubnt", false),
    ] {
        let p = CredentialProfile {
            id: CredentialProfileId::new(),
            name: "fleet".into(),
            kind: CredentialKind::SshPassword {
                username: username.into(),
            },
            storage: StorageMode::SessionOnly,
            scope_hint: String::new(),
            is_vendor_default: !expected,
        };
        svc.add_credential(
            &p,
            nm_app::SecretMaterial::SshPassword(nm_app::SecretString::new(password.into())),
        )
        .await
        .unwrap();
        assert_eq!(
            ProfileRepo::new(&svc.db)
                .get(p.id)
                .unwrap()
                .unwrap()
                .is_vendor_default,
            expected
        );
    }
    svc.shutdown().await.unwrap();
}
#[test]
fn report_golden_redaction_and_markdown_escape() {
    let d = Device {
        id: "00000000000000000000000002".parse().unwrap(),
        display_name: "Private Name".into(),
        management: "203.0.113.17".parse().unwrap(),
        vendor: Vendor::Ubiquiti,
        family: DeviceFamily::EdgeOs,
        role: Some(DeviceRole::Router),
        site: Some("00000000000000000000000004".parse().unwrap()),
        credential_profile: None,
        source: EnrollmentSource::Manual,
        enrolled: true,
        ssh_legacy_ok: false,
        tags: vec![],
        interface_roles: std::collections::BTreeMap::default(),
    };
    let s = snapshot(d.id);
    let sites = vec![Site {
        id: d.site.unwrap(),
        name: "Private Site".into(),
        notes: String::new(),
        max_distance_m: None,
    }];
    let view = nm_analyze::SnapshotView::new(&s, std::slice::from_ref(&d), &sites, &[]);
    let mut findings = nm_analyze::runner::evaluate(&view, &nm_analyze::RuleConfig::default());
    findings[0].evidence[0].observed = serde_json::json!({"host":"CustomerRouter","address":"203.0.113.17","mac":"02:00:00:00:00:01","serial":"private-serial","unsafe":"a|<script>\nnext"});
    let options = ReportOptions {
        devices: vec![d],
        sites,
        ..Default::default()
    };
    let report = render_report(&s, &findings, &options);
    for hidden in [
        "Private Name",
        "Private Site",
        "CustomerRouter",
        "203.0.113.17",
        "02:00:00:00:00:01",
        "private-serial",
        "00000000000000000000000002",
    ] {
        assert!(!report.contains(hidden), "{hidden}");
    }
    assert!(report.contains("&#124;"));
    assert!(report.contains("&lt;script&gt;"));
    assert!(!report.contains("<script>"));
    insta::assert_snapshot!("full_redacted_report", report);
    let names = render_report(
        &s,
        &findings,
        &ReportOptions {
            redact: nm_core::redact::RedactionLevel::Names,
            ..options.clone()
        },
    );
    assert!(names.contains("203.0.113.17"));
    assert!(!names.contains("Private Name"));
    let clear = render_report(
        &s,
        &findings,
        &ReportOptions {
            redact: nm_core::redact::RedactionLevel::None,
            min_severity: Some(Severity::Critical),
            ..options
        },
    );
    assert!(clear.contains("Private Name"));
    assert!(!clear.contains("UBNT-PERF-001"));
}
