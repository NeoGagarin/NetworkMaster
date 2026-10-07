use assert_cmd::Command;
use nm_core::*;
use nm_store::{
    repo::{DeviceRepo, SiteRepo, SnapshotRepo},
    Db,
};
use predicates::prelude::*;
fn command(path: &std::path::Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("netmaster"));
    cmd.env("NETMASTER_NET", "deny").arg("--data-dir").arg(path);
    cmd
}
#[test]
fn analysis_findings_rules_report_and_topology_have_cli_parity() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("netmaster.db")).unwrap();
    let site = Site {
        id: SiteId::new(),
        name: "Private Site".into(),
        notes: String::new(),
        max_distance_m: None,
    };
    SiteRepo::new(&db).insert(&site).unwrap();
    let d = Device {
        id: DeviceId::new(),
        display_name: "Private Router".into(),
        management: "10.0.0.1".parse().unwrap(),
        vendor: Vendor::Ubiquiti,
        family: DeviceFamily::EdgeOs,
        role: Some(DeviceRole::Router),
        site: Some(site.id),
        credential_profile: None,
        source: EnrollmentSource::Manual,
        enrolled: true,
        ssh_legacy_ok: false,
        tags: vec![],
        interface_roles: std::collections::BTreeMap::default(),
    };
    DeviceRepo::new(&db).insert(&d).unwrap();
    let s = Snapshot {
        id: SnapshotId::new(),
        started_at: Timestamp::now(),
        finished_at: Some(Timestamp::now()),
        device_results: vec![],
        findings: vec![],
    };
    let repo = SnapshotRepo::new(&db);
    repo.create(&s, "test", "").unwrap();
    repo.insert_device_result(
        s.id,
        &DeviceResult {
            device_id: d.id,
            outcome: Outcome::Ok,
            facts: serde_json::from_value(
                serde_json::json!({"system":{"model":"ER-X","offload":{"ipv4_forwarding":false}}}),
            )
            .unwrap(),
            raw: vec![],
            coverage: Coverage::default(),
        },
    )
    .unwrap();
    command(dir.path())
        .args(["analyze", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("UBNT-PERF-001"));
    command(dir.path())
        .args([
            "findings",
            "--severity",
            "high",
            "--category",
            "performance",
            "--device",
            &d.id.to_string(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("UBNT-PERF-001"));
    command(dir.path())
        .args(["rules", "disable", "UBNT-PERF-001"])
        .assert()
        .success();
    command(dir.path())
        .args(["findings", "--json"])
        .assert()
        .success()
        .stdout("[]\n");
    command(dir.path())
        .args(["rules", "enable", "UBNT-PERF-001"])
        .assert()
        .success();
    command(dir.path())
        .args(["rules", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GEN-CAP-002"));
    command(dir.path())
        .args(["rules", "disable", "GEN-HYG-123"])
        .assert()
        .failure();
    let out = dir.path().join("report.md");
    command(dir.path())
        .args(["report", "--snapshot", &s.id.to_string(), "--out"])
        .arg(&out)
        .assert()
        .success();
    let text = std::fs::read_to_string(out).unwrap();
    assert!(text.contains("UBNT-PERF-001"));
    assert!(!text.contains("Private Router"));
    command(dir.path())
        .args(["topology", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Private Router"));
    let doc = command(dir.path())
        .args(["rules", "export-md"])
        .output()
        .unwrap();
    assert!(doc.status.success());
    assert_eq!(
        String::from_utf8(doc.stdout).unwrap(),
        nm_analyze::catalog::export_md()
    );
    let empty = tempfile::tempdir().unwrap();
    command(empty.path()).arg("analyze").assert().code(3);
}
