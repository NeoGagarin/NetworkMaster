#[path = "../../nm-collect/tests/support/mod.rs"]
mod support;
use nm_app::inventory::InventoryService;
use nm_core::*;
use nm_store::{
    repo::{DeviceRepo, ProfileRepo, SnapshotRepo},
    Db,
};
use std::time::Duration;
fn cmd(dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("netmaster"));
    c.arg("--data-dir").arg(dir).env_remove("NETMASTER_NET");
    c
}
fn seed(dir: &std::path::Path, address: std::net::SocketAddr) -> (Db, Device) {
    let db = Db::open(&dir.join("netmaster.db")).unwrap();
    let p = CredentialProfile {
        id: CredentialProfileId::new(),
        name: "test".into(),
        kind: CredentialKind::SshPassword {
            username: "operator".into(),
        },
        storage: StorageMode::SessionOnly,
        scope_hint: String::new(),
        is_vendor_default: false,
    };
    ProfileRepo::new(&db).insert(&p).unwrap();
    let inventory = InventoryService::new(&db);
    let d = inventory
        .add_manual(
            address.to_string().parse().unwrap(),
            DeviceFamily::AirOs,
            Some("fixture AP".into()),
            None,
        )
        .unwrap();
    inventory.assign_profile(&[d.id], Some(p.id)).unwrap();
    inventory.enroll(&[d.id]).unwrap();
    let d = DeviceRepo::new(&db).get(d.id).unwrap().unwrap();
    (db, d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edgeos_scan_redacts_config_skips_protocols_and_analyzes_automatically() {
    use nm_collect::allowlist::edgeos;
    use nm_collect_ubiquiti::edgeos::collector::artifact_name;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/edgeos/synthetic-er-x-2.0.9");
    let mut outputs: std::collections::BTreeMap<_, _> = edgeos::ALL
        .iter()
        .map(|c| {
            (
                c.as_str().to_owned(),
                (std::fs::read(root.join(artifact_name(*c))).unwrap(), 0),
            )
        })
        .collect();
    outputs.insert(edgeos::CONFIG_CMDS.as_str().into(), (
        b"set system host-name fixture-router\nset interfaces ethernet eth0 description WAN\nset service snmp community public authorization ro\nset system login user operator plaintext-password 'planted-edge-secret'\n".to_vec(), 0));
    let server = support::ReplayServer::start(support::key(), false, Duration::ZERO, outputs).await;
    let dir = tempfile::tempdir().unwrap();
    let (db, mut device) = seed(dir.path(), server.address);
    device.family = DeviceFamily::EdgeOs;
    DeviceRepo::new(&db).update(&device).unwrap();
    let path = dir.path().to_owned();
    let scan = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["scan", "--json", "--secret-from-stdin"])
            .write_stdin("test-password\n")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let commands = server.commands.lock().unwrap().clone();
    assert_eq!(
        commands.first().map(String::as_str),
        Some(edgeos::CONFIG_CMDS.as_str())
    );
    for skipped in [
        edgeos::OSPF_NEIGHBOR,
        edgeos::OSPF_INTERFACE,
        edgeos::BGP_SUMMARY,
    ] {
        assert!(!commands.iter().any(|c| c == skipped.as_str()));
    }
    let snapshot = SnapshotRepo::new(&db).list().unwrap().remove(0);
    let result = &snapshot.device_results[0];
    assert_eq!(result.outcome, Outcome::Ok);
    assert_eq!(result.coverage.skipped.len(), 3);
    assert_eq!(result.coverage.collected.len(), 16);
    assert!(result.coverage.missing.is_empty());
    assert_eq!(result.facts.services.snmp.community_is_default, Some(true));
    for artifact in &result.raw {
        let text = String::from_utf8_lossy(&artifact.bytes);
        assert!(!text.contains("planted-edge-secret"));
        if artifact.kind == ArtifactKind::Config {
            assert!(!text.contains("public"));
        }
    }
    assert!(snapshot
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == "UBNT-SEC-005"));
    assert!(snapshot
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == "UBNT-PERF-001"));
    assert!(snapshot
        .findings
        .iter()
        .any(|f| f.rule_id.as_str() == "GEN-CAP-001"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_edgeos_config_is_missing_and_never_persisted_as_complete() {
    use nm_collect::allowlist::edgeos;
    use nm_collect_ubiquiti::edgeos::collector::artifact_name;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/edgeos/synthetic-er-x-2.0.9");
    let mut outputs: std::collections::BTreeMap<_, _> = edgeos::ALL
        .iter()
        .map(|c| {
            (
                c.as_str().to_owned(),
                (std::fs::read(root.join(artifact_name(*c))).unwrap(), 0),
            )
        })
        .collect();
    outputs.insert(
        edgeos::CONFIG_CMDS.as_str().into(),
        (
            b"set system login user operator password 'planted-edge-secret\n".to_vec(),
            0,
        ),
    );
    let server = support::ReplayServer::start(support::key(), false, Duration::ZERO, outputs).await;
    let dir = tempfile::tempdir().unwrap();
    let (db, mut device) = seed(dir.path(), server.address);
    device.family = DeviceFamily::EdgeOs;
    DeviceRepo::new(&db).update(&device).unwrap();
    let path = dir.path().to_owned();
    let scan = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["scan", "--json", "--secret-from-stdin"])
            .write_stdin("test-password\n")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(scan.status.code(), Some(4));
    let snapshot = SnapshotRepo::new(&db).list().unwrap().remove(0);
    let result = &snapshot.device_results[0];
    assert!(result.facts.config.is_none());
    assert!(result
        .coverage
        .missing
        .iter()
        .any(|c| c == edgeos::CONFIG_CMDS.as_str()));
    assert!(result.coverage.skipped.is_empty());
    assert!(!serde_json::to_string(result)
        .unwrap()
        .contains("planted-edge-secret"));
    assert!(!snapshot
        .findings
        .iter()
        .any(|f| matches!(f.rule_id.as_str(), "GEN-HYG-003" | "UBNT-SEC-011")));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_dry_run_matches_real_audit_and_capture_scrubs() {
    let mut outputs = support::fixture_outputs();
    outputs.get_mut("cat /tmp/system.cfg").unwrap().0.extend_from_slice(b"\nwireless.1.wpa.psk=planted-passphrase\nntpclient.1.password=planted-password\nnetconf.2.ip=10.10.10.1\nwireless.2.ssid=Customers\n");
    let server = support::ReplayServer::start(support::key(), false, Duration::ZERO, outputs).await;
    let dir = tempfile::tempdir().unwrap();
    let (db, device) = seed(dir.path(), server.address);
    let path = dir.path().to_owned();
    let dry = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .env("NETMASTER_NET", "deny")
            .args(["scan", "--dry-run", "--json"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(server.commands.lock().unwrap().is_empty());
    let plan: Vec<_> = String::from_utf8(dry.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            v["command"].as_str().map(str::to_owned)
        })
        .collect();
    assert_eq!(plan.len(), 14);
    let path = dir.path().to_owned();
    let scan = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["scan", "--json", "--secret-from-stdin"])
            .write_stdin("test-password\n")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        scan.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&scan.stderr),
        String::from_utf8_lossy(&scan.stdout)
    );
    let path = dir.path().to_owned();
    let audit = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["audit", "tail", "--json"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let events: Vec<AuditEvent> = serde_json::from_slice(&audit.stdout).unwrap();
    let commands: Vec<_> = events
        .iter()
        .rev()
        .filter(|e| e.action == AuditAction::SshCommand)
        .map(|e| e.detail["command"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(plan, commands);
    let snapshots = SnapshotRepo::new(&db).list().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].device_results[0].outcome, Outcome::Ok);
    assert_eq!(
        snapshots[0].device_results[0]
            .facts
            .radio
            .as_ref()
            .unwrap()
            .stations
            .len(),
        1
    );
    let path = dir.path().to_owned();
    let out = dir.path().join("capture");
    let target = out.clone();
    let id = device.id.to_string();
    let capture = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["fixture", "capture", "--device", &id, "--out"])
            .arg(target)
            .arg("--secret-from-stdin")
            .write_stdin("test-password\n")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        capture.status.success(),
        "{}",
        String::from_utf8_lossy(&capture.stderr)
    );
    for file in std::fs::read_dir(out).unwrap() {
        let text = std::fs::read_to_string(file.unwrap().path()).unwrap();
        assert!(!text.contains("planted-"));
        assert!(!text.contains("10.10.10.1"));
        assert!(!text.contains("Customers"));
    }
    assert_eq!(server.commands.lock().unwrap().len(), 28);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_partial_exit_and_station_plan_skip() {
    let mut outputs = support::fixture_outputs();
    outputs.insert("mca-dump".into(), (b"not found".to_vec(), 127));
    let server = support::ReplayServer::start(support::key(), false, Duration::ZERO, outputs).await;
    let dir = tempfile::tempdir().unwrap();
    let (db, mut d) = seed(dir.path(), server.address);
    d.role = Some(DeviceRole::Station);
    DeviceRepo::new(&db).update(&d).unwrap();
    let path = dir.path().to_owned();
    let output = tokio::task::spawn_blocking(move || {
        cmd(&path)
            .args(["scan", "--secret-from-stdin", "--json"])
            .write_stdin("test-password\n")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let snapshot = SnapshotRepo::new(&db).list().unwrap().remove(0);
    let result = &snapshot.device_results[0];
    assert!(matches!(result.outcome, Outcome::Partial(_)));
    assert!(result.coverage.missing.contains(&"mca-dump".into()));
    assert_eq!(result.facts.radio.as_ref().unwrap().signal_dbm, Some(-61));
    assert!(!server
        .commands
        .lock()
        .unwrap()
        .iter()
        .any(|c| c == "wstalist"));
}
