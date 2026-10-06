use nm_core::*;
use nm_store::{repo::*, AuditSink, Db, StoreError};
use sha2::{Digest, Sha256};

fn device() -> Device {
    Device {
        id: DeviceId::new(),
        display_name: "test radio".into(),
        management: "192.0.2.10:22".parse().unwrap(),
        vendor: Vendor::Ubiquiti,
        family: DeviceFamily::AirOs,
        role: Some(DeviceRole::Ap),
        site: None,
        credential_profile: None,
        source: EnrollmentSource::Manual,
        enrolled: false,
        tags: vec!["tower".into()],
    }
}
fn event(target: &str) -> AuditEvent {
    AuditEvent {
        ts: Timestamp::now(),
        actor: Actor::Cli,
        action: AuditAction::DryRun,
        target: target.into(),
        detail: serde_json::json!({}),
        bytes_out: 0,
        bytes_in: 0,
    }
}
#[test]
fn inventory_and_metadata_crud_with_foreign_keys() {
    let db = Db::open_in_memory().unwrap();
    let sites = SiteRepo::new(&db);
    let mut site = Site {
        id: SiteId::new(),
        name: "Tower A".into(),
        notes: "hill".into(),
    };
    sites.insert(&site).unwrap();
    assert_eq!(sites.get(site.id).unwrap(), Some(site.clone()));
    site.notes = "updated".into();
    sites.update(&site).unwrap();
    assert_eq!(sites.list().unwrap(), vec![site.clone()]);
    let profiles = ProfileRepo::new(&db);
    let mut profile = CredentialProfile {
        id: CredentialProfileId::new(),
        name: "fleet".into(),
        kind: CredentialKind::SshPassword {
            username: "readonly".into(),
        },
        storage: StorageMode::SessionOnly,
        scope_hint: "Tower A".into(),
    };
    profiles.insert(&profile).unwrap();
    assert_eq!(profiles.get(profile.id).unwrap(), Some(profile.clone()));
    profile.name = "renamed".into();
    profiles.update(&profile).unwrap();
    assert_eq!(profiles.list().unwrap(), vec![profile.clone()]);
    let devices = DeviceRepo::new(&db);
    let mut dev = device();
    dev.site = Some(site.id);
    dev.credential_profile = Some(profile.id);
    devices.insert(&dev).unwrap();
    assert_eq!(devices.get(dev.id).unwrap(), Some(dev.clone()));
    assert!(sites.delete(site.id).is_err());
    assert!(profiles.delete(profile.id).is_err());
    dev.display_name = "renamed radio".into();
    devices.update(&dev).unwrap();
    devices.set_enrolled(dev.id, true).unwrap();
    dev.enrolled = true;
    let filter = DeviceFilter {
        site: Some(site.id),
        family: Some(DeviceFamily::AirOs),
        enrolled: Some(true),
        source: Some(EnrollmentSource::Manual),
    };
    assert_eq!(devices.list(&filter).unwrap(), vec![dev.clone()]);
    assert!(devices
        .list(&DeviceFilter {
            enrolled: Some(false),
            ..filter.clone()
        })
        .unwrap()
        .is_empty());
    assert!(devices
        .list(&DeviceFilter {
            family: Some(DeviceFamily::EdgeOs),
            ..filter
        })
        .unwrap()
        .is_empty());
    devices.delete(dev.id).unwrap();
    assert_eq!(devices.get(dev.id).unwrap(), None);
    assert!(matches!(
        devices.set_enrolled(dev.id, true),
        Err(StoreError::NotFound)
    ));
    profiles.delete(profile.id).unwrap();
    sites.delete(site.id).unwrap();
    assert!(profiles.list().unwrap().is_empty());
    assert!(sites.list().unwrap().is_empty());
}
#[test]
fn typed_settings_round_trip() {
    let db = Db::open_in_memory().unwrap();
    let repo = SettingsRepo::new(&db);
    assert_eq!(repo.get::<Vec<String>>("providers").unwrap(), None);
    repo.set("providers", &vec!["local".to_string()]).unwrap();
    assert_eq!(
        repo.get::<Vec<String>>("providers").unwrap(),
        Some(vec!["local".into()])
    );
    repo.set("providers", &vec!["other".to_string()]).unwrap();
    assert_eq!(
        repo.get::<Vec<String>>("providers").unwrap(),
        Some(vec!["other".into()])
    );
    assert!(repo.get::<bool>("providers").is_err());
    repo.delete("providers").unwrap();
    assert!(repo.get::<Vec<String>>("providers").unwrap().is_none());
}
#[test]
fn audit_tail_is_newest_first_and_query_is_chronological() {
    let db = Db::open_in_memory().unwrap();
    let repo = AuditRepo::new(&db);
    let before = Timestamp::now();
    for target in ["one", "two", "three", "four"] {
        repo.append(&event(target)).unwrap();
    }
    let after = Timestamp::now();
    assert_eq!(
        repo.tail(3)
            .unwrap()
            .iter()
            .map(|e| e.target.as_str())
            .collect::<Vec<_>>(),
        vec!["four", "three", "two"]
    );
    assert_eq!(repo.query(before, after).unwrap().len(), 4);
    assert!(repo.tail(0).unwrap().is_empty());
}
#[tokio::test]
async fn audit_writer_flushes_in_order() {
    let db = Db::open_in_memory().unwrap();
    let sink = AuditSink::new(db.clone(), 2);
    for target in ["one", "two", "three"] {
        sink.append(event(target)).await.unwrap();
    }
    sink.flush().await.unwrap();
    assert_eq!(
        AuditRepo::new(&db)
            .tail(3)
            .unwrap()
            .iter()
            .map(|e| e.target.as_str())
            .collect::<Vec<_>>(),
        vec!["three", "two", "one"]
    );
}
#[test]
fn snapshots_preserve_facts_coverage_findings_and_redacted_artifacts() {
    let db = Db::open_in_memory().unwrap();
    let repo = SnapshotRepo::new(&db);
    let dev = device();
    let mut snapshot = Snapshot {
        id: SnapshotId::new(),
        started_at: Timestamp::now(),
        finished_at: None,
        device_results: vec![],
        findings: vec![],
    };
    repo.create(&snapshot, "inventory-hash", "first scan")
        .unwrap();
    assert_eq!(repo.get(snapshot.id).unwrap(), Some(snapshot.clone()));
    assert!(repo
        .latest_for_inventory_hash("inventory-hash")
        .unwrap()
        .is_none());
    let raw = RawArtifact {
        kind: ArtifactKind::Text,
        name: "version".into(),
        bytes: b"firmware 1".to_vec(),
        sha256: Sha256::digest(b"firmware 1").into(),
        redacted: true,
    };
    let mut result = DeviceResult {
        device_id: dev.id,
        outcome: Outcome::Partial(vec!["radio".into()]),
        facts: DeviceFacts::default(),
        raw: vec![raw.clone()],
        coverage: Coverage {
            expected: vec!["version".into(), "radio".into()],
            collected: vec!["version".into()],
            missing: vec!["radio".into()],
        },
    };
    result.facts.system.firmware = Some("1".into());
    repo.insert_device_result(snapshot.id, &result).unwrap();
    let mut rejected = raw.clone();
    rejected.redacted = false;
    assert!(matches!(
        repo.insert_raw_artifact(snapshot.id, dev.id, &rejected),
        Err(StoreError::UnredactedArtifact)
    ));
    rejected.redacted = true;
    rejected.bytes.push(1);
    assert!(matches!(
        repo.insert_raw_artifact(snapshot.id, dev.id, &rejected),
        Err(StoreError::ArtifactHash)
    ));
    repo.insert_raw_artifact(snapshot.id, dev.id, &raw).unwrap();
    snapshot.device_results.push(result);
    let finding = Finding {
        id: FindingId::new(),
        rule_id: RuleId::new("GEN-HYG-001").unwrap(),
        severity: Severity::Low,
        category: Category::Hygiene,
        devices: vec![dev.id],
        title: "test".into(),
        evidence: vec![Evidence {
            device_id: dev.id,
            metric_path: "system.firmware".into(),
            observed: serde_json::json!("1"),
            threshold: None,
        }],
        explanation: "test explanation".into(),
        confidence: Confidence::Certain,
    };
    repo.insert_findings(snapshot.id, std::slice::from_ref(&finding))
        .unwrap();
    snapshot.findings.push(finding);
    let finished = Timestamp::now();
    repo.finish(snapshot.id, finished).unwrap();
    snapshot.finished_at = Some(finished);
    assert_eq!(repo.get(snapshot.id).unwrap(), Some(snapshot.clone()));
    assert_eq!(repo.list().unwrap(), vec![snapshot.clone()]);
    assert_eq!(
        repo.latest_for_inventory_hash("inventory-hash").unwrap(),
        Some(snapshot)
    );
    assert!(repo.get(SnapshotId::new()).unwrap().is_none());
}
#[test]
fn file_database_persists_across_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("netmaster.db");
    let db = Db::open(&path).unwrap();
    let dev = device();
    DeviceRepo::new(&db).insert(&dev).unwrap();
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(DeviceRepo::new(&db).get(dev.id).unwrap(), Some(dev));
}
