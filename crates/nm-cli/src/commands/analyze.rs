//! Offline analysis CLI.
use nm_app::AppService;
use nm_core::SnapshotId;
use nm_store::repo::SnapshotRepo;
/// Select an explicit snapshot or the most recently finished snapshot.
pub fn snapshot_id(svc: &AppService, id: Option<SnapshotId>) -> anyhow::Result<Option<SnapshotId>> {
    if let Some(id) = id {
        anyhow::ensure!(
            SnapshotRepo::new(&svc.db).get(id)?.is_some(),
            "snapshot not found"
        );
        Ok(Some(id))
    } else {
        Ok(SnapshotRepo::new(&svc.db)
            .list()?
            .into_iter()
            .find(|s| s.finished_at.is_some())
            .map(|s| s.id))
    }
}
/// Evaluate and persist findings without collector or model access.
pub fn execute(svc: &AppService, id: Option<SnapshotId>, json: bool) -> anyhow::Result<u8> {
    let Some(id) = snapshot_id(svc, id)? else {
        if json {
            println!("{{\"error\":\"no completed snapshots\"}}");
        } else {
            println!("No completed snapshots. Run a scan first.");
        }
        return Ok(3);
    };
    let findings = nm_app::analyze::AnalyzeService::new(&svc.db, &svc.data_dir).run(id)?;
    if json {
        println!("{}", serde_json::to_string(&findings)?);
    } else {
        println!("Snapshot {id}: {} findings", findings.len());
        for f in findings {
            println!("{:?} {} {}", f.severity, f.rule_id, f.title);
        }
    }
    Ok(0)
}
