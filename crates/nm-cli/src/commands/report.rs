//! Deterministic report export.
use nm_app::{
    report::{render_report, ReportOptions},
    AppService,
};
use nm_core::{redact::RedactionLevel, Severity, SnapshotId};
use nm_store::repo::{DeviceFilter, DeviceRepo, SiteRepo, SnapshotRepo};
use std::path::Path;
/// Export stored findings with the same renderer used by the TUI.
pub fn execute(
    svc: &AppService,
    id: SnapshotId,
    path: &Path,
    redact: RedactionLevel,
    min_severity: Option<Severity>,
    json: bool,
) -> anyhow::Result<u8> {
    let snapshot = SnapshotRepo::new(&svc.db)
        .get(id)?
        .ok_or_else(|| anyhow::anyhow!("snapshot not found"))?;
    let options = ReportOptions {
        redact,
        min_severity,
        devices: DeviceRepo::new(&svc.db).list(&DeviceFilter::default())?,
        sites: SiteRepo::new(&svc.db).list()?,
    };
    let report = render_report(&snapshot, &snapshot.findings, &options);
    std::fs::write(path, report)?;
    if json {
        println!("{}", serde_json::json!({"out":path,"snapshot":id}));
    } else {
        println!("Report written to {}", path.display());
    }
    Ok(0)
}
