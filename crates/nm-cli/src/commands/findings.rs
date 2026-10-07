//! Filtered persisted findings CLI.
use nm_app::AppService;
use nm_store::repo::{FindingFilter, FindingsRepo};
/// Print findings using the supplied repository filter.
pub fn execute(svc: &AppService, filter: &FindingFilter, json: bool) -> anyhow::Result<u8> {
    let findings = FindingsRepo::new(&svc.db).query(filter)?;
    if json {
        println!("{}", serde_json::to_string(&findings)?);
    } else {
        for f in findings {
            println!(
                "{:?} {} {} ({} devices, {:?})",
                f.severity,
                f.rule_id,
                f.title,
                f.devices.len(),
                f.confidence
            );
        }
    }
    Ok(0)
}
