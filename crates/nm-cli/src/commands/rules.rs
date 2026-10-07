//! Catalog documentation and local rule enablement.
use crate::cli::Rules;
use nm_app::AppService;
/// Run a catalog subcommand; enablement immediately refreshes the latest snapshot.
pub fn execute(svc: &AppService, command: &Rules, json: bool) -> anyhow::Result<u8> {
    match command {
        Rules::ExportMd => print!("{}", nm_analyze::catalog::export_md()),
        Rules::List => {
            let config = nm_analyze::RuleConfig::load(&svc.data_dir.join("rules.toml"))
                .map_err(anyhow::Error::msg)?;
            if json {
                let rules:Vec<_>=nm_analyze::catalog::all().iter().map(|r|serde_json::json!({"meta":r.meta(),"enabled":config.is_enabled(&r.meta().id)})).collect();
                println!("{}", serde_json::to_string(&rules)?);
            } else {
                for r in nm_analyze::catalog::all() {
                    println!(
                        "{} {:?} {} [{}]",
                        r.meta().id,
                        r.meta().default_severity,
                        r.meta().title,
                        if config.is_enabled(&r.meta().id) {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                }
            }
        }
        Rules::Disable { id } | Rules::Enable { id } => {
            let snapshot = super::analyze::snapshot_id(svc, None)?;
            nm_app::analyze::AnalyzeService::new(&svc.db, &svc.data_dir).set_enabled(
                id.clone(),
                matches!(command, Rules::Enable { .. }),
                snapshot,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"rule":id,"enabled":matches!(command,Rules::Enable{..})})
                );
            } else {
                println!(
                    "{id}: {}",
                    if matches!(command, Rules::Enable { .. }) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            }
        }
    }
    Ok(0)
}
