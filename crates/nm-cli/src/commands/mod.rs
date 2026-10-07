pub mod analyze;
pub mod credentials;
pub mod findings;
pub mod fixture;
pub mod inventory;
pub mod report;
pub mod rules;
pub mod scan;
use crate::cli::{Audit, Cli, Command, Creds};
use nm_app::AppService;
use nm_store::repo::AuditRepo;

pub async fn execute(cli: &Cli, svc: &AppService) -> anyhow::Result<u8> {
    match cli.command.as_ref().expect("CLI command selected") {
        Command::Inventory { command } => inventory::execute(command, cli.json, svc).await,
        Command::Creds {
            command: Creds::Add(args),
        } => credentials::add(args, cli.json, svc).await,
        Command::Audit {
            command: Audit::Tail { count },
        } => {
            let events = AuditRepo::new(&svc.db).tail(*count)?;
            if cli.json {
                println!("{}", serde_json::to_string(&events)?);
            } else {
                for event in events {
                    println!(
                        "{} {:?} {:?} {} {}",
                        event.ts, event.actor, event.action, event.target, event.detail
                    );
                }
            }
            Ok(0)
        }
        Command::Forget { .. } => {
            svc.forget_all_credentials().await?;
            if cli.json {
                println!("{{\"forgotten\":true,\"storage\":\"session-only\"}}");
            } else {
                println!("All credentials in this process have been forgotten. Profile metadata is retained.");
            }
            Ok(0)
        }
        Command::Scan {
            dry_run,
            site,
            family,
            concurrency,
            per_site,
            auth,
        } => {
            scan::execute(
                svc,
                cli.json,
                *dry_run,
                site.as_deref(),
                *family,
                *concurrency,
                *per_site,
                auth,
            )
            .await
        }
        Command::Fixture {
            command: crate::cli::Fixture::Capture { device, out, auth },
        } => fixture::execute(svc, *device, out, auth, cli.json).await,
        Command::Creds {
            command:
                Creds::Assign {
                    profile,
                    devices,
                    site,
                    family,
                },
        } => {
            let ids = if devices.is_empty() {
                scan::scope_with_enrollment(svc, site.as_deref(), *family, None)?
                    .into_iter()
                    .map(|d| d.id)
                    .collect()
            } else {
                devices.clone()
            };
            nm_app::inventory::InventoryService::new(&svc.db)
                .assign_profile(&ids, Some(*profile))?;
            println!("{}", serde_json::json!({"assigned":ids,"profile":profile}));
            Ok(if ids.is_empty() { 3 } else { 0 })
        }
        Command::Analyze { snapshot } => analyze::execute(svc, *snapshot, cli.json),
        Command::Findings {
            severity,
            category,
            device,
            rule,
            snapshot,
        } => findings::execute(
            svc,
            &nm_store::repo::FindingFilter {
                snapshot: *snapshot,
                severity_min: *severity,
                category: *category,
                device: *device,
                rule: rule.clone(),
            },
            cli.json,
        ),
        Command::Rules { command } => rules::execute(svc, command, cli.json),
        Command::Report {
            snapshot,
            out,
            redact,
            min_severity,
        } => report::execute(
            svc,
            *snapshot,
            out,
            match redact.as_str() {
                "none" => nm_core::redact::RedactionLevel::None,
                "names" => nm_core::redact::RedactionLevel::Names,
                _ => nm_core::redact::RedactionLevel::Full,
            },
            *min_severity,
            cli.json,
        ),
        Command::Topology { snapshot } => {
            let Some(id) = analyze::snapshot_id(svc, *snapshot)? else {
                return Ok(3);
            };
            let snapshot = nm_store::repo::SnapshotRepo::new(&svc.db)
                .get(id)?
                .expect("selected snapshot");
            let devices = nm_store::repo::DeviceRepo::new(&svc.db)
                .list(&nm_store::repo::DeviceFilter::default())?;
            let sites = nm_store::repo::SiteRepo::new(&svc.db).list()?;
            let view = nm_analyze::SnapshotView::new(&snapshot, &devices, &sites, &[]);
            println!(
                "{}",
                serde_json::to_string_pretty(&nm_analyze::topology::infer(&view))?
            );
            Ok(0)
        }
        Command::Ai { .. } => Ok(not_implemented("M3", cli.json)),
        Command::Export { .. } | Command::Mcp { .. } => Ok(not_implemented("M4", cli.json)),
        Command::Diff { .. } => Ok(not_implemented("M6", cli.json)),
    }
}
pub fn not_implemented(milestone: &str, json: bool) -> u8 {
    if json {
        println!(
            "{}",
            serde_json::json!({"error":"not implemented yet","planned_for":milestone})
        );
    } else {
        eprintln!("not implemented yet (planned for {milestone})");
    }
    2
}
