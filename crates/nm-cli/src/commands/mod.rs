pub mod credentials;
pub mod inventory;
use crate::cli::{Audit, Cli, Command, Creds};
use nm_app::AppService;
use nm_store::repo::AuditRepo;

pub async fn execute(cli: &Cli, svc: &AppService) -> anyhow::Result<u8> {
    match cli.command.as_ref().expect("CLI command selected") {
        Command::Inventory { command } => inventory::execute(command, cli.json, svc),
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
        Command::Creds { .. } | Command::Scan { .. } | Command::Fixture { .. } => {
            Ok(not_implemented("M1", cli.json))
        }
        Command::Analyze { .. } | Command::Findings { .. } | Command::Report { .. } => {
            Ok(not_implemented("M2", cli.json))
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
