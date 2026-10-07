use crate::{cli::Inventory, commands::not_implemented};
use nm_app::{inventory::InventoryService, AppService};
use nm_store::repo::{DeviceFilter, DeviceRepo};
pub async fn execute(command: &Inventory, json: bool, svc: &AppService) -> anyhow::Result<u8> {
    let inventory = InventoryService::new(&svc.db);
    let repo = DeviceRepo::new(&svc.db);
    match command {
        Inventory::Add {
            addr,
            family,
            role,
            site,
            name,
        } => {
            let device =
                inventory.add_manual(addr.clone(), *family, name.clone(), site.as_deref())?;
            inventory.set_role(&[device.id], *role)?;
            let device = repo.get(device.id)?.expect("inserted device");
            if json {
                println!("{}", serde_json::to_string(&device)?);
            } else {
                println!(
                    "{} {} (candidate; not enrolled)",
                    device.id, device.display_name
                );
            }
            Ok(0)
        }
        Inventory::List => {
            let devices = repo.list(&DeviceFilter::default())?;
            if json {
                println!("{}", serde_json::to_string(&devices)?);
            } else {
                for d in devices {
                    println!(
                        "{} {:20} {:20} {:?} {}",
                        d.id,
                        d.display_name,
                        d.management,
                        d.family,
                        if d.enrolled { "enrolled" } else { "candidate" }
                    );
                }
            }
            Ok(0)
        }
        Inventory::Enroll {
            ids,
            all_candidates,
        } => {
            let ids = if *all_candidates {
                repo.list(&DeviceFilter {
                    enrolled: Some(false),
                    ..DeviceFilter::default()
                })?
                .into_iter()
                .map(|d| d.id)
                .collect()
            } else {
                ids.clone()
            };
            if ids.is_empty() {
                if json {
                    println!("{}", serde_json::json!({"enrolled":[]}));
                }
                return Ok(3);
            }
            inventory.enroll(&ids)?;
            if json {
                println!("{}", serde_json::json!({"enrolled":ids}));
            } else {
                println!("Enrolled {} device(s).", ids.len());
            }
            Ok(0)
        }
        Inventory::Unenroll { ids } => {
            inventory.unenroll(ids)?;
            Ok(0)
        }
        Inventory::AllowLegacy { ids } => {
            inventory.allow_legacy(ids, true)?;
            println!("{}", serde_json::json!({"ssh_legacy_ok":ids}));
            Ok(0)
        }
        Inventory::Import(args) => {
            if args.uisp.is_some() || args.unifi.is_some() {
                return Ok(not_implemented("M5", json));
            }
            let file = std::fs::File::open(args.file.as_ref().expect("CSV source"))?;
            let report = inventory.import_csv(file)?;
            if json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                println!(
                    "Added {}; skipped {} duplicates.",
                    report.added, report.skipped_duplicates
                );
                for (line, reason) in &report.errors {
                    println!("line {line}: {reason}");
                }
            }
            Ok(if report.errors.is_empty() { 0 } else { 4 })
        }
        Inventory::Discover { interface } => {
            let interfaces = nm_collect::list_local_interfaces()?;
            let iface = interfaces
                .iter()
                .find(|i| i.name == *interface || i.ipv4.to_string() == *interface)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "interface not found; available: {}",
                        interfaces
                            .iter()
                            .map(|i| format!("{} ({})", i.name, i.ipv4))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            let devices = nm_collect_ubiquiti::discovery::discover(
                svc.net.as_ref(),
                &svc.audit,
                iface,
                std::time::Duration::from_secs(3),
            )
            .await?;
            let mut added = 0;
            for d in &devices {
                if let Some(candidate) = d.candidate() {
                    added += usize::from(inventory.add_candidate(&candidate)?);
                }
            }
            if json {
                for d in &devices {
                    println!("{}", serde_json::json!({"type":"candidate","device":d}));
                }
                println!(
                    "{}",
                    serde_json::json!({"type":"summary","replies":devices.len(),"added":added,"enrolled":0})
                );
            } else if devices.is_empty() {
                println!("no replies — many operators disable UBNT discovery");
            } else {
                println!("Added {added} candidates. Enroll explicitly with inventory enroll.");
            }
            Ok(0)
        }
    }
}
