use crate::{cli::Inventory, commands::not_implemented};
use nm_app::AppService;
use nm_core::{Device, DeviceFamily, DeviceId, EnrollmentSource, Site, SiteId, Vendor};
use nm_store::repo::{DeviceFilter, DeviceRepo, SiteRepo};

pub fn execute(command: &Inventory, json: bool, svc: &AppService) -> anyhow::Result<u8> {
    let repo = DeviceRepo::new(&svc.db);
    match command {
        Inventory::Add {
            addr,
            family,
            site,
            name,
        } => {
            let site = site
                .as_ref()
                .map(|name| -> anyhow::Result<SiteId> {
                    let sites = SiteRepo::new(&svc.db);
                    if let Ok(id) = name.parse::<SiteId>() {
                        anyhow::ensure!(sites.get(id)?.is_some(), "site ID does not exist");
                        return Ok(id);
                    }
                    if let Some(site) = sites.list()?.into_iter().find(|s| s.name == *name) {
                        return Ok(site.id);
                    }
                    let site = Site {
                        id: SiteId::new(),
                        name: name.clone(),
                        notes: String::new(),
                    };
                    sites.insert(&site)?;
                    Ok(site.id)
                })
                .transpose()?;
            let device = Device {
                id: DeviceId::new(),
                display_name: name.clone().unwrap_or_else(|| addr.to_string()),
                management: addr.clone(),
                vendor: if *family == DeviceFamily::Unknown {
                    Vendor::Unknown
                } else {
                    Vendor::Ubiquiti
                },
                family: *family,
                role: None,
                site,
                credential_profile: None,
                source: EnrollmentSource::Manual,
                enrolled: false,
                tags: vec![],
            };
            repo.insert(&device)?;
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
                for device in devices {
                    println!(
                        "{}  {:20}  {:20}  {:?}  {}",
                        device.id,
                        device.display_name,
                        device.management,
                        device.family,
                        if device.enrolled {
                            "enrolled"
                        } else {
                            "candidate"
                        }
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
            // Validate the whole request before changing enrollment.
            for id in &ids {
                anyhow::ensure!(repo.get(*id)?.is_some(), "device {id} does not exist");
            }
            if ids.is_empty() {
                if json {
                    println!("{{\"enrolled\":[]}}");
                }
                return Ok(3);
            }
            for id in &ids {
                repo.set_enrolled(*id, true)?;
            }
            if json {
                println!("{}", serde_json::json!({"enrolled":ids}));
            } else {
                println!("Enrolled {} device(s).", ids.len());
            }
            Ok(0)
        }
        Inventory::Import(args) => Ok(not_implemented(
            if args.uisp.is_some() || args.unifi.is_some() {
                "M5"
            } else {
                "M1"
            },
            json,
        )),
        Inventory::Discover { .. } => Ok(not_implemented("M1", json)),
    }
}
