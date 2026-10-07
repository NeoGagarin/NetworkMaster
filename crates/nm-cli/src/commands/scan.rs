use crate::cli::AuthArgs;
use nm_app::{AppService, Job, JobCtx, JobEvent, JobOutcome, SecretMaterial, SecretVec};
use nm_core::{CredentialKind, Device, DeviceFamily};
use nm_store::repo::{DeviceFilter, DeviceRepo, ProfileRepo};
use tokio_util::sync::CancellationToken;

pub async fn load_credentials(
    svc: &AppService,
    devices: &[Device],
    auth: &AuthArgs,
) -> anyhow::Result<()> {
    let mut ids: Vec<_> = devices
        .iter()
        .filter_map(|d| d.credential_profile)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        if svc.creds.contains(id) {
            continue;
        }
        let profile = ProfileRepo::new(&svc.db)
            .get(id)?
            .ok_or_else(|| anyhow::anyhow!("profile {id} does not exist"))?;
        eprintln!("Load session credential: {}", profile.name);
        let secret = match profile.kind {
            CredentialKind::SshPassword { .. } => SecretMaterial::SshPassword(
                super::credentials::read_secret(auth.secret_from_stdin, "SSH password: ").await?,
            ),
            CredentialKind::SshKey { has_passphrase, .. } => {
                let path = auth.key_file.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--key-file is required to reload SSH key profiles")
                })?;
                SecretMaterial::SshKey {
                    key: SecretVec::new(std::fs::read(path)?),
                    passphrase: if has_passphrase {
                        Some(
                            super::credentials::read_secret(
                                auth.secret_from_stdin,
                                "SSH key passphrase: ",
                            )
                            .await?,
                        )
                    } else {
                        None
                    },
                }
            }
            _ => continue,
        };
        svc.creds.insert(id, secret)?;
    }
    Ok(())
}
pub fn scope(
    svc: &AppService,
    site: Option<&str>,
    family: Option<DeviceFamily>,
) -> anyhow::Result<Vec<Device>> {
    scope_with_enrollment(svc, site, family, Some(true))
}
pub fn scope_with_enrollment(
    svc: &AppService,
    site: Option<&str>,
    family: Option<DeviceFamily>,
    enrolled: Option<bool>,
) -> anyhow::Result<Vec<Device>> {
    let site = site
        .map(|name| {
            let sites = nm_store::repo::SiteRepo::new(&svc.db).list()?;
            sites
                .iter()
                .find(|s| s.name == name || s.id.to_string() == name)
                .map(|s| s.id)
                .ok_or_else(|| anyhow::anyhow!("site not found"))
        })
        .transpose()?;
    Ok(DeviceRepo::new(&svc.db).list(&DeviceFilter {
        site,
        family,
        enrolled,
        ..DeviceFilter::default()
    })?)
}
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    svc: &AppService,
    json: bool,
    dry_run: bool,
    site: Option<&str>,
    family: Option<DeviceFamily>,
    concurrency: Option<usize>,
    per_site: Option<usize>,
    auth: &AuthArgs,
) -> anyhow::Result<u8> {
    let devices = scope(svc, site, family)?;
    if devices.is_empty() {
        if json {
            println!("{}", serde_json::json!({"type":"summary","devices":0}));
        } else {
            println!("No enrolled devices in scope.");
        }
        return Ok(3);
    }
    if !dry_run {
        load_credentials(svc, &devices, auth).await?;
    }
    let cancel = CancellationToken::new();
    let job = svc
        .scan_job(
            devices,
            dry_run,
            concurrency.unwrap_or(svc.settings.max_concurrent_devices),
            per_site.unwrap_or(svc.settings.max_concurrent_per_site),
            cancel.clone(),
        )
        .await?;
    let (events, mut receive) = tokio::sync::mpsc::channel(128);
    let future = job.run(JobCtx {
        cancel: cancel.clone(),
        events,
    });
    tokio::pin!(future);
    let outcome = loop {
        tokio::select! {
            result=&mut future=>break result?,
            Some(event)=receive.recv()=>print_event(event,json),
            result=tokio::signal::ctrl_c(),if !cancel.is_cancelled()=>{result?;cancel.cancel();},
        }
    };
    while let Ok(event) = receive.try_recv() {
        print_event(event, json);
    }
    if json {
        println!(
            "{}",
            serde_json::json!({"type":"summary","outcome":outcome})
        );
    } else {
        println!("{outcome:?}");
    }
    Ok(if cancel.is_cancelled() {
        130
    } else if matches!(outcome,JobOutcome::Scan {partial,failed,..} if partial>0||failed>0) {
        4
    } else {
        0
    })
}
fn print_event(event: JobEvent, json: bool) {
    if json {
        let command = if let JobEvent::Log(line) = &event {
            line.split_once(" Ssh ").map(|(_, c)| c)
        } else {
            None
        };
        println!(
            "{}",
            serde_json::json!({"type":"progress","event":event,"command":command})
        );
    } else {
        match event {
            JobEvent::Log(line) => println!("{line}"),
            other => println!("{other:?}"),
        }
    }
}
