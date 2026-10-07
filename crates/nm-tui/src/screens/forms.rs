use crate::{
    action::Effect,
    app::{Modal, ScreenId},
    widgets, App,
};
use crossterm::event::{KeyCode, KeyEvent};
use nm_app::{inventory::InventoryService, AppService};
use nm_core::{CredentialKind, CredentialProfile, CredentialProfileId, DeviceFamily, StorageMode};
use ratatui::{
    layout::Rect,
    widgets::{Clear, Paragraph},
    Frame,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum FormKind {
    Manual,
    Import,
    Credential,
    Site,
    Filter,
    ConfigSearch,
    Concurrency,
    InterfaceRole,
}
pub struct Field {
    pub label: &'static str,
    pub value: Zeroizing<String>,
    pub secret: bool,
    pub choices: Vec<&'static str>,
}
pub struct Form {
    pub kind: FormKind,
    pub fields: Vec<Field>,
    pub cursor: usize,
}
impl Form {
    pub fn new(kind: FormKind) -> Self {
        let labels: Vec<(&str, &str, bool, Vec<&str>)> = match kind {
            FormKind::Manual => vec![
                ("Address", "", false, vec![]),
                (
                    "Family",
                    "airos",
                    false,
                    vec!["airos", "edgeos", "edgeswitch", "unifi", "uisp", "auto"],
                ),
                ("Name", "", false, vec![]),
                ("Site", "", false, vec![]),
                (
                    "Role",
                    "auto",
                    false,
                    vec!["auto", "ap", "station", "ptp", "router", "switch"],
                ),
            ],
            FormKind::Import => vec![("CSV file", "", false, vec![])],
            FormKind::Credential => vec![
                ("Name", "", false, vec![]),
                (
                    "Kind",
                    "ssh-password",
                    false,
                    vec!["ssh-password", "ssh-key"],
                ),
                ("Username", "", false, vec![]),
                ("Password / key file", "", true, vec![]),
            ],
            FormKind::Site => vec![
                ("Site name", "", false, vec![]),
                ("Max distance (m, optional)", "", false, vec![]),
            ],
            FormKind::InterfaceRole => vec![
                ("Interface", "", false, vec![]),
                (
                    "Role",
                    "auto",
                    false,
                    vec!["auto", "wan", "lan", "management"],
                ),
            ],
            FormKind::Filter => vec![("Filter", "", false, vec![])],
            FormKind::ConfigSearch => vec![("Config search", "", false, vec![])],
            FormKind::Concurrency => vec![
                ("Global", "8", false, vec![]),
                ("Per site", "2", false, vec![]),
            ],
        };
        Self {
            kind,
            cursor: 0,
            fields: labels
                .into_iter()
                .map(|(label, value, secret, choices)| Field {
                    label,
                    value: Zeroizing::new(value.into()),
                    secret,
                    choices,
                })
                .collect(),
        }
    }
    fn edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.cursor = (self.cursor + 1) % self.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.cursor = (self.cursor + self.fields.len() - 1) % self.fields.len();
            }
            KeyCode::Left | KeyCode::Right => {
                let f = &mut self.fields[self.cursor];
                if !f.choices.is_empty() {
                    let i = f
                        .choices
                        .iter()
                        .position(|s| *s == f.value.as_str())
                        .unwrap_or(0);
                    let i = if key.code == KeyCode::Right {
                        (i + 1) % f.choices.len()
                    } else {
                        (i + f.choices.len() - 1) % f.choices.len()
                    };
                    *f.value = f.choices[i].into();
                }
            }
            KeyCode::Char(c) => {
                if self.fields[self.cursor].choices.is_empty() {
                    self.fields[self.cursor].value.push(c);
                }
            }
            KeyCode::Backspace => {
                if self.fields[self.cursor].choices.is_empty() {
                    self.fields[self.cursor].value.pop();
                }
            }
            _ => {}
        }
    }
}
#[derive(Clone, Copy)]
pub enum PickerKind {
    Profile,
    Site,
    Interface,
    Scope,
}
pub struct Picker {
    pub kind: PickerKind,
    pub options: Vec<(String, String)>,
    pub cursor: usize,
}
pub fn picker(app: &mut App, kind: PickerKind, svc: &AppService) {
    let options = match kind {
        PickerKind::Profile => svc_profiles(svc),
        PickerKind::Site => app
            .inventory
            .sites
            .iter()
            .map(|(id, name)| (name.clone(), id.to_string()))
            .chain(std::iter::once(("new site...".into(), "new".into())))
            .collect(),
        PickerKind::Interface => nm_collect::list_local_interfaces()
            .unwrap_or_default()
            .iter()
            .map(|i| (format!("{} ({})", i.name, i.ipv4), i.ipv4.to_string()))
            .collect(),
        PickerKind::Scope => vec![
            ("all enrolled".into(), "all enrolled".into()),
            ("Inventory selection".into(), "selection".into()),
        ]
        .into_iter()
        .chain(
            app.inventory
                .sites
                .iter()
                .map(|(id, name)| (format!("site: {name}"), format!("site:{id}"))),
        )
        .chain(
            [
                DeviceFamily::AirOs,
                DeviceFamily::EdgeOs,
                DeviceFamily::EdgeSwitch,
                DeviceFamily::UniFi,
                DeviceFamily::Uisp,
            ]
            .into_iter()
            .map(|f| (format!("family: {f:?}"), format!("family:{f:?}"))),
        )
        .collect(),
    };
    app.modal = Some(Modal::Picker(Picker {
        kind,
        options,
        cursor: 0,
    }));
}
fn svc_profiles(svc: &AppService) -> Vec<(String, String)> {
    nm_store::repo::ProfileRepo::new(&svc.db)
        .list()
        .unwrap_or_default()
        .iter()
        .map(|p| (p.name.clone(), p.id.to_string()))
        .collect()
}
pub fn modal_key(app: &mut App, key: KeyEvent, svc: &AppService) -> Vec<Effect> {
    let Some(mut modal) = app.modal.take() else {
        return vec![];
    };
    if key.code == KeyCode::Esc
        || key.code == KeyCode::Char('n')
            && matches!(
                modal,
                Modal::ConfirmQuit
                    | Modal::Remove(_)
                    | Modal::Forget(_)
                    | Modal::ConfirmScan(_)
                    | Modal::Legacy(_)
                    | Modal::EnrollDiscovery(_)
            )
    {
        return vec![];
    }
    match &mut modal {
        Modal::Form(form) => {
            if key.code == KeyCode::Enter {
                match submit(form, app, svc) {
                    Ok(effects) => {
                        let _ = app.refresh(svc);
                        return effects;
                    }
                    Err(error) => app.status_line = error.to_string(),
                }
            } else {
                form.edit(key);
            }
        }
        Modal::Picker(p) => match key.code {
            KeyCode::Down => p.cursor = (p.cursor + 1).min(p.options.len().saturating_sub(1)),
            KeyCode::Up => p.cursor = p.cursor.saturating_sub(1),
            KeyCode::Enter => {
                if let Some((_, value)) = p.options.get(p.cursor) {
                    let result: anyhow::Result<Vec<Effect>> = (|| {
                        let inventory = InventoryService::new(&svc.db);
                        match p.kind {
                            PickerKind::Profile => inventory
                                .assign_profile(&app.inventory.targets(), Some(value.parse()?))?,
                            PickerKind::Site => {
                                if value == "new" {
                                    app.modal = Some(Modal::Form(Form::new(FormKind::Site)));
                                    return Ok(vec![]);
                                }
                                inventory
                                    .set_site(&app.inventory.targets(), Some(value.parse()?))?;
                            }
                            PickerKind::Interface => {
                                let iface = nm_collect::list_local_interfaces()?
                                    .into_iter()
                                    .find(|i| i.ipv4.to_string() == *value)
                                    .ok_or_else(|| anyhow::anyhow!("interface disappeared"))?;
                                app.inventory.discovering = true;
                                return Ok(vec![Effect::Discover(iface)]);
                            }
                            PickerKind::Scope => app.scan.scope.clone_from(value),
                        }
                        app.refresh(svc)?;
                        Ok(vec![])
                    })();
                    match result {
                        Ok(effects) => return effects,
                        Err(e) => app.status_line = e.to_string(),
                    }
                }
            }
            _ => {}
        },
        Modal::ConfirmQuit if key.code == KeyCode::Char('y') => {
            svc.jobs.cancel_active();
            app.status_line = "Cancelling and saving snapshot before exit...".into();
            app.quit_after_job = true;
            return vec![];
        }
        Modal::Remove(ids) if key.code == KeyCode::Char('y') => {
            if let Err(e) = InventoryService::new(&svc.db).remove(ids) {
                app.status_line = e.to_string();
            }
            let _ = app.refresh(svc);
            return vec![];
        }
        Modal::Forget(id) if key.code == KeyCode::Char('y') => {
            return vec![Effect::ForgetCredential(*id)]
        }
        Modal::ConfirmScan(devices) if key.code == KeyCode::Char('y') => {
            app.scan.states = devices.iter().map(|d| (d.id, "queued".into())).collect();
            app.scan.started = Some(std::time::Instant::now());
            app.scan.device_started.clear();
            app.scan.device_elapsed.clear();
            app.scan.done = 0;
            app.scan.total = devices.len();
            app.scan.snapshot = None;
            return vec![Effect::StartScan {
                devices: devices.clone(),
                dry_run: false,
            }];
        }
        Modal::Legacy(id) if key.code == KeyCode::Char('y') => {
            if let Err(e) = InventoryService::new(&svc.db).allow_legacy(&[*id], true) {
                app.status_line = e.to_string();
            } else {
                app.status_line = "Legacy SSH allowed for this device. Run the scan again.".into();
            }
            let _ = app.refresh(svc);
            return vec![];
        }
        Modal::EnrollDiscovery(ids) if key.code == KeyCode::Char('y') => {
            if let Err(e) = InventoryService::new(&svc.db).enroll(ids) {
                app.status_line = e.to_string();
            }
            app.inventory.discovery_candidates = false;
            let _ = app.refresh(svc);
            return vec![];
        }
        _ => {}
    }
    app.modal = Some(modal);
    vec![]
}
fn submit(form: &mut Form, app: &mut App, svc: &AppService) -> anyhow::Result<Vec<Effect>> {
    let value = |i: usize| form.fields[i].value.as_str();
    let inventory = InventoryService::new(&svc.db);
    match form.kind {
        FormKind::Manual => {
            let device = inventory.add_manual(
                value(0).parse().map_err(anyhow::Error::msg)?,
                value(1).parse().map_err(anyhow::Error::msg)?,
                Some(value(2).into()),
                (!value(3).is_empty()).then_some(value(3)),
            )?;
            if value(4) != "auto" {
                inventory.set_role(
                    &[device.id],
                    Some(value(4).parse().map_err(anyhow::Error::msg)?),
                )?;
            }
            app.status_line = "Added candidate. Assign a profile and enroll with e.".into();
        }
        FormKind::Import => {
            let report = inventory.import_csv(std::fs::File::open(value(0))?)?;
            app.status_line = format!(
                "Import: {} added, {} duplicates, {} errors {:?}",
                report.added,
                report.skipped_duplicates,
                report.errors.len(),
                report.errors
            );
        }
        FormKind::Site => {
            let site = inventory.site(value(0))?;
            if !value(1).is_empty() {
                let repo = nm_store::repo::SiteRepo::new(&svc.db);
                let mut record = repo.get(site)?.expect("created site");
                record.max_distance_m = Some(value(1).parse()?);
                repo.update(&record)?;
            }
            inventory.set_site(&app.inventory.targets(), Some(site))?;
        }
        FormKind::InterfaceRole => {
            let snapshot = app
                .devices
                .snapshots
                .get(app.devices.snapshot)
                .ok_or_else(|| anyhow::anyhow!("no snapshot"))?;
            let id = snapshot
                .device_results
                .get(app.devices.cursor)
                .ok_or_else(|| anyhow::anyhow!("no device"))?
                .device_id;
            let repo = nm_store::repo::DeviceRepo::new(&svc.db);
            let mut device = repo
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!("no inventory record"))?;
            anyhow::ensure!(
                snapshot.device_results[app.devices.cursor]
                    .facts
                    .interfaces
                    .iter()
                    .any(|i| i.name.as_deref() == Some(value(0))),
                "interface not observed"
            );
            let role = match value(1) {
                "wan" => Some(nm_core::InterfaceRole::Wan),
                "lan" => Some(nm_core::InterfaceRole::Lan),
                "management" => Some(nm_core::InterfaceRole::Management),
                _ => None,
            };
            if let Some(role) = role {
                device.interface_roles.insert(value(0).into(), role);
            } else {
                device.interface_roles.remove(value(0));
            }
            repo.update(&device)?;
            nm_app::analyze::AnalyzeService::new(&svc.db, &svc.data_dir).run(snapshot.id)?;
            app.status_line = "Interface role saved; findings refreshed.".into();
        }
        FormKind::Filter => {
            app.inventory.filter = value(0).into();
            app.inventory.cursor = 0;
        }
        FormKind::ConfigSearch => {
            app.devices.search = value(0).into();
            app.devices.scroll = 0;
        }
        FormKind::Concurrency => {
            let global = value(0).parse::<usize>()?;
            let per_site = value(1).parse::<usize>()?;
            anyhow::ensure!(
                global > 0 && per_site > 0,
                "concurrency must be greater than zero"
            );
            app.scan.global = global;
            app.scan.per_site = per_site;
        }
        FormKind::Credential => {
            anyhow::ensure!(
                !value(0).is_empty() && !value(2).is_empty() && !value(3).is_empty(),
                "name, username, and secret are required"
            );
            let key = value(1) == "ssh-key";
            let material = if key {
                nm_app::SecretMaterial::SshKey {
                    key: nm_app::SecretVec::new(std::fs::read(value(3))?),
                    passphrase: None,
                }
            } else {
                nm_app::SecretMaterial::SshPassword(nm_app::SecretString::new(std::mem::take(
                    &mut *form.fields[3].value,
                )))
            };
            let profile = CredentialProfile {
                id: CredentialProfileId::new(),
                name: form.fields[0].value.to_string(),
                kind: if key {
                    CredentialKind::SshKey {
                        username: form.fields[2].value.to_string(),
                        has_passphrase: false,
                    }
                } else {
                    CredentialKind::SshPassword {
                        username: form.fields[2].value.to_string(),
                    }
                },
                storage: StorageMode::SessionOnly,
                scope_hint: String::new(),
                is_vendor_default: false,
            };
            return Ok(vec![Effect::AddCredential {
                profile,
                secret: material,
            }]);
        }
    }
    Ok(vec![])
}
pub fn view(app: &App, frame: &mut Frame<'_>) {
    let Some(modal) = &app.modal else {
        return;
    };
    let (title, text) = match modal {
        Modal::Form(f) => {
            let lines = f
                .fields
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    format!(
                        "{} {}: {}{}",
                        if i == f.cursor { ">" } else { " " },
                        v.label,
                        if v.secret {
                            if v.value.is_empty() {
                                String::new()
                            } else {
                                "********".into()
                            }
                        } else {
                            v.value.to_string()
                        },
                        if v.choices.is_empty() {
                            ""
                        } else {
                            "  [Left/Right]"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            (
                "Enter saves | Tab next | Esc cancels",
                format!(
                    "{lines}\n\n{}",
                    if matches!(f.kind, FormKind::Credential) {
                        "Session-only; persistent storage arrives in M5"
                    } else {
                        ""
                    }
                ),
            )
        }
        Modal::Picker(p) => (
            "Up/Down choose | Enter selects | Esc cancels",
            p.options
                .iter()
                .enumerate()
                .map(|(i, (name, _))| format!("{} {name}", if i == p.cursor { ">" } else { " " }))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Modal::ConfirmQuit => (
            "Confirm quit",
            "A job is active. Cancel it and quit?\n\ny Yes   n / Esc Stay".into(),
        ),
        Modal::Remove(ids) => (
            "Remove inventory",
            format!("Remove {} selected devices? [y/N]", ids.len()),
        ),
        Modal::Forget(_) => (
            "Forget credential",
            "Forget this credential and unassign its devices? [y/N]".into(),
        ),
        Modal::ConfirmScan(devices) => (
            "Start read-only scan",
            format!(
                "Read-only; {} devices; commands shown in dry run.\nStart? [y/N]",
                devices.len()
            ),
        ),
        Modal::Legacy(id) => {
            let offered = app
                .scan
                .legacy_algorithms
                .get(id)
                .filter(|a| !a.is_empty())
                .map_or_else(|| "dh-group1-sha1, ssh-rsa".to_owned(), |a| a.join(", "));
            ("Legacy SSH opt-in",format!("This device only offers deprecated SSH algorithms:\n{offered}\nAllow for this device? [y/N]"))
        }
        Modal::EnrollDiscovery(ids) => (
            "Enroll discovered candidates",
            format!("Enroll {} checked candidates? [y/N]", ids.len()),
        ),
    };
    let area = frame.area();
    let width = area.width.min(72);
    let height = area
        .height
        .min(u16::try_from(text.lines().count() + 4).unwrap_or(20));
    let rect = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(text).block(widgets::block(app, title)), rect);
}
pub fn screen_key(app: &mut App, key: KeyEvent, svc: &AppService) -> Option<Vec<Effect>> {
    let result = (|| -> anyhow::Result<Option<Vec<Effect>>> {
        match app.screen {
            ScreenId::Inventory => {
                match key.code {
                    KeyCode::Down => {
                        app.inventory.cursor = (app.inventory.cursor + 1)
                            .min(app.inventory.visible().len().saturating_sub(1));
                    }
                    KeyCode::Up => app.inventory.cursor = app.inventory.cursor.saturating_sub(1),
                    KeyCode::Char(' ') => {
                        if let Some(id) = app
                            .inventory
                            .visible()
                            .get(app.inventory.cursor)
                            .map(|d| d.id)
                        {
                            if !app.inventory.selected.remove(&id) {
                                app.inventory.selected.insert(id);
                            }
                        }
                    }
                    KeyCode::Char('a') => {
                        let ids: Vec<_> = app.inventory.visible().iter().map(|d| d.id).collect();
                        app.inventory.selected.extend(ids);
                    }
                    KeyCode::Esc => {
                        app.inventory.selected.clear();
                        app.inventory.filter.clear();
                    }
                    KeyCode::Char('s') => {
                        app.inventory.sort = (app.inventory.sort + 1) % 8;
                        app.inventory.cursor = 0;
                    }
                    KeyCode::Char('n') => {
                        app.modal = Some(Modal::Form(Form::new(FormKind::Manual)));
                    }
                    KeyCode::Char('i') => {
                        app.modal = Some(Modal::Form(Form::new(FormKind::Import)));
                    }
                    KeyCode::Char('/') => {
                        app.modal = Some(Modal::Form(Form::new(FormKind::Filter)));
                    }
                    KeyCode::Char('p') => picker(app, PickerKind::Profile, svc),
                    KeyCode::Char('t') => picker(app, PickerKind::Site, svc),
                    KeyCode::Char('d') => picker(app, PickerKind::Interface, svc),
                    KeyCode::Char('e') => {
                        InventoryService::new(&svc.db).enroll(&app.inventory.targets())?;
                    }
                    KeyCode::Char('u') => {
                        InventoryService::new(&svc.db).unenroll(&app.inventory.targets())?;
                    }
                    KeyCode::Char('x') => app.modal = Some(Modal::Remove(app.inventory.targets())),
                    KeyCode::Enter if app.inventory.discovery_candidates => {
                        app.modal = Some(Modal::EnrollDiscovery(
                            app.inventory.selected.iter().copied().collect(),
                        ));
                    }
                    _ => return Ok(None),
                }
                app.refresh(svc)?;
            }
            ScreenId::Credentials => match key.code {
                KeyCode::Char('n') => {
                    app.modal = Some(Modal::Form(Form::new(FormKind::Credential)));
                }
                KeyCode::Down => {
                    app.credentials.cursor = (app.credentials.cursor + 1)
                        .min(app.credentials.profiles.len().saturating_sub(1));
                }
                KeyCode::Up => app.credentials.cursor = app.credentials.cursor.saturating_sub(1),
                KeyCode::Char('f') => {
                    if let Some(p) = app.credentials.profiles.get(app.credentials.cursor) {
                        app.modal = Some(Modal::Forget(p.id));
                    }
                }
                KeyCode::Enter => {
                    if let Some(p) = app.credentials.profiles.get(app.credentials.cursor) {
                        app.credentials.devices = Some(
                            app.inventory
                                .devices
                                .iter()
                                .filter(|d| d.credential_profile == Some(p.id))
                                .map(|d| format!("{} {}", d.display_name, d.management))
                                .collect(),
                        );
                    }
                }
                KeyCode::Esc if app.credentials.devices.is_some() => app.credentials.devices = None,
                _ => return Ok(None),
            },
            ScreenId::Scan => match key.code {
                KeyCode::Char('o') => picker(app, PickerKind::Scope, svc),
                KeyCode::Char('g') => {
                    app.modal = Some(Modal::Form(Form::new(FormKind::Concurrency)));
                }
                KeyCode::Char('r') => {
                    let devices = app.scan_devices();
                    app.scan.preview_devices.clone_from(&devices);
                    app.scan.states.clear();
                    app.scan.plan.clear();
                    let mut count = 0;
                    for d in &devices {
                        app.scan
                            .plan
                            .push(format!("{} {}", d.display_name, d.management));
                        if let Some(collector) = svc.collectors.get(d.family) {
                            for action in collector.plan(d).0 {
                                app.scan.plan.push(format!(
                                    "  {}",
                                    nm_collect::CollectionPlan(vec![action])
                                        .to_string()
                                        .trim_end()
                                ));
                                count += 1;
                            }
                        }
                    }
                    app.scan.plan.insert(
                        0,
                        format!(
                            "{count} SSH commands x {} devices, 0 HTTP, 0 UDP",
                            devices.len()
                        ),
                    );
                    app.scan.scroll = 0;
                    return Ok(Some(vec![Effect::StartScan {
                        devices,
                        dry_run: true,
                    }]));
                }
                KeyCode::Char('s') => {
                    anyhow::ensure!(!svc.jobs.is_active(), "a job is already running");
                    let devices = app.scan_devices();
                    anyhow::ensure!(!devices.is_empty(), "no enrolled devices in scope");
                    if devices != app.scan.preview_devices {
                        app.status_line = "Review the dry run; press s again to start.".into();
                        return Ok(screen_key(
                            app,
                            KeyEvent::new(KeyCode::Char('r'), crossterm::event::KeyModifiers::NONE),
                            svc,
                        ));
                    }
                    app.modal = Some(Modal::ConfirmScan(devices));
                }
                KeyCode::Char('c') => svc.jobs.cancel_active(),
                KeyCode::Down => app.scan.scroll = app.scan.scroll.saturating_add(1),
                KeyCode::Up => app.scan.scroll = app.scan.scroll.saturating_sub(1),
                KeyCode::Enter => {
                    if let Some(id) = app.scan.snapshot {
                        app.refresh(svc)?;
                        app.devices.snapshot = app
                            .devices
                            .snapshots
                            .iter()
                            .position(|s| s.id == id)
                            .unwrap_or(0);
                        app.screen = ScreenId::Devices;
                    } else {
                        app.scan.expanded = !app.scan.expanded;
                    }
                }
                _ => return Ok(None),
            },
            ScreenId::Devices => {
                let count = app
                    .devices
                    .snapshots
                    .get(app.devices.snapshot)
                    .map_or(0, |s| s.device_results.len());
                match key.code {
                    KeyCode::Down => {
                        app.devices.cursor = (app.devices.cursor + 1).min(count.saturating_sub(1));
                        app.devices.scroll = 0;
                    }
                    KeyCode::Up => {
                        app.devices.cursor = app.devices.cursor.saturating_sub(1);
                        app.devices.scroll = 0;
                    }
                    KeyCode::Tab => {
                        app.devices.tab = (app.devices.tab + 1) % 6;
                        app.devices.scroll = 0;
                    }
                    KeyCode::BackTab => {
                        app.devices.tab = (app.devices.tab + 5) % 6;
                        app.devices.scroll = 0;
                    }
                    KeyCode::PageDown => app.devices.scroll = app.devices.scroll.saturating_add(10),
                    KeyCode::PageUp => app.devices.scroll = app.devices.scroll.saturating_sub(10),
                    KeyCode::Char('[') => {
                        app.devices.snapshot = app.devices.snapshot.saturating_sub(1);
                        app.devices.cursor = 0;
                    }
                    KeyCode::Char(']') => {
                        app.devices.snapshot = (app.devices.snapshot + 1)
                            .min(app.devices.snapshots.len().saturating_sub(1));
                        app.devices.cursor = 0;
                    }
                    KeyCode::Char('R') if app.devices.tab == 1 => {
                        app.modal = Some(Modal::Form(Form::new(FormKind::InterfaceRole)));
                    }
                    KeyCode::Char('/') if app.devices.tab == 3 => {
                        app.modal = Some(Modal::Form(Form::new(FormKind::ConfigSearch)));
                    }
                    KeyCode::Enter if app.devices.tab == 4 => {
                        app.devices.raw_open = !app.devices.raw_open;
                    }
                    KeyCode::Left if app.devices.tab == 4 => {
                        app.devices.raw = app.devices.raw.saturating_sub(1);
                        app.devices.scroll = 0;
                    }
                    KeyCode::Right if app.devices.tab == 4 => {
                        let artifacts = app
                            .devices
                            .snapshots
                            .get(app.devices.snapshot)
                            .and_then(|s| s.device_results.get(app.devices.cursor))
                            .map_or(0, |r| r.raw.len());
                        app.devices.raw = app
                            .devices
                            .raw
                            .saturating_add(1)
                            .min(artifacts.saturating_sub(1));
                        app.devices.scroll = 0;
                    }
                    _ => return Ok(None),
                }
            }
            _ => return Ok(None),
        }
        Ok(Some(vec![]))
    })();
    match result {
        Ok(result) => result,
        Err(e) => {
            app.status_line = e.to_string();
            Some(vec![])
        }
    }
}
