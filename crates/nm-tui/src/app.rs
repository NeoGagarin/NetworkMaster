use crate::{
    action::{Action, Effect},
    screens::{dashboard::DashboardState, help::HelpState, settings::SettingsState},
    theme::Theme,
    widgets,
};
use crossterm::event::{KeyCode, KeyModifiers};
use nm_app::{AppService, JobEvent, ThemeChoice};
use nm_core::DeviceFamily;
use nm_store::repo::{DeviceFilter, DeviceRepo, SnapshotRepo};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::Paragraph,
    Frame,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenId {
    Dashboard,
    Inventory,
    Credentials,
    Scan,
    Findings,
    Devices,
    Topology,
    Ai,
    Audit,
    Settings,
    Help,
}
impl ScreenId {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Inventory => "Inventory",
            Self::Credentials => "Credentials",
            Self::Scan => "Scan",
            Self::Findings => "Findings",
            Self::Devices => "Devices",
            Self::Topology => "Topology",
            Self::Ai => "AI",
            Self::Audit => "Audit",
            Self::Settings => "Settings",
            Self::Help => "Help",
        }
    }
}
pub enum Modal {
    ConfirmQuit,
    Form(crate::screens::forms::Form),
    Picker(crate::screens::forms::Picker),
    Remove(Vec<nm_core::DeviceId>),
    Forget(nm_core::CredentialProfileId),
    ConfirmScan(Vec<nm_core::Device>),
    Legacy(nm_core::DeviceId),
    EnrollDiscovery(Vec<nm_core::DeviceId>),
}
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    pub screen: ScreenId,
    pub findings: crate::screens::findings::FindingsState,
    pub topology: crate::screens::topology::TopologyState,
    pub dashboard: DashboardState,
    pub settings: SettingsState,
    pub help: HelpState,
    pub status_line: String,
    pub modal: Option<Modal>,
    pub theme: Theme,
    pub ascii: bool,
    pub force_no_color: bool,
    pub interrupted: bool,
    pub quit_after_job: bool,
    pub inventory: crate::screens::inventory::InventoryState,
    pub credentials: crate::screens::credentials::CredentialsState,
    pub scan: crate::screens::scan::ScanState,
    pub devices: crate::screens::devices::DevicesState,
    pub discovery:
        Option<tokio::sync::oneshot::Receiver<std::result::Result<Vec<nm_core::Device>, String>>>,
}
impl App {
    pub fn new(svc: &AppService) -> anyhow::Result<Self> {
        let devices = DeviceRepo::new(&svc.db).list(&DeviceFilter::default())?;
        let families = [
            DeviceFamily::AirOs,
            DeviceFamily::EdgeOs,
            DeviceFamily::EdgeSwitch,
            DeviceFamily::UniFi,
            DeviceFamily::Uisp,
            DeviceFamily::Unknown,
        ]
        .into_iter()
        .map(|family| {
            let enrolled = devices
                .iter()
                .filter(|d| d.family == family && d.enrolled)
                .count();
            let candidates = devices
                .iter()
                .filter(|d| d.family == family && !d.enrolled)
                .count();
            (format!("{family:?}"), enrolled, candidates)
        })
        .collect();
        let mut dashboard = DashboardState {
            families,
            ..DashboardState::default()
        };
        if let Some(snapshot) = SnapshotRepo::new(&svc.db).list()?.first() {
            dashboard.last_snapshot = Some(
                snapshot
                    .finished_at
                    .unwrap_or(snapshot.started_at)
                    .to_string(),
            );
            for finding in &snapshot.findings {
                dashboard.findings[finding.severity as usize] += 1;
            }
        }
        let force_no_color = std::env::var_os("NO_COLOR").is_some();
        let mut app = Self {
            screen: ScreenId::Dashboard,
            findings: crate::screens::findings::FindingsState::default(),
            topology: crate::screens::topology::TopologyState::default(),
            dashboard,
            settings: SettingsState {
                data_dir: svc.data_dir.display().to_string(),
                theme: svc.settings.theme,
            },
            help: HelpState,
            status_line: "Ready. Network actions require enrollment.".into(),
            modal: None,
            theme: Theme::default_dark(),
            ascii: svc.settings.ascii || crate::event::needs_ascii(),
            force_no_color,
            interrupted: false,
            quit_after_job: false,
            inventory: crate::screens::inventory::InventoryState::default(),
            credentials: crate::screens::credentials::CredentialsState::default(),
            scan: crate::screens::scan::ScanState {
                global: svc.settings.max_concurrent_devices,
                per_site: svc.settings.max_concurrent_per_site,
                ..Default::default()
            },
            devices: crate::screens::devices::DevicesState::default(),
            discovery: None,
        };
        app.apply_theme();
        app.refresh(svc)?;
        Ok(app)
    }
    pub fn apply_theme(&mut self) {
        self.theme = if self.force_no_color {
            Theme::no_color()
        } else {
            match self.settings.theme {
                ThemeChoice::Dark => Theme::default_dark(),
                ThemeChoice::HighContrast => Theme::high_contrast(),
                ThemeChoice::NoColor => Theme::no_color(),
            }
        };
    }
    pub fn refresh(&mut self, svc: &AppService) -> anyhow::Result<()> {
        self.inventory.devices = DeviceRepo::new(&svc.db).list(&DeviceFilter::default())?;
        for (name, enrolled, candidates) in &mut self.dashboard.families {
            *enrolled = self
                .inventory
                .devices
                .iter()
                .filter(|d| format!("{:?}", d.family) == *name && d.enrolled)
                .count();
            *candidates = self
                .inventory
                .devices
                .iter()
                .filter(|d| format!("{:?}", d.family) == *name && !d.enrolled)
                .count();
        }
        self.inventory.sites = nm_store::repo::SiteRepo::new(&svc.db)
            .list()?
            .into_iter()
            .map(|s| (s.id, s.name))
            .collect();
        self.credentials.profiles = nm_store::repo::ProfileRepo::new(&svc.db).list()?;
        self.credentials.available = self
            .credentials
            .profiles
            .iter()
            .filter(|p| svc.creds.contains(p.id))
            .map(|p| p.id)
            .collect();
        self.inventory.profiles = self
            .credentials
            .profiles
            .iter()
            .map(|p| (p.id, p.name.clone()))
            .collect();
        self.inventory
            .selected
            .retain(|id| self.inventory.devices.iter().any(|d| d.id == *id));
        self.inventory.cursor = self
            .inventory
            .cursor
            .min(self.inventory.visible().len().saturating_sub(1));
        self.devices.snapshots = SnapshotRepo::new(&svc.db).list()?;
        self.dashboard.findings = [0; 5];
        if let Some(s) = self.devices.snapshots.first() {
            for f in &s.findings {
                self.dashboard.findings[f.severity as usize] += 1;
            }
        }
        self.dashboard.last_snapshot = self
            .devices
            .snapshots
            .first()
            .map(|s| s.finished_at.unwrap_or(s.started_at).to_string());
        Ok(())
    }
    pub fn scan_devices(&self) -> Vec<nm_core::Device> {
        self.inventory
            .devices
            .iter()
            .filter(|d| {
                d.enrolled
                    && match self.scan.scope.as_str() {
                        "selection" => self.inventory.selected.contains(&d.id),
                        s if s.starts_with("site:") => {
                            d.site.is_some_and(|id| format!("site:{id}") == s)
                        }
                        s if s.starts_with("family:") => format!("family:{:?}", d.family) == s,
                        _ => true,
                    }
            })
            .cloned()
            .collect()
    }
}
pub fn update(app: &mut App, action: Action, svc: &AppService) -> Vec<Effect> {
    let job_active = svc.jobs.is_active();
    match action {
        Action::Navigate(screen) => {
            app.screen = screen;
            app.modal = None;
        }
        Action::Quit => {
            if job_active {
                app.modal = Some(Modal::ConfirmQuit);
            } else {
                return vec![Effect::Quit];
            }
        }
        Action::Key(key) => {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if job_active && !app.interrupted {
                    svc.jobs.cancel_active();
                    app.interrupted = true;
                    app.status_line = "Cancelling job. Press Ctrl+C again to quit.".into();
                } else {
                    return vec![Effect::Interrupted];
                }
            } else if app.modal.is_some() {
                return crate::screens::forms::modal_key(app, key, svc);
            } else {
                if app.screen == ScreenId::Findings && crate::screens::findings::key(app, key, svc)
                {
                    return vec![];
                }
                if app.screen == ScreenId::Topology {
                    let rows = crate::screens::topology::rows(app);
                    match key.code {
                        KeyCode::Down => {
                            app.topology.cursor =
                                (app.topology.cursor + 1).min(rows.len().saturating_sub(1));
                            return vec![];
                        }
                        KeyCode::Up => {
                            app.topology.cursor = app.topology.cursor.saturating_sub(1);
                            return vec![];
                        }
                        KeyCode::Enter => {
                            if let Some(id) = rows.get(app.topology.cursor).and_then(|(_, id)| *id)
                            {
                                crate::screens::findings::jump(app, id);
                            }
                            return vec![];
                        }
                        _ => {}
                    }
                }
                if let Some(effects) = crate::screens::forms::screen_key(app, key, svc) {
                    return effects;
                }
                match key.code {
                    KeyCode::Char('q') => return update(app, Action::Quit, svc),
                    KeyCode::Esc => app.screen = ScreenId::Dashboard,
                    KeyCode::Char('?') => app.screen = ScreenId::Help,
                    KeyCode::Char(digit @ '0'..='9') => {
                        app.screen = match digit {
                            '0' => ScreenId::Settings,
                            '1' => ScreenId::Dashboard,
                            '2' => ScreenId::Inventory,
                            '3' => ScreenId::Credentials,
                            '4' => ScreenId::Scan,
                            '5' => ScreenId::Findings,
                            '6' => ScreenId::Devices,
                            '7' => ScreenId::Topology,
                            '8' => ScreenId::Ai,
                            _ => ScreenId::Audit,
                        }
                    }
                    KeyCode::Char(theme @ ('d' | 'h' | 'n'))
                        if app.screen == ScreenId::Settings =>
                    {
                        app.settings.theme = match theme {
                            'h' => ThemeChoice::HighContrast,
                            'n' => ThemeChoice::NoColor,
                            _ => ThemeChoice::Dark,
                        };
                        app.apply_theme();
                        return vec![Effect::SaveSettings];
                    }
                    _ => {}
                }
            }
        }
        Action::Job(event) => {
            match &event {
                JobEvent::Started { total } => app.scan.total = *total,
                JobEvent::DeviceStarted(id) => {
                    app.scan.states.insert(*id, "connecting".into());
                    app.scan
                        .device_started
                        .insert(*id, std::time::Instant::now());
                }
                JobEvent::DeviceState { device, state } => {
                    app.scan.states.insert(*device, state.clone());
                    if state.starts_with("legacy required:") {
                        app.scan.legacy_queue.push(*device);
                    }
                }
                JobEvent::DeviceFinished(id, outcome) => {
                    app.scan.states.insert(
                        *id,
                        match outcome {
                            nm_core::Outcome::Ok => "done",
                            nm_core::Outcome::Partial(_) => "partial",
                            nm_core::Outcome::Cancelled => "cancelled",
                            _ => "failed",
                        }
                        .into(),
                    );
                    if let Some(started) = app.scan.device_started.remove(id) {
                        app.scan
                            .device_elapsed
                            .insert(*id, started.elapsed().as_secs());
                    }
                }
                JobEvent::Progress { done, total } => {
                    app.scan.done = *done;
                    app.scan.total = *total;
                }
                JobEvent::Finished(nm_app::JobOutcome::Scan { snapshot_id, .. }) => {
                    app.scan.snapshot = Some(*snapshot_id);
                    let _ = app.refresh(svc);
                }
                _ => {}
            }
            let name = |id: nm_core::DeviceId| {
                app.inventory
                    .devices
                    .iter()
                    .find(|d| d.id == id)
                    .map_or_else(|| id.to_string(), |d| d.display_name.clone())
            };
            app.status_line = match event {
                JobEvent::Started { total } => format!("{total} devices queued."),
                JobEvent::DeviceStarted(id) => format!("{}: connecting", name(id)),
                JobEvent::DeviceState { device, state } => format!("{}: {state}", name(device)),
                JobEvent::DeviceFinished(id, _) => format!(
                    "{}: {}",
                    name(id),
                    app.scan.states.get(&id).map_or("finished", String::as_str)
                ),
                JobEvent::Progress { done, total } => format!("Progress: {done}/{total}"),
                JobEvent::Log(text) => text,
                JobEvent::Cancelled | JobEvent::Finished(nm_app::JobOutcome::Cancelled) => {
                    "Job cancelled.".into()
                }
                JobEvent::Failed(error) | JobEvent::Finished(nm_app::JobOutcome::Failed(error)) => {
                    format!("Job failed: {error}")
                }
                JobEvent::Finished(nm_app::JobOutcome::Scan {
                    ok,
                    partial,
                    failed,
                    ..
                }) => format!("Scan complete: {ok} OK / {partial} partial / {failed} failed."),
                JobEvent::Finished(nm_app::JobOutcome::Completed) => "Job complete.".into(),
            }
        }
        Action::Tick => {
            if let Some(receive) = &mut app.discovery {
                match receive.try_recv() {
                    Ok(result) => {
                        app.discovery = None;
                        app.inventory.discovering = false;
                        match result {
                            Ok(devices) => {
                                let inventory = nm_app::inventory::InventoryService::new(&svc.db);
                                app.inventory.selected.clear();
                                for d in &devices {
                                    let _ = inventory.add_candidate(d);
                                }
                                app.inventory.discovery_candidates = true;
                                app.status_line = if devices.is_empty() {
                                    "no replies — many operators disable UBNT discovery".into()
                                } else {
                                    "Discovery candidates: Space selects; Enter confirms enrollment.".into()
                                };
                                let _ = app.refresh(svc);
                            }
                            Err(e) => app.status_line = e,
                        }
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                        app.discovery = None;
                        app.inventory.discovering = false;
                        app.status_line = "Discovery task closed".into();
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                }
            }
            if app.modal.is_none() {
                if let Some(id) = app.scan.legacy_queue.pop() {
                    app.modal = Some(Modal::Legacy(id));
                }
            }
        }
    }
    if app.quit_after_job && !svc.jobs.is_active() {
        return vec![Effect::Quit];
    }
    vec![]
}
pub fn view(app: &App, frame: &mut Frame<'_>) {
    frame.render_widget(
        ratatui::widgets::Block::default()
            .style(Style::default().fg(app.theme.fg).bg(app.theme.bg)),
        frame.area(),
    );
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(frame.area());
    widgets::TitleBar::render(app, frame, areas[0]);
    match app.screen {
        ScreenId::Dashboard => crate::screens::dashboard::view(app,frame,areas[1]),
        ScreenId::Settings => crate::screens::settings::view(app,frame,areas[1]),
        ScreenId::Help => crate::screens::help::view(app,frame,areas[1]),
        ScreenId::Inventory => crate::screens::inventory::view(app,frame,areas[1]),
        ScreenId::Credentials => crate::screens::credentials::view(app,frame,areas[1]),
        ScreenId::Scan => crate::screens::scan::view(app,frame,areas[1]),
        ScreenId::Devices => crate::screens::devices::view(app,frame,areas[1]),
        ScreenId::Findings => crate::screens::findings::view(app,frame,areas[1]),
        ScreenId::Topology => crate::screens::topology::view(app,frame,areas[1]),
        screen => frame.render_widget(Paragraph::new(format!("{} is planned for a later milestone.\nUse the CLI for inventory and session credential commands.\nPress 1 for Dashboard or ? for Help.",screen.label())).block(widgets::block(app,screen.label())),areas[1]),
    }
    widgets::StatusLine::render(app, frame, areas[2]);
    widgets::KeyHints::render(app, frame, areas[3]);
    if app.modal.is_some() {
        crate::screens::forms::view(app, frame);
    }
}
