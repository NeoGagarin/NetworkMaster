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
#[derive(Clone, Debug)]
pub enum Modal {
    ConfirmQuit,
}
pub struct App {
    pub screen: ScreenId,
    pub dashboard: DashboardState,
    pub settings: SettingsState,
    pub help: HelpState,
    pub status_line: String,
    pub modal: Option<Modal>,
    pub theme: Theme,
    pub ascii: bool,
    pub force_no_color: bool,
    pub interrupted: bool,
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
            dashboard,
            settings: SettingsState {
                data_dir: svc.data_dir.display().to_string(),
                theme: svc.settings.theme,
            },
            help: HelpState,
            status_line: "Ready. No network actions in M0.".into(),
            modal: None,
            theme: Theme::default_dark(),
            ascii: svc.settings.ascii || crate::event::needs_ascii(),
            force_no_color,
            interrupted: false,
        };
        app.apply_theme();
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
                match key.code {
                    KeyCode::Char('y') => {
                        svc.jobs.cancel_active();
                        return vec![Effect::Quit];
                    }
                    KeyCode::Char('n') | KeyCode::Esc => app.modal = None,
                    _ => {}
                }
            } else {
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
            app.status_line = match event {
                JobEvent::Progress { done, total } => format!("Progress: {done}/{total}"),
                JobEvent::Log(text) => text,
                JobEvent::Cancelled => "Job cancelled.".into(),
                JobEvent::Failed(error) => format!("Job failed: {error}"),
                other => format!("{other:?}"),
            }
        }
        Action::Tick => {}
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
        screen => frame.render_widget(Paragraph::new(format!("{} is not implemented in M0.\nUse the CLI for inventory and session credential commands.\nPress 1 for Dashboard or ? for Help.",screen.label())).block(widgets::block(app,screen.label())),areas[1]),
    }
    widgets::StatusLine::render(app, frame, areas[2]);
    widgets::KeyHints::render(app, frame, areas[3]);
    if app.modal.is_some() {
        widgets::ConfirmModal::render(app, frame);
    }
}
