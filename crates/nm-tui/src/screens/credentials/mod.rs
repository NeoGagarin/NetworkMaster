use crate::{widgets, App};
use nm_core::{CredentialKind, CredentialProfile, CredentialProfileId};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Paragraph, Row, Table, TableState},
    Frame,
};
#[derive(Default)]
pub struct CredentialsState {
    pub profiles: Vec<CredentialProfile>,
    pub cursor: usize,
    pub devices: Option<Vec<String>>,
    pub available: Vec<CredentialProfileId>,
}
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    if let Some(devices) = &app.credentials.devices {
        frame.render_widget(
            Paragraph::new(devices.join("\n"))
                .block(widgets::block(app, "Devices using profile | Esc closes")),
            area,
        );
        return;
    }
    let rows = app
        .credentials
        .profiles
        .iter()
        .map(|p| {
            Row::new(vec![
                p.name.clone(),
                match p.kind {
                    CredentialKind::SshPassword { .. } => "SSH password",
                    CredentialKind::SshKey { .. } => "SSH key",
                    _ => "other",
                }
                .into(),
                format!("{:?}", p.storage),
                app.inventory
                    .devices
                    .iter()
                    .filter(|d| d.credential_profile == Some(p.id))
                    .count()
                    .to_string(),
                if app.credentials.available.contains(&p.id) {
                    "loaded"
                } else {
                    "needs re-entry"
                }
                .into(),
            ])
        })
        .collect::<Vec<_>>();
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Fill(2),
                Constraint::Fill(1),
                Constraint::Fill(1),
                Constraint::Length(7),
                Constraint::Fill(1),
            ],
        )
        .header(Row::new([
            "Profile", "Kind", "Storage", "Devices", "Session",
        ]))
        .block(widgets::block(
            app,
            "Credentials | session-only; persistent storage arrives in M5",
        ))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut TableState::default().with_selected(Some(app.credentials.cursor)),
    );
}
