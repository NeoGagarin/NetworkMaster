use crate::{widgets, App};
use nm_core::{CredentialProfileId, Device, DeviceId, SiteId};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Row, Table, TableState},
    Frame,
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Default)]
pub struct InventoryState {
    pub devices: Vec<Device>,
    pub sites: BTreeMap<SiteId, String>,
    pub profiles: BTreeMap<CredentialProfileId, String>,
    pub selected: BTreeSet<DeviceId>,
    pub cursor: usize,
    pub filter: String,
    pub sort: usize,
    pub discovery_candidates: bool,
    pub discovering: bool,
}
impl InventoryState {
    pub fn visible(&self) -> Vec<&Device> {
        let mut devices: Vec<_> = self
            .devices
            .iter()
            .filter(|d| {
                format!(
                    "{} {} {}",
                    d.display_name,
                    d.management,
                    d.site
                        .and_then(|id| self.sites.get(&id))
                        .map_or("", String::as_str)
                )
                .to_lowercase()
                .contains(&self.filter.to_lowercase())
            })
            .collect();
        devices.sort_by_key(|d| match self.sort {
            0 => format!("{}", d.enrolled),
            1 => d.display_name.clone(),
            2 => d.management.to_string(),
            3 => format!("{:?}", d.family),
            4 => format!("{:?}", d.role),
            5 => d
                .site
                .and_then(|s| self.sites.get(&s))
                .cloned()
                .unwrap_or_default(),
            6 => d
                .credential_profile
                .and_then(|p| self.profiles.get(&p))
                .cloned()
                .unwrap_or_default(),
            _ => format!("{:?}", d.source),
        });
        devices
    }
    pub fn targets(&self) -> Vec<DeviceId> {
        if self.selected.is_empty() {
            self.visible()
                .get(self.cursor)
                .map(|d| vec![d.id])
                .unwrap_or_default()
        } else {
            self.selected.iter().copied().collect()
        }
    }
}
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let state = &app.inventory;
    let rows = state
        .visible()
        .iter()
        .map(|d| {
            Row::new(vec![
                format!(
                    "{}{}",
                    if state.selected.contains(&d.id) {
                        "*"
                    } else {
                        " "
                    },
                    if d.enrolled {
                        if app.ascii {
                            "Y"
                        } else {
                            "✓"
                        }
                    } else {
                        " "
                    }
                ),
                d.display_name.clone(),
                d.management.to_string(),
                format!("{:?}", d.family),
                d.role.map_or("—".into(), |r| format!("{r:?}")),
                d.site
                    .and_then(|id| state.sites.get(&id))
                    .cloned()
                    .unwrap_or_else(|| "—".into()),
                d.credential_profile
                    .and_then(|id| state.profiles.get(&id))
                    .cloned()
                    .unwrap_or_else(|| "—".into()),
                format!("{:?}", d.source),
            ])
            .style(if d.enrolled {
                Style::default()
            } else {
                Style::default()
                    .fg(app.theme.muted)
                    .add_modifier(Modifier::DIM)
            })
        })
        .collect::<Vec<_>>();
    let enrolled = state.devices.iter().filter(|d| d.enrolled).count();
    let title = format!(
        "Inventory | {enrolled} enrolled / {} candidates | sort {} | / {}{}",
        state.devices.len() - enrolled,
        state.sort,
        state.filter,
        if state.discovering {
            " | discovering..."
        } else {
            ""
        }
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(9),
        ],
    )
    .header(Row::new([
        "✓", "Name", "Address", "Family", "Role", "Site", "Profile", "Source",
    ]))
    .block(widgets::block(app, &title))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(
        table,
        area,
        &mut TableState::default().with_selected(Some(state.cursor)),
    );
}
