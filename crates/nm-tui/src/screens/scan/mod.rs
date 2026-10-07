use crate::{widgets, App};
use nm_core::{DeviceId, SnapshotId};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    widgets::{Paragraph, Row, Table},
    Frame,
};
use std::{collections::BTreeMap, time::Instant};
pub struct ScanState {
    pub scope: String,
    pub global: usize,
    pub per_site: usize,
    pub plan: Vec<String>,
    pub scroll: u16,
    pub states: BTreeMap<DeviceId, String>,
    pub started: Option<Instant>,
    pub device_started: BTreeMap<DeviceId, Instant>,
    pub device_elapsed: BTreeMap<DeviceId, u64>,
    pub done: usize,
    pub total: usize,
    pub snapshot: Option<SnapshotId>,
    pub legacy_queue: Vec<DeviceId>,
    pub expanded: bool,
    pub preview_devices: Vec<nm_core::Device>,
}
impl Default for ScanState {
    fn default() -> Self {
        Self {
            scope: "all enrolled".into(),
            global: 8,
            per_site: 2,
            plan: vec![],
            scroll: 0,
            states: BTreeMap::new(),
            started: None,
            device_started: BTreeMap::new(),
            device_elapsed: BTreeMap::new(),
            done: 0,
            total: 0,
            snapshot: None,
            legacy_queue: vec![],
            expanded: true,
            preview_devices: vec![],
        }
    }
}
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let s = &app.scan;
    let split = Layout::vertical([Constraint::Length(4), Constraint::Min(0)]).split(area);
    let elapsed = s.started.map_or(0, |t| t.elapsed().as_secs());
    let eta = if s.done > 0 {
        format!(
            "{}s",
            elapsed * u64::try_from(s.total.saturating_sub(s.done)).unwrap_or(0)
                / u64::try_from(s.done).unwrap_or(1)
        )
    } else {
        "—".into()
    };
    frame.render_widget(Paragraph::new(format!("Scope: {} | global {} / per site {}\nLegacy SSH requires explicit per-device opt-in.\n{}/{} done | elapsed {elapsed}s | ETA {eta}",s.scope,s.global,s.per_site,s.done,s.total)).block(widgets::block(app,"Scan | o scope | g concurrency | r dry run | s start | c cancel")),split[0]);
    if s.states.is_empty() {
        let lines = if s.expanded {
            s.plan.join("\n")
        } else {
            s.plan
                .iter()
                .filter(|l| !l.starts_with("  "))
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        };
        frame.render_widget(
            Paragraph::new(lines)
                .scroll((s.scroll, 0))
                .block(widgets::block(
                    app,
                    "Dry run | Enter expand/collapse | Up/Down scroll",
                )),
            split[1],
        );
    } else {
        let rows = s
            .states
            .iter()
            .map(|(id, state)| {
                Row::new(vec![
                    app.inventory
                        .devices
                        .iter()
                        .find(|d| d.id == *id)
                        .map_or_else(|| id.to_string(), |d| d.display_name.clone()),
                    state.clone(),
                    s.device_elapsed
                        .get(id)
                        .copied()
                        .or_else(|| s.device_started.get(id).map(|t| t.elapsed().as_secs()))
                        .map_or_else(|| "—".into(), |n| format!("{n}s")),
                ])
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Fill(2),
                    Constraint::Fill(4),
                    Constraint::Length(9),
                ],
            )
            .header(Row::new(["Device", "State", "Elapsed"]))
            .block(widgets::block(
                app,
                "Progress | Enter opens completed snapshot",
            )),
            split[1],
        );
    }
}
