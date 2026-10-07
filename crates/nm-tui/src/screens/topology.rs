//! Per-site ASCII tree with observed wireless links and routing adjacencies.
use crate::{widgets, App};
use nm_analyze::{
    topology::{Edge, StationNode},
    SnapshotView,
};
use nm_core::{DeviceFamily, DeviceId, DeviceRole, RadioMode, Site};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    widgets::{List, ListItem, ListState},
    Frame,
};
/// Selection index in the derived topology rows.
#[derive(Default)]
pub struct TopologyState {
    pub cursor: usize,
}
/// Derive tree rows and optional device navigation targets.
pub fn rows(app: &App) -> Vec<(String, Option<DeviceId>)> {
    let Some(snapshot) = app.devices.snapshots.get(app.devices.snapshot) else {
        return vec![("No snapshots. Run a scan first.".into(), None)];
    };
    let sites: Vec<_> = app
        .inventory
        .sites
        .iter()
        .map(|(id, name)| Site {
            id: *id,
            name: name.clone(),
            notes: String::new(),
            max_distance_m: None,
        })
        .collect();
    let view = SnapshotView::new(snapshot, &app.inventory.devices, &sites, &[]);
    let graph = nm_analyze::topology::infer(&view);
    let name = |id: DeviceId| {
        app.inventory
            .devices
            .iter()
            .find(|d| d.id == id)
            .map_or_else(|| id.to_string(), |d| d.display_name.clone())
    };
    let mut out = vec![];
    for (site, label) in sites
        .iter()
        .map(|s| (Some(s.id), s.name.clone()))
        .chain(std::iter::once((None, "Unassigned".into())))
    {
        let devices: Vec<_> = view.devices().filter(|(d, _)| d.site == site).collect();
        if devices.is_empty() {
            continue;
        }
        out.push((label, None));
        for (d, r) in &devices {
            if let Some(radio) = r
                .facts
                .radio
                .as_ref()
                .filter(|r| matches!(r.mode, Some(RadioMode::Ap | RadioMode::PtpMaster)))
            {
                out.push((
                    format!(
                        "  +-- {} ({} MHz / {} MHz, {} stations)",
                        d.display_name,
                        radio
                            .frequency_mhz
                            .map_or_else(|| "unknown".into(), |v| v.to_string()),
                        radio
                            .channel_width_mhz
                            .map_or_else(|| "unknown".into(), |v| v.to_string()),
                        radio.stations.len()
                    ),
                    Some(d.id),
                ));
                for edge in &graph.edges {
                    if let Edge::Wireless {
                        ap,
                        station,
                        signal,
                        chains,
                        ..
                    } = edge
                    {
                        if *ap != d.id {
                            continue;
                        }
                        let (label, id) = match station {
                            StationNode::Device(id) => (name(*id), Some(*id)),
                            StationNode::Unknown(mac) => (format!("Unknown station {mac}"), None),
                        };
                        let chain: Vec<_> = chains.iter().filter_map(|c| c.rssi_dbm).collect();
                        let imbalance = chain.len() > 1
                            && i32::from(*chain.iter().max().unwrap())
                                - i32::from(*chain.iter().min().unwrap())
                                > 6;
                        out.push((
                            format!(
                                "  |   +-- {label} (signal {} dBm, chains {})",
                                signal.map_or_else(|| "unknown".into(), |v| v.to_string()),
                                if imbalance {
                                    "!"
                                } else if chain.len() > 1 {
                                    "ok"
                                } else {
                                    "unknown"
                                }
                            ),
                            id,
                        ));
                    }
                }
            }
        }
        out.push(("  Routers and OSPF adjacencies".into(), None));
        for (d, _) in devices
            .iter()
            .filter(|(d, _)| d.family == DeviceFamily::EdgeOs || d.role == Some(DeviceRole::Router))
        {
            out.push((format!("  +-- {}", d.display_name), Some(d.id)));
            for edge in &graph.edges {
                if let Edge::Ospf { a, b, state, .. } = edge {
                    if *a == d.id {
                        out.push((format!("  |   +-- {} ({state:?})", name(*b)), Some(*b)));
                    }
                }
            }
        }
    }
    out
}
/// Render the derived tree with row selection.
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let rows = rows(app);
    frame.render_stateful_widget(
        List::new(
            rows.into_iter()
                .map(|(text, _)| ListItem::new(text))
                .collect::<Vec<_>>(),
        )
        .block(widgets::block(
            app,
            "Topology | Up/Down select | Enter device",
        ))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut ListState::default().with_selected(Some(app.topology.cursor)),
    );
}
