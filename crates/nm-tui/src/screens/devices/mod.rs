use crate::{widgets, App};
use nm_core::{DeviceFacts, Duplex, InterfaceFacts, Outcome, RadioFacts, RadioMode, Snapshot};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    widgets::{List, ListItem, ListState, Paragraph, Tabs},
    Frame,
};
#[derive(Default)]
pub struct DevicesState {
    pub snapshots: Vec<Snapshot>,
    pub snapshot: usize,
    pub cursor: usize,
    pub tab: usize,
    pub scroll: u16,
    pub raw: usize,
    pub raw_open: bool,
    pub search: String,
}
pub const TABS: [&str; 6] = ["System", "Interfaces", "Radio", "Config", "Raw", "Coverage"];
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let s = &app.devices;
    let Some(snapshot) = s.snapshots.get(s.snapshot) else {
        frame.render_widget(
            Paragraph::new("No snapshots. Enroll devices and run a scan.")
                .block(widgets::block(app, "Devices")),
            area,
        );
        return;
    };
    let split =
        Layout::horizontal([Constraint::Percentage(28), Constraint::Percentage(72)]).split(area);
    let items = snapshot
        .device_results
        .iter()
        .map(|r| {
            let name = app
                .inventory
                .devices
                .iter()
                .find(|d| d.id == r.device_id)
                .map_or_else(|| r.device_id.to_string(), |d| d.display_name.clone());
            let pct = if r.coverage.expected.is_empty() {
                0
            } else {
                r.coverage.collected.len() * 100 / r.coverage.expected.len()
            };
            ListItem::new(format!(
                "{} {name} {pct}%",
                match r.outcome {
                    Outcome::Ok => "+",
                    Outcome::Partial(_) => "~",
                    Outcome::Cancelled => "c",
                    _ => "!",
                }
            ))
        })
        .collect::<Vec<_>>();
    let title = format!("Snapshot {}/{} | [ ]", s.snapshot + 1, s.snapshots.len());
    frame.render_stateful_widget(
        List::new(items)
            .block(widgets::block(app, &title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        split[0],
        &mut ListState::default().with_selected(Some(s.cursor)),
    );
    let right = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(split[1]);
    frame.render_widget(
        Tabs::new(TABS)
            .select(s.tab)
            .block(widgets::block(app, "Tab / Shift+Tab detail")),
        right[0],
    );
    let Some(r) = snapshot.device_results.get(s.cursor) else {
        return;
    };
    let f = &r.facts;
    let mut interfaces = f.interfaces.clone();
    if let Some(d) = app.inventory.devices.iter().find(|d| d.id == r.device_id) {
        for i in &mut interfaces {
            if let Some(role) = i.name.as_ref().and_then(|n| d.interface_roles.get(n)) {
                i.role = Some(*role);
                i.role_confidence = Some(nm_core::Confidence::Certain);
            }
        }
    }
    let detail=match s.tab {
        0=>system_detail(f),
        1=>interface_detail(&interfaces),
        2=>radio_detail(f.radio.as_ref()),
        3=>f.config.as_ref().map_or_else(||"Config unavailable".into(),|c|if s.search.is_empty(){c.text.clone()}else{c.text.lines().filter(|l|l.to_lowercase().contains(&s.search.to_lowercase())).collect::<Vec<_>>().join("\n")}),
        4=>if s.raw_open{r.raw.get(s.raw).map_or_else(||"No artifact".into(),|a|String::from_utf8_lossy(&a.bytes).into_owned())}else{r.raw.iter().enumerate().map(|(i,a)|format!("{} {} ({} bytes)",if i==s.raw{">"}else{" "},a.name,a.bytes.len())).collect::<Vec<_>>().join("\n")},
        _=>format!("Skipped by configuration:\n{}\n\nOutcome {}\n\nExpected:\n{}\n\nCollected:\n{}\n\nMissing:\n{}\n\nSources:\n{}\n\nErrors:\n{}",r.coverage.skipped.iter().map(|(a,b)|format!("{a}: {b}")).collect::<Vec<_>>().join("\n"),match r.outcome{Outcome::Ok=>"OK",Outcome::Partial(_)=>"partial",Outcome::Cancelled=>"cancelled",Outcome::AuthFailed=>"authentication failed",Outcome::Unreachable=>"unreachable",Outcome::ParseError=>"parse error"},r.coverage.expected.join("\n"),r.coverage.collected.join("\n"),r.coverage.missing.join("\n"),r.coverage.sources.iter().map(|(k,v)|format!("{k}: {v}")).collect::<Vec<_>>().join("\n"),r.coverage.errors.iter().map(|(k,v)|format!("{k}: {v}")).collect::<Vec<_>>().join("\n")),
    };
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .scroll((s.scroll, 0))
            .block(widgets::block(app, TABS[s.tab])),
        right[1],
    );
}
fn flag(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn display<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "--".into(), |v| v.to_string())
}
fn system_detail(f: &DeviceFacts) -> String {
    let s = &f.system;
    let load = s.loadavg.as_ref().map_or_else(
        || "--".into(),
        |l| {
            format!(
                "{} / {} / {}",
                display(l.one_min),
                display(l.five_min),
                display(l.fifteen_min)
            )
        },
    );
    let memory = s.memory.as_ref().map_or_else(
        || "--".into(),
        |m| {
            format!(
                "{} MiB total / {} MiB free",
                display(m.total_bytes.map(|n| n / 1_048_576)),
                display(m.free_bytes.map(|n| n / 1_048_576))
            )
        },
    );
    let mut lines = vec![
        format!("Model: {}", s.model.as_deref().unwrap_or("--")),
        format!("Firmware: {}", s.firmware.as_deref().unwrap_or("--")),
        format!("Hostname: {}", s.hostname.as_deref().unwrap_or("--")),
        format!("Uptime: {} seconds", display(s.uptime_seconds)),
        format!("Load: {load}"),
        format!("Memory: {memory}"),
        format!("Legacy SSH: {}", flag(s.ssh_legacy_algorithms)),
        format!("Host key changed: {}", flag(s.ssh_host_key_changed)),
        String::new(),
        "Service       State     Port".into(),
    ];
    for (name, svc) in [
        ("SSH", &f.services.ssh),
        ("Telnet", &f.services.telnet),
        ("HTTP", &f.services.http),
        ("HTTPS", &f.services.https),
        ("UPnP", &f.services.upnp),
        ("Discovery", &f.services.discovery),
        ("NTP", &f.services.ntp),
    ] {
        lines.push(format!(
            "{name:13} {:9} {}",
            flag(svc.enabled),
            display(svc.port)
        ));
    }
    lines.push(format!("SNMP          {}", flag(f.services.snmp.enabled)));
    lines.join("\n")
}
fn interface_detail(interfaces: &[InterfaceFacts]) -> String {
    interfaces
        .iter()
        .map(|i| {
            let mut lines = vec![
                format!(
                    "{}  {}",
                    i.name.as_deref().unwrap_or("--"),
                    i.mac.as_deref().unwrap_or("--")
                ),
                format!("Admin {} / link {}", flag(i.admin_up), flag(i.oper_up)),
                format!(
                    "Speed {} Mbps / {} duplex",
                    display(i.speed_mbps),
                    match i.duplex {
                        Some(Duplex::Full) => "full",
                        Some(Duplex::Half) => "half",
                        None => "unknown",
                    }
                ),
                format!("Addresses: {}", i.addresses.join(", ")),
                format!(
                    "Role {:?} / {:?} (R edits override)",
                    i.role, i.role_confidence
                ),
            ];
            if let Some(c) = &i.counters {
                lines.push(format!(
                    "RX {} bytes / {} packets",
                    display(c.rx_bytes),
                    display(c.rx_packets)
                ));
                lines.push(format!(
                    "TX {} bytes / {} packets",
                    display(c.tx_bytes),
                    display(c.tx_packets)
                ));
                lines.push(format!(
                    "Errors RX {} / TX {}",
                    display(c.rx_errors),
                    display(c.tx_errors)
                ));
                lines.push(format!(
                    "Dropped RX {} / TX {}",
                    display(c.rx_dropped),
                    display(c.tx_dropped)
                ));
            }
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}
fn radio_detail(r: Option<&RadioFacts>) -> String {
    let Some(r) = r else {
        return "Radio unavailable".into();
    };
    let mode = match r.mode {
        Some(RadioMode::Ap) => "AP",
        Some(RadioMode::Station) => "station",
        Some(RadioMode::PtpMaster) => "PTP master",
        Some(RadioMode::PtpSlave) => "PTP slave",
        None => "unknown",
    };
    let mut lines = vec![
        format!("Mode: {mode}"),
        format!("SSID: {}", r.ssid.as_deref().unwrap_or("--")),
        format!(
            "Frequency {} MHz / width {} MHz",
            display(r.frequency_mhz),
            display(r.channel_width_mhz)
        ),
        format!("TX power {} dBm", display(r.tx_power_dbm)),
        format!(
            "Signal {} dBm / noise {} dBm",
            display(r.signal_dbm),
            display(r.noise_floor_dbm)
        ),
        format!(
            "CCQ {}% / TX {} / RX {} Mbps",
            display(r.ccq_pct),
            display(r.tx_rate_mbps),
            display(r.rx_rate_mbps)
        ),
        format!("Distance {} m", display(r.distance_m)),
    ];
    if let Some(a) = &r.airmax {
        lines.push(format!(
            "airMAX quality {}% / capacity {}%",
            display(a.quality_pct),
            display(a.capacity_pct)
        ));
    }
    if let Some(a) = &r.airtime_pct {
        lines.push(format!(
            "Airtime TX {}% / RX {}% / busy {}%",
            display(a.tx),
            display(a.rx),
            display(a.busy)
        ));
    }
    for chain in &r.chains {
        let n = usize::try_from((i32::from(chain.rssi_dbm.unwrap_or(-100)) + 100).clamp(0, 60) / 3)
            .unwrap_or(0);
        lines.push(format!(
            "Chain {} {:20} {} dBm",
            display(chain.chain),
            "#".repeat(n),
            display(chain.rssi_dbm)
        ));
    }
    if !r.stations.is_empty() {
        lines.push("\nStations: MAC / name / signal / CCQ / rates".into());
        for s in &r.stations {
            lines.push(format!(
                "{} {}",
                s.mac.as_deref().unwrap_or("--"),
                s.hostname.as_deref().unwrap_or("--")
            ));
            lines.push(format!(
                "  {} dBm / CCQ {}% / TX {} / RX {} Mbps",
                display(s.signal_dbm),
                display(s.ccq_pct),
                display(s.tx_rate_mbps),
                display(s.rx_rate_mbps)
            ));
        }
    }
    lines.join("\n")
}
