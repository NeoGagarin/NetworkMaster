//! Findings table, local filters, evidence detail, navigation and shared report export.
use crate::{widgets, App, ScreenId};
use crossterm::event::{KeyCode, KeyEvent};
use nm_app::AppService;
use nm_core::{Category, Confidence, DeviceId, Finding, Severity, Snapshot};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
/// Filter and selection state for findings from the selected snapshot.
#[derive(Default)]
pub struct FindingsState {
    pub cursor: usize,
    pub search: String,
    pub editing: bool,
    pub severity: Option<Severity>,
    pub category: Option<Category>,
    pub hide_heuristics: bool,
    pub scroll: u16,
    pub affected: usize,
}
impl FindingsState {
    /// Apply the current filters while preserving deterministic runner order.
    pub fn visible<'a>(&self, snapshot: &'a Snapshot) -> Vec<&'a Finding> {
        let query = self.search.to_ascii_lowercase();
        snapshot
            .findings
            .iter()
            .filter(|f| {
                self.severity.is_none_or(|s| f.severity >= s)
                    && self.category.is_none_or(|c| f.category == c)
                    && (!self.hide_heuristics || f.confidence != Confidence::Heuristic)
                    && (query.is_empty()
                        || format!(
                            "{} {} {} {:?}",
                            f.rule_id, f.title, f.explanation, f.category
                        )
                        .to_ascii_lowercase()
                        .contains(&query))
            })
            .collect()
    }
}
/// Render headings, simple bold spans and bullet lists in catalog explanations.
pub fn markdown(text: &str) -> Vec<Line<'static>> {
    text.lines()
        .map(|line| {
            let heading = line.starts_with('#');
            let line = line.trim_start_matches('#').trim();
            let mut spans = vec![];
            for (i, s) in line.split("**").enumerate() {
                let style = if heading || i % 2 == 1 {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                spans.push(Span::styled(s.to_owned(), style));
            }
            Line::from(spans)
        })
        .collect()
}
/// Findings keyboard actions; writes are local and analysis immediately refreshes.
pub fn key(app: &mut App, key: KeyEvent, svc: &AppService) -> bool {
    if app.findings.editing {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => app.findings.editing = false,
            KeyCode::Backspace => {
                app.findings.search.pop();
            }
            KeyCode::Char(c) => app.findings.search.push(c),
            _ => {}
        }
        app.findings.cursor = 0;
        return true;
    }
    let selected = app
        .devices
        .snapshots
        .get(app.devices.snapshot)
        .and_then(|s| app.findings.visible(s).get(app.findings.cursor).copied())
        .cloned();
    let count = app
        .devices
        .snapshots
        .get(app.devices.snapshot)
        .map_or(0, |s| app.findings.visible(s).len());
    match key.code {
        KeyCode::Char('/') => app.findings.editing = true,
        KeyCode::Char(c @ '1'..='5') => {
            app.findings.severity = Some(
                [
                    Severity::Info,
                    Severity::Low,
                    Severity::Medium,
                    Severity::High,
                    Severity::Critical,
                ][c as usize - '1' as usize],
            );
            app.findings.cursor = 0;
        }
        KeyCode::Char('c') => {
            app.findings.category = match app.findings.category {
                None => Some(Category::Security),
                Some(Category::Security) => Some(Category::Performance),
                Some(Category::Performance) => Some(Category::Reliability),
                Some(Category::Reliability) => Some(Category::Capacity),
                Some(Category::Capacity) => Some(Category::Hygiene),
                Some(Category::Hygiene) => Some(Category::RfHealth),
                Some(Category::RfHealth) => None,
            };
            app.findings.cursor = 0;
        }
        KeyCode::Char('h') => {
            app.findings.hide_heuristics = !app.findings.hide_heuristics;
            app.findings.cursor = 0;
        }
        KeyCode::Up => {
            app.findings.cursor = app.findings.cursor.saturating_sub(1);
            app.findings.scroll = 0;
            app.findings.affected = 0;
        }
        KeyCode::Down => {
            app.findings.cursor = (app.findings.cursor + 1).min(count.saturating_sub(1));
            app.findings.scroll = 0;
            app.findings.affected = 0;
        }
        KeyCode::PageDown => app.findings.scroll = app.findings.scroll.saturating_add(8),
        KeyCode::PageUp => app.findings.scroll = app.findings.scroll.saturating_sub(8),
        KeyCode::Right => {
            if let Some(f) = &selected {
                app.findings.affected = (app.findings.affected + 1) % f.devices.len().max(1);
            }
        }
        KeyCode::Left => app.findings.affected = app.findings.affected.saturating_sub(1),
        KeyCode::Enter => {
            if let Some(id) = selected
                .as_ref()
                .and_then(|f| f.devices.get(app.findings.affected))
            {
                jump(app, *id);
            }
        }
        KeyCode::Char('D') => {
            if let Some(f) = selected {
                let snapshot = app
                    .devices
                    .snapshots
                    .get(app.devices.snapshot)
                    .map(|s| s.id);
                let result = nm_app::analyze::AnalyzeService::new(&svc.db, &svc.data_dir)
                    .set_enabled(f.rule_id.clone(), false, snapshot);
                app.status_line = match result {
                    Ok(()) => {
                        let _ = app.refresh(svc);
                        format!("{} disabled; findings refreshed.", f.rule_id)
                    }
                    Err(e) => e.to_string(),
                };
                app.findings.cursor = 0;
            }
        }
        KeyCode::Char('E') => {
            if let Some(snapshot) = app.devices.snapshots.get(app.devices.snapshot) {
                let findings: Vec<_> = app
                    .findings
                    .visible(snapshot)
                    .into_iter()
                    .cloned()
                    .collect();
                let options = nm_app::report::ReportOptions {
                    devices: app.inventory.devices.clone(),
                    sites: nm_store::repo::SiteRepo::new(&svc.db)
                        .list()
                        .unwrap_or_default(),
                    ..Default::default()
                };
                let path = svc.data_dir.join(format!("report-{}.md", snapshot.id));
                app.status_line = match std::fs::write(
                    &path,
                    nm_app::report::render_report(snapshot, &findings, &options),
                ) {
                    Ok(()) => format!("Filtered report exported: {}", path.display()),
                    Err(e) => e.to_string(),
                };
            }
        }
        _ => return false,
    }
    true
}
/// Navigate to a scanned device in the currently selected snapshot.
pub fn jump(app: &mut App, id: DeviceId) {
    if let Some(index) = app
        .devices
        .snapshots
        .get(app.devices.snapshot)
        .and_then(|s| s.device_results.iter().position(|r| r.device_id == id))
    {
        app.devices.cursor = index;
        app.devices.scroll = 0;
        app.screen = ScreenId::Devices;
    }
}
/// Render the severity table and selected finding explanation and evidence.
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let Some(snapshot) = app.devices.snapshots.get(app.devices.snapshot) else {
        frame.render_widget(
            Paragraph::new("No snapshots. Run a scan to produce findings.")
                .block(widgets::block(app, "Findings")),
            area,
        );
        return;
    };
    let rows = app.findings.visible(snapshot);
    let split =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);
    let table_rows: Vec<_> = rows
        .iter()
        .map(|f| {
            let glyph = if app.ascii {
                ["i", "-", "!", "!!", "!!!"][f.severity as usize]
            } else {
                ["·", "○", "▲", "◆", "●"][f.severity as usize]
            };
            let style = Style::default().fg(app.theme.severity[f.severity as usize]);
            let style = if f.confidence == Confidence::Heuristic {
                style.add_modifier(Modifier::DIM)
            } else {
                style
            };
            Row::new(vec![
                Cell::from(format!("{glyph} {:?}", f.severity)).style(style),
                Cell::from(f.rule_id.to_string()),
                Cell::from(f.title.clone()),
                Cell::from(f.devices.len().to_string()),
                Cell::from(format!("{:?}", f.category)),
                Cell::from(format!("{:?}", f.confidence)),
            ])
        })
        .collect();
    let title = format!(
        "Findings {} | / {}{} | min {:?} | {:?} | heuristics {}",
        rows.len(),
        app.findings.search,
        if app.findings.editing { "_" } else { "" },
        app.findings.severity,
        app.findings.category,
        if app.findings.hide_heuristics {
            "hidden"
        } else {
            "shown"
        }
    );
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(10),
            Constraint::Length(13),
            Constraint::Min(14),
            Constraint::Length(3),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["Severity", "Rule", "Title", "#", "Category", "Confidence"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(widgets::block(app, &title))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(
        table,
        split[0],
        &mut TableState::default().with_selected(Some(app.findings.cursor)),
    );
    let mut lines = vec![];
    if let Some(f) = rows.get(app.findings.cursor) {
        lines.extend(markdown(&f.explanation));
        lines.push(Line::raw(""));
        lines.push(Line::raw(
            "Evidence: device | metric | observed | threshold",
        ));
        for e in &f.evidence {
            let name = app
                .inventory
                .devices
                .iter()
                .find(|d| d.id == e.device_id)
                .map_or_else(|| e.device_id.to_string(), |d| d.display_name.clone());
            lines.push(Line::raw(format!(
                "{} | {} | {} | {}",
                name,
                e.metric_path,
                e.observed,
                e.threshold
                    .as_ref()
                    .map_or_else(|| "-".into(), ToString::to_string)
            )));
        }
        lines.push(Line::raw(""));
        for (i, id) in f.devices.iter().enumerate() {
            let name = app
                .inventory
                .devices
                .iter()
                .find(|d| d.id == *id)
                .map_or_else(|| id.to_string(), |d| d.display_name.clone());
            lines.push(Line::raw(format!(
                "{} {name}",
                if i == app.findings.affected { ">" } else { " " }
            )));
        }
    } else {
        lines.push(Line::raw("No findings match the current filters."));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.findings.scroll, 0))
            .block(widgets::block(
                app,
                "Explanation | Enter device | Left/Right affected | PgUp/PgDn",
            )),
        split[1],
    );
}
