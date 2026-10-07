use crate::{app::App, widgets};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Paragraph, Row, Wrap},
    Frame,
};

#[derive(Clone, Debug, Default)]
pub struct DashboardState {
    pub families: Vec<(String, usize, usize)>,
    pub last_snapshot: Option<String>,
    pub findings: [usize; 5],
}
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(9),
            Constraint::Length(5),
            Constraint::Length(4),
        ])
        .split(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(panels[0]);
    let mut rows = vec![Row::new(["Family", "Enrolled", "Candidates"])];
    rows.extend(
        app.dashboard
            .families
            .iter()
            .map(|(name, enrolled, candidates)| {
                Row::new(vec![
                    name.clone(),
                    enrolled.to_string(),
                    candidates.to_string(),
                ])
            }),
    );
    frame.render_widget(
        widgets::stable_table(rows, &[15, 10, 10]).block(widgets::block(app, "Inventory")),
        columns[0],
    );
    let findings = ["Info", "Low", "Medium", "High", "Critical"]
        .iter()
        .zip(app.dashboard.findings)
        .map(|(name, count)| Row::new(vec![(*name).to_string(), count.to_string()]));
    frame.render_widget(
        widgets::stable_table(findings.collect(), &[12, 8]).block(widgets::block(app, "Findings")),
        columns[1],
    );
    let coverage = if app.ascii { "--" } else { "—" };
    frame.render_widget(
        Paragraph::new(format!(
            "Last snapshot: {}\nCoverage: {coverage}\nairOS SSH collector available. Press 4 for dry run.",
            app.dashboard.last_snapshot.as_deref().unwrap_or("never")
        ))
        .block(widgets::block(app, "Collection")),
        panels[1],
    );
    frame.render_widget(Paragraph::new("Add candidates: netmaster inventory add <address>\nEnroll: netmaster inventory enroll <id>   |   0 Settings   ? Help")
        .wrap(Wrap { trim: false }).block(widgets::block(app,"Quick actions")),panels[2]);
}
