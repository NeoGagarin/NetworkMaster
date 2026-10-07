use crate::app::App;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    symbols,
    widgets::{Block, Borders, Clear, Paragraph, Row, Table},
    Frame,
};

pub fn block<'a>(app: &App, title: &'a str) -> Block<'a> {
    let ascii = symbols::border::Set {
        top_left: "+",
        top_right: "+",
        bottom_left: "+",
        bottom_right: "+",
        vertical_left: "|",
        vertical_right: "|",
        horizontal_top: "-",
        horizontal_bottom: "-",
    };
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_set(if app.ascii {
            ascii
        } else {
            symbols::border::PLAIN
        })
        .border_style(Style::default().fg(app.theme.border))
}
pub struct TitleBar;
impl TitleBar {
    pub fn render(app: &App, frame: &mut Frame<'_>, area: Rect) {
        frame.render_widget(
            Paragraph::new(format!(
                "NetworkMaster  |  {}  |  pre-alpha {}",
                app.screen.label(),
                env!("CARGO_PKG_VERSION")
            ))
            .style(
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            )
            .block(block(app, "Read-only network assessment")),
            area,
        );
    }
}
pub struct StatusLine;
impl StatusLine {
    pub fn render(app: &App, frame: &mut Frame<'_>, area: Rect) {
        frame.render_widget(
            Paragraph::new(app.status_line.as_str()).style(Style::default().fg(app.theme.muted)),
            area,
        );
    }
}
pub struct KeyHints;
impl KeyHints {
    pub fn render(app: &App, frame: &mut Frame<'_>, area: Rect) {
        frame.render_widget(
            Paragraph::new(match app.screen {
                crate::ScreenId::Inventory=>"n Add  i CSV  d Discover  Space Select  e Enroll  u Unenroll  p Profile  t Site",
                crate::ScreenId::Credentials=>"n New  f Forget  Enter Devices  2 Inventory  4 Scan  q Quit",
                crate::ScreenId::Scan=>"r Dry run  s Start  c Cancel  o Scope  g Limits  Enter Details  q Quit",
                crate::ScreenId::Findings=>"/ Filter  1-5 Severity  c Category  h Heuristics  D Disable  E Export  Enter Device",
                crate::ScreenId::Topology=>"Up/Down Select  Enter Device  5 Findings  Esc Dashboard",
                crate::ScreenId::Devices=>"Tab Detail  Up/Down Device  [ ] Snapshot  / Search  R Interface role  q Quit",
                _=>"1 Home  2 Inventory  3 Credentials  4 Scan  5 Findings  6 Devices  7 Topology  ? Help",
            })
                .style(Style::default().fg(app.theme.accent)),
            area,
        );
    }
}
pub struct ConfirmModal;
impl ConfirmModal {
    pub fn render(app: &App, frame: &mut Frame<'_>) {
        let area = frame.area();
        let width = area.width.min(52);
        let height = area.height.min(5);
        let modal = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, modal);
        frame.render_widget(
            Paragraph::new("A job is active. Cancel it and quit?\n\ny Yes   n / Esc Stay")
                .block(block(app, "Confirm quit")),
            modal,
        );
    }
}
/// Fixed-length columns preserve alignment across refreshes.
pub fn stable_table<'a>(rows: Vec<Row<'a>>, widths: &[u16]) -> Table<'a> {
    Table::new(
        rows,
        widths
            .iter()
            .copied()
            .map(Constraint::Length)
            .collect::<Vec<_>>(),
    )
}
