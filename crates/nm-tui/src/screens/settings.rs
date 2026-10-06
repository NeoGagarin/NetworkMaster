use crate::{app::App, widgets};
use nm_app::ThemeChoice;
use ratatui::{
    layout::Rect,
    widgets::{Paragraph, Wrap},
    Frame,
};
#[derive(Clone, Debug, Default)]
pub struct SettingsState {
    pub data_dir: String,
    pub theme: ThemeChoice,
}
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Paragraph::new(format!("Theme: {:?}\nBorders: {}\nData directory: {}\nVersion: {}\n\nProviders: none (planned for M3)\n\nd Dark   h High contrast   n No color\nTheme changes are saved locally. NO_COLOR takes precedence.",
        app.settings.theme,if app.ascii { "ASCII" } else { "Unicode" },app.settings.data_dir,env!("CARGO_PKG_VERSION")))
        .wrap(Wrap { trim: false }).block(widgets::block(app,"Settings")),area);
}
