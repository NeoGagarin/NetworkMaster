use crate::{app::App, widgets};
use ratatui::{layout::Rect, widgets::Paragraph, Frame};
#[derive(Clone, Debug, Default)]
pub struct HelpState;
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Paragraph::new("1       Dashboard\n2       Inventory\n3       Credentials\n4       Scan\n5       Findings\n6       Devices\n7       Topology\n8       AI (M3)\n9       Audit (later)\n0       Settings\n?       Help\nEsc     Dashboard / dismiss confirmation\nq       Quit (confirm if a job is active)\nCtrl+C  Cancel active job; press again to quit\n\nOnly explicitly enrolled devices may be contacted.\nDry run is offline. Credentials last for this process only.")
        .block(widgets::block(app,"Global keys")),area);
}
