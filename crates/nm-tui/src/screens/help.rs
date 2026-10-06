use crate::{app::App, widgets};
use ratatui::{layout::Rect, widgets::Paragraph, Frame};
#[derive(Clone, Debug, Default)]
pub struct HelpState;
pub fn view(app: &App, frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Paragraph::new("1       Dashboard\n2       Inventory (M1)\n3       Credentials (M1)\n4       Scan (M1)\n5       Findings (M2)\n6       Devices (M1)\n7       Topology (M2)\n8       AI (M3)\n9       Audit (later)\n0       Settings\n?       Help\nEsc     Dashboard / dismiss confirmation\nq       Quit (confirm if a job is active)\nCtrl+C  Cancel active job; press again to quit\n\nOnly explicitly enrolled devices may be contacted.\nM0 has no network collectors. Credentials last for this process only.")
        .block(widgets::block(app,"Global keys")),area);
}
