use nm_app::{AppConfig, AppService};
use nm_tui::{app::ScreenId, view, App};
use ratatui::{backend::TestBackend, Terminal};

#[tokio::test]
async fn screen_snapshots_at_supported_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().to_path_buf()),
        deny_network: true,
    })
    .unwrap();
    let mut app = App::new(&svc).unwrap();
    // Stable paths and border choice make the same golden files portable across OSes.
    app.settings.data_dir = "<data-dir>".into();
    app.ascii = true;
    app.force_no_color = true;
    app.apply_theme();
    for (width, height) in [(80, 24), (120, 40)] {
        for screen in [ScreenId::Dashboard, ScreenId::Settings, ScreenId::Help] {
            app.screen = screen;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| view(&app, frame)).unwrap();
            let buffer = terminal.backend().buffer();
            let output = buffer
                .content
                .chunks(usize::from(width))
                .map(|row| {
                    row.iter()
                        .map(ratatui::buffer::Cell::symbol)
                        .collect::<String>()
                        .trim_end()
                        .to_owned()
                })
                .collect::<Vec<_>>()
                .join("\n");
            insta::assert_snapshot!(
                format!("{}_{}x{}", screen.label().to_lowercase(), width, height),
                output
            );
        }
    }
    svc.shutdown().await.unwrap();
}
