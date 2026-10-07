use crate::{
    action::{Action, Effect},
    app::{update, view, App},
};
use crossterm::{
    cursor::{Hide, Show},
    event::{Event, EventStream, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use nm_app::AppService;
use nm_store::repo::SettingsRepo;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, IsTerminal},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Quit,
    Interrupted,
}
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
}
pub fn needs_ascii() -> bool {
    #[cfg(windows)]
    {
        // chcp reports the console code page without requiring unsafe FFI in the workspace.
        // GetConsoleOutputCP is sampled indirectly; cmd cannot change it with no arguments.
        let result = std::process::Command::new("cmd")
            .args(["/d", "/c", "chcp"])
            .output();
        result.map_or(true, |output| {
            !String::from_utf8_lossy(&output.stdout)
                .split(|c: char| !c.is_ascii_digit())
                .any(|part| part == "65001")
        })
    }
    #[cfg(not(windows))]
    {
        false
    }
}
pub async fn run(mut svc: AppService) -> anyhow::Result<RunOutcome> {
    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "TUI requires an interactive terminal; use inventory list or --help when piping output"
    );
    let mut app = App::new(&svc)?;
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous_hook(info);
    }));
    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen, Hide)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut input = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut jobs = svc
        .take_job_events()
        .expect("new service owns its event receiver");
    let outcome = loop {
        terminal.draw(|frame| view(&app, frame))?;
        let action = tokio::select! {
            event = input.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => Action::Key(key),
                Some(Ok(_)) => Action::Tick, Some(Err(error)) => return Err(error.into()), None => break RunOutcome::Quit,
            },
            _ = tick.tick() => Action::Tick,
            event = jobs.recv() => match event { Some(event) => Action::Job(event), None => Action::Tick },
        };
        let mut exit = None;
        for effect in update(&mut app, action, &svc) {
            match effect {
                Effect::Quit => exit = Some(RunOutcome::Quit),
                Effect::Interrupted => exit = Some(RunOutcome::Interrupted),
                Effect::SaveSettings => {
                    svc.settings.theme = app.settings.theme;
                    match SettingsRepo::new(&svc.db).set("app", &svc.settings) {
                        Ok(()) => app.status_line = "Settings saved.".into(),
                        Err(error) => app.status_line = format!("Could not save settings: {error}"),
                    }
                }
                Effect::AddCredential { profile, secret } => {
                    match svc.add_credential(&profile, secret).await {
                        Ok(()) => {
                            app.status_line = "Session credential added.".into();
                            app.refresh(&svc)?;
                        }
                        Err(e) => app.status_line = e.to_string(),
                    }
                }
                Effect::ForgetCredential(id) => match svc.forget_credential(id).await {
                    Ok(()) => {
                        app.status_line = "Credential forgotten and devices unassigned.".into();
                        app.refresh(&svc)?;
                    }
                    Err(e) => app.status_line = e.to_string(),
                },
                Effect::StartScan { devices, dry_run } => {
                    match svc
                        .scan_job(
                            devices,
                            dry_run,
                            app.scan.global,
                            app.scan.per_site,
                            tokio_util::sync::CancellationToken::new(),
                        )
                        .await
                        .and_then(|job| svc.jobs.spawn(job).map_err(nm_app::AppError::from))
                    {
                        Ok(_) => app.interrupted = false,
                        Err(e) => app.status_line = e.to_string(),
                    }
                }
                Effect::Discover(iface) => {
                    let (send, receive) = tokio::sync::oneshot::channel();
                    app.discovery = Some(receive);
                    let net = svc.net.clone();
                    let audit = svc.audit.clone();
                    tokio::spawn(async move {
                        let result = nm_collect_ubiquiti::discovery::discover(
                            net.as_ref(),
                            &audit,
                            &iface,
                            Duration::from_secs(3),
                        )
                        .await
                        .map(|devices| {
                            devices
                                .iter()
                                .filter_map(
                                    nm_collect_ubiquiti::discovery::DiscoveredDevice::candidate,
                                )
                                .collect()
                        })
                        .map_err(|e| e.to_string());
                        let _ = send.send(result);
                    });
                }
            }
        }
        if let Some(outcome) = exit {
            break outcome;
        }
    };
    svc.shutdown().await?;
    Ok(outcome)
}
