#![doc = include_str!("../README.md")]
mod cli;
mod commands;
use clap::Parser;
use cli::Cli;
use nm_app::{AppConfig, AppService, ThemeChoice};
use std::{process::ExitCode, time::Duration};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .with_ansi(!cli.no_color && std::env::var_os("NO_COLOR").is_none())
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    // Poll SSH handshakes on runtime workers. Windows' main thread has only a
    // 1 MiB stack, which is insufficient for debug-build cryptographic futures.
    let code = match runtime
        .block_on(async { tokio::spawn(run(cli)).await.map_err(anyhow::Error::from)? })
    {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    };
    // A cancelled interactive input worker must not keep the process alive.
    // AppService and its arena are dropped before this runtime shutdown.
    runtime.shutdown_timeout(Duration::from_millis(250));
    ExitCode::from(code)
}
async fn run(cli: Cli) -> anyhow::Result<u8> {
    let mut svc = AppService::open(AppConfig {
        data_dir: cli.data_dir.clone(),
        deny_network: false,
    })?;
    svc.settings.ascii |= cli.ascii;
    if cli.no_color {
        svc.settings.theme = ThemeChoice::NoColor;
    }
    if cli.command.is_none() {
        return Ok(match nm_tui::run(svc).await? {
            nm_tui::RunOutcome::Quit => 0,
            nm_tui::RunOutcome::Interrupted => 130,
        });
    }
    let result = if matches!(cli.command, Some(cli::Command::Scan { .. })) {
        commands::execute(&cli, &svc).await
    } else {
        tokio::select! {
            result = commands::execute(&cli,&svc) => result,
            result = tokio::signal::ctrl_c() => { result?; Ok(130) },
        }
    };
    let shutdown = svc.shutdown().await;
    let code = result?;
    shutdown?;
    Ok(code)
}
