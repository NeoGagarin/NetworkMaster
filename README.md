# NetworkMaster

> **Status: pre-alpha — M0 foundation.** No device collection, analysis or AI calls yet.

NetworkMaster is a native, read-only network assessment tool for small ISPs, WISPs and engineers. Its CLI and terminal UI share a Rust application service, SQLite inventory and audit log. Devices enter the inventory as candidates and require explicit enrollment. It never changes device configuration, and credential secrets remain in memory for the current process only.

Install Rust and the platform build prerequisites in [DEVELOPMENT.md](docs/DEVELOPMENT.md), then run `cargo run -p nm-cli --` for the TUI or `cargo run -p nm-cli -- inventory add 192.0.2.10 --family airos --name test`. `inventory list --json`, `inventory enroll <id>` and `audit tail` work in M0; later commands report their planned milestone. See [CLI.md](docs/CLI.md), [SPEC.md](docs/SPEC.md) and the [foundation plan](docs/plans/00-foundation.md). Licensed under Apache-2.0 OR MIT.
