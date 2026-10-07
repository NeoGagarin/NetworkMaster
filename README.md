# NetworkMaster

> **Status: pre-alpha — M2 EdgeOS collection and deterministic analysis implemented; hardware acceptance pending.**

NetworkMaster is a native, read-only network assessment tool for small ISPs, WISPs and engineers. Its CLI and terminal UI share a Rust application service, SQLite inventory, snapshots and audit log. Devices enter as candidates and require explicit enrollment. Credential secrets remain in memory for the current process only.

M1 adds manual/CSV inventory, explicit UDP discovery, pinned SSH collection, fourteen allowlisted airOS commands, secret scrubbing, fixture capture, dry-run planning and the Inventory, Credentials, Scan and Devices screens. Local tests use synthetic airOS 6.x/8.x fixtures and an in-process SSH server. Real AP/station validation remains pending; see [HARDWARE-TESTING.md](docs/HARDWARE-TESTING.md).

M2 adds EdgeRouter SSH collection, a secret-redacting configuration parser, 34 deterministic rules, findings persistence, reports and topology inference. The Findings and Topology screens share the same analysis and report services as the CLI. See the generated [rule catalog](docs/RULES.md), [M2 validation](docs/M2-VALIDATION.md) and [threshold rationale](docs/adr/0006-rule-thresholds.md). EdgeOS fixtures are synthetic; real ER-X command and finding acceptance remains pending.

Install Rust and the platform prerequisites in [DEVELOPMENT.md](docs/DEVELOPMENT.md), then run `cargo run -p nm-cli --` for the TUI. Use [CLI.md](docs/CLI.md) for enrollment, credentials, scanning and analysis, and [NETWORK-FOOTPRINT.md](docs/NETWORK-FOOTPRINT.md) for traffic limits. The [EdgeOS and rules plan](docs/plans/02-edgeos-and-rules.md) and [SPEC.md](docs/SPEC.md) describe the scope. AI, controller imports, additional device families and persistent credential storage remain later milestones.

Licensed under Apache-2.0 OR MIT.
