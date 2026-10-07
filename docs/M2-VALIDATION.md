# M2 validation

Date: 2026-10-06 (Asia/Manila)

Software scope: EdgeOS collection, 34 single-snapshot rules, findings persistence,
CLI commands, Findings and Topology screens, Markdown reports and platform tables.
Hardware acceptance remains pending; no device settings were changed.

## Reproducible local checks

```text
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
cargo deny check
```

Parser goldens use fixtures/edgeos/synthetic-er-x-2.0.9, explicitly marked synthetic.
Tests cover every command parser, config quoting and round trips, every secret leaf,
crypt strings, unknown offload flags, OSPF states and merged facts. Catalog tests
cover positive, negative and unavailable facts for every rule, strict boundaries,
overrides, stable IDs and panic isolation. Integration tests cover persistence,
filters, profile metadata, redaction, report goldens, CLI parity, SSH replay and TUI snapshots
at 80×24 and 120×40.

Local Windows validation passed: workspace build, tests, Clippy with warnings
as errors, Rust formatting, rustdoc with warnings as errors, cargo-deny, and
unused-dependency checks. TOML formatting, Markdown lint, spelling, workflow
lint, direct socket creation and AI credential dependency boundaries also passed.
The CLI-generated rules reference matches docs/RULES.md byte for byte.

The SSH replay tests exercise the real EdgeOS collector against a local test
server, including config-first ordering, absent-protocol skips, secret scrubbing,
automatic analysis, and malformed config handling. These are synthetic tests.

CI runs Windows and Linux checks and compares generated docs/RULES.md with the
catalog. Linux CI has not been executed locally.

## Pending hardware acceptance

Follow [HARDWARE-TESTING.md](HARDWARE-TESTING.md) to validate wrapper command
availability, capture real ER-X outputs, compare typed facts with the UI, review
findings on real radios, and confirm the inferred station tree. The optional
ethernet detail command is provisional until the bench confirms it. Unsupported
commands produce coverage gaps; do not mark them collected.

The PERF-001 offload check requires the operator to toggle offload in the router
UI during the bench test and restore it afterward. NetworkMaster has no command
or API for doing this. Threshold rationale is in
[ADR 0006](adr/0006-rule-thresholds.md).
