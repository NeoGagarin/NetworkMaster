# ADR 0003: Layered core and three front ends

Date: 2026-10-06
Status: accepted

## Context

SPEC §3.4 requires TUI, CLI and a future stdio MCP server to expose the same assessments. Secret access must be isolated from AI, and persistence and networking must remain testable without a terminal or devices.

## Decision

Use the eleven-crate layout from SPEC §4. Front ends call `nm-app`; shared metadata lives in `nm-core`; SQLite lives in `nm-store`; secret allocations live in `nm-creds`. Credential profile types are defined in core and re-exported by creds, so store does not depend on secret storage. `AuditSink` lives in store and is re-exported by app, avoiding a collect/app dependency cycle.

`TargetGate::new` is async because hostname resolution uses Tokio. It resolves enrolled hostnames once and rejects ambiguous IP ownership rather than selecting another device's credentials. UDP bind addresses are checked against local interfaces via the safe if-addrs API, independently of OS nonlocal-bind settings. Unfinished snapshots have `finished_at: None`. The arena's shared inner owner clears secrets on final drop; dropping a temporary arena clone must not wipe other owners' session credentials. Fingerprint generation returns a Result so a poisoned arena cannot silently yield an empty scrub pattern set. The CLI drops AppService on interruption, and its bounded runtime shutdown prevents a blocked password prompt from delaying exit indefinitely.

Windows code-page detection uses `cmd /d /c chcp` to query the console code page safely instead of introducing unsafe GetConsoleOutputCP FFI. Explicit `--ascii` overrides the query. Future unused transport/provider dependency versions are declared centrally; they enter Cargo.lock when the corresponding implementation starts linking them. A workspace dependency declaration alone cannot lock an unused package.

## Consequences

Cargo-deny permits only app and collect to depend directly on creds; a graph check additionally bans every transitive AI-to-creds path. This strengthens the [cargo-deny wrappers rule](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html). The three front ends remain thin and tests can substitute deny-all sockets. M0 leaves vendor, analysis, AI and MCP crates as documented stubs.

No remote is configured in this bootstrap. The workspace repository URL is a clearly documented placeholder; assign the canonical URL and security reporting contact and verify the CODEOWNERS maintainer email before public hosting. Remote workflow success and interactive terminal matrix checks require that environment and are tracked separately from local tests.
