# NetworkMaster — Implementation Plans

These plans break [SPEC.md](../SPEC.md) into seven sequential milestones. Each plan is self-contained enough to hand to a contributor, or to an agent harness, as the brief for that milestone. Spec section numbers are referenced as `SPEC §n`.

| # | Plan | Milestone | Depends on | Rough effort* |
|---|------|-----------|------------|---------------|
| 00 | [Foundation](00-foundation.md) | M0 — Skeleton | — | 8–12 days |
| 01 | [airOS collection](01-airos-collection.md) | M1 — airOS | 00 | 12–18 days |
| 02 | [EdgeOS and rules engine](02-edgeos-and-rules.md) | M2 — EdgeOS + rules | 01 | 12–18 days |
| 03 | [AI layer](03-ai-layer.md) | M3 — AI | 02 | 12–16 days |
| 04 | [External harnesses](04-external-harnesses.md) | M4 — MCP + export | 03 | 5–8 days |
| 05 | [Controllers](05-controllers.md) | M5 — UISP + UniFi | 01, 02 (parallel with 03/04) | 10–14 days |
| 06 | [Release 1.0](06-release-1.0.md) | M6 — 1.0 | all | 15–20 days |

\* Focused days for one developer who is competent but not expert in Rust. Double it for calendar time with a day job. Plan 05 can run in parallel with 03 and 04 if a second contributor appears.

## Conventions shared by every plan

### Definition of done (applies to every task)

- `cargo build --workspace` and `cargo test --workspace` pass on Windows and Linux in CI.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- `cargo fmt --check` is clean.
- `cargo deny check` passes (licenses, bans, advisories).
- Any new public type or function has a doc comment.
- Any decision that was not obvious has an ADR in `docs/adr/` (template in plan 00).
- `CHANGELOG.md` has an entry under `Unreleased`.
- No task is "done" if it weakens a non-negotiable in SPEC §1.3. If a task seems to require that, stop and write an ADR explaining why before proceeding.

### Task format

Each task in a plan has:

- **ID** like `00-07` (plan number, task number).
- **Where**: the crate and file paths it touches.
- **What**: the deliverable, with types or signatures where they matter.
- **Accept**: how to verify it, as a command or an observable behavior.

Tasks within a plan are ordered so that each one compiles and tests pass when it lands. Land them as separate commits or PRs.

### Branching and commits

- `main` is always releasable (even if "releasable" means "an empty TUI that launches").
- One branch per task or small group of tasks. Conventional commit prefixes: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.
- The allowlist file (`crates/nm-collect/src/allowlist.rs`) and `SECURITY.md` require a second pair of eyes once the project has more than one maintainer. Until then, the author re-reads the diff out loud. Seriously.

### Hardware you need on the bench, by plan

| Plan | Hardware |
|------|----------|
| 01 | One airMAX AP (any Rocket, LiteAP, NanoStation in AP mode) and at least one station. An airOS 6.x device and an airOS 8.x device if possible. |
| 02 | One EdgeRouter (ER-X is ideal because hardware offload matters there). Two if you want a real OSPF adjacency. |
| 05 | A UISP instance (the free tier or a self-hosted container) and a UniFi Network controller (the Windows installer or a Docker image) with at least one adopted device. |
| 06 | An EdgeSwitch for SNMP. Optional. |

### What is deliberately not planned

Post-1.0 items from SPEC §19 (MikroTik, Cambium, Cisco, generic SNMP, scheduled snapshots) have no plan yet. Write one when 1.0 ships, using these as templates.
