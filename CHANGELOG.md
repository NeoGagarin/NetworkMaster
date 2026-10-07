# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows Semantic Versioning; APIs may change before 1.0.

## [Unreleased]

### Changed

- The legacy SSH opt-in is now a typed job event carrying the algorithms the device offered, and the TUI modal shows them, instead of matching a progress-message prefix.
- SSH connection, key exchange and authentication have their own 45 second budget instead of sharing the 20 second per-command timeout.

### Fixed

- The forbidden-command test now rejects shell metacharacters, interpreters and privilege escalation (`| & ; $() < >`, `sudo`, `sh`, `tee`, `sed`, `chmod`, …), not only mutating verbs.
- A parser disagreement while merging interface facts is recorded as a coverage error instead of panicking the whole scan job.
- The analysis migration quotes its JSON default as a string literal.
- Findings loaded with a snapshot now use the same canonical order as the rules runner and the findings query. Ordering by id made the Findings screen order depend on inventory ids, which flipped equal-severity rows between runs.

### Added

- M2 EdgeOS SSH collector, redacted configuration tree, synthetic parser fixtures and shared Linux parsers.
- Deterministic catalog of 34 single-snapshot rules, configurable thresholds, panic isolation and atomic findings replacement.
- Findings and Topology screens, interface role overrides, filtered Markdown reports and analysis CLI commands.
- Offline capability and firmware tables, generated rule documentation and CI drift checks.
- M0 foundation: eleven-crate Rust workspace, shared domain types and bundled SQLite migrations.
- Candidate inventory, explicit enrollment, metadata profiles, settings and append-only audit storage.
- Session credential arena with redacted debugging, zeroization and compile-fail serialization checks.
- Read-only collection contracts, empty SSH allowlists, enrolled target gate and deny-all networking.
- Cancellable jobs, shared application services, Dashboard/Settings/Help terminal shell and CLI tree.
- Windows/Linux CI, dependency boundaries, forbidden-command checks and offline egress workflow.
- Dual licenses, contribution/security guidance and architecture decisions.
- `scripts/check.sh` static-analysis suite (gitleaks, typos, taplo, shellcheck, shfmt, ruff, markdownlint, lychee, actionlint, zizmor, cargo-machete, rustdoc) shared by versioned pre-commit/pre-push hooks and a CI lint job; GitHub Actions pinned to commit SHAs.
- `AGENTS.md` guide for coding agents (imported by `CLAUDE.md`) and a Claude Code PostToolUse hook that formats edited files.
