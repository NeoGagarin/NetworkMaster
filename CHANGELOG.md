# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows Semantic Versioning; APIs may change before 1.0.

## [Unreleased]

### Added

- M0 foundation: eleven-crate Rust workspace, shared domain types and bundled SQLite migrations.
- Candidate inventory, explicit enrollment, metadata profiles, settings and append-only audit storage.
- Session credential arena with redacted debugging, zeroization and compile-fail serialization checks.
- Read-only collection contracts, empty SSH allowlists, enrolled target gate and deny-all networking.
- Cancellable jobs, shared application services, Dashboard/Settings/Help terminal shell and CLI tree.
- Windows/Linux CI, dependency boundaries, forbidden-command checks and offline egress workflow.
- Dual licenses, contribution/security guidance and architecture decisions.
- `scripts/check.sh` static-analysis suite (gitleaks, typos, taplo, shellcheck, shfmt, ruff, markdownlint, lychee, actionlint, zizmor, cargo-machete, rustdoc) shared by versioned pre-commit/pre-push hooks and a CI lint job; GitHub Actions pinned to commit SHAs.
- `AGENTS.md` guide for coding agents (imported by `CLAUDE.md`) and a Claude Code PostToolUse hook that formats edited files.
