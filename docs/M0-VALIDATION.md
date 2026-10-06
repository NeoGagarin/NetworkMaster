# M0 foundation validation

Date: 2026-10-06 (Asia/Manila)
Status: implementation and local automated checks passed; remote CI and remaining native terminal hosts pending.

## Build and automated checks

The eleven-crate workspace builds on Windows MSVC and Linux (Ubuntu under WSL) with Rust 1.92.0. `nm-cli` produces `netmaster.exe` on Windows and `netmaster` on Linux. The workspace test suite passes on both systems (36 tests, including the six terminal golden snapshots inside one test). Formatting and clippy with `-D warnings` pass. Cargo-deny advisories, bans, licenses and sources pass; its default output includes non-failing duplicate-version and unused-license-allowance warnings.

The tests cover domain validation and empty partial facts, fourteen-table migration idempotence, repository CRUD and persistence, audit ordering and append-only triggers, redaction/hash checks at artifact storage, session credentials and their compile-fail Serialize boundary, job cancellation/admission/backpressure, CLI add/list/enroll, secret-free credential creation audit, data-directory precedence and stable exit codes.

The direct-connect shell check passes on Git Bash and Linux. The dependency graph check passes on Windows and Linux. The Linux egress script successfully runs `inventory list` and `audit tail` inside `unshare --user --map-root-user --net`, then exercises the environment-selected deny-all factory. Deny-all socket tests also pass on Windows. No application startup or implemented command needs network access.

## Negative controls

Temporary changes were tested and restored before committing:

1. Putting `cmd("set system host-name x")` in the airOS allowlist makes the actual forbidden-command integration test fail with a mutating-command diagnostic.
2. Adding `nm-creds` to `nm-ai` makes `cargo deny check bans` fail.
3. Adding `nm-app` to `nm-ai` makes the graph check fail on an indirect path to credentials.

The production SSH allowlists are empty. Manifests and Cargo.lock were restored after these checks. These proofs are also recorded in the bootstrap commit message.

## Terminal checks

| Environment | Result |
|-------------|--------|
| cmd.exe in a Windows ConPTY session | Dashboard launches; `q` exits 0 and restores screen/cursor |
| PowerShell 5.1.26100.9444 in ConPTY | Dashboard launches; `q` exits 0 and restores screen/cursor |
| PowerShell 7 in ConPTY | Dashboard, Settings and Help navigate; `q` exits 0 and restores screen/cursor |
| Ubuntu WSL PTY, TERM=xterm-256color | Launch, navigation, 80×24 → 120×40 resize/redraw, quit 0, Ctrl+C 130 and original termios restoration pass |
| Windows Terminal GUI host | Pending direct manual verification |
| Linux xterm GUI host | Pending direct manual verification; xterm is not installed on this host |
| Legacy Windows 10 1809 conhost | Pending hardware/VM verification from the plan's risk checklist |

`scripts/check-tui-pty.py` verifies the real Linux event loop and terminal restoration, separately from TestBackend golden output. The test emulates xterm's cursor-position response. ConPTY and PTY results do not claim verification of every native GUI host.

## CI and publication

Both workflow YAML files and Dependabot configuration parse successfully. CI defines Windows/Ubuntu build, formatting, clippy, tests, cargo-deny, connection/dependency boundaries, forbidden commands and deny-all checks; Ubuntu additionally runs the real TUI PTY test. The egress workflow runs the namespace/factory checks.

There is no configured remote, so GitHub Actions success on `main` has not been established. Assign the canonical repository URL (the Cargo repository field is a documented placeholder), verify the CODEOWNERS email maps to its maintainer account, and enable GitHub private vulnerability reporting before public hosting. The initial commit's maintainer email is the current private disclosure contact.
