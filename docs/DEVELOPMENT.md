# Developing NetworkMaster

## Prerequisites and build

On Windows, install [Rust through rustup](https://rustup.rs/) and Visual Studio Build Tools with **Desktop development with C++**, the MSVC compiler and Windows SDK. Use the `x86_64-pc-windows-msvc` host. The project pins Rust 1.92.0 and installs rustfmt/clippy through `rust-toolchain.toml`. PowerShell 5, PowerShell 7 and cmd can all run these commands:

```text
cargo build --locked --workspace
cargo run -p nm-cli --
```

The binary is `target\debug\netmaster.exe`. On Linux install rustup, a C compiler, make and a linker (`build-essential` on Debian/Ubuntu), then run the same Cargo commands. The binary is `target/debug/netmaster`. An interactive terminal is required for the TUI. SQLite is bundled; M0 needs no other C library. Later HTTP/SSH transports use Rust implementations and rustls.

Press `q` to exit, `0` for Settings and `?` for Help. Try `--ascii` in legacy consoles and `--no-color` to disable color. `NO_COLOR` is honored. On Windows, `chcp` is queried without changing the console code page; Unicode borders are used for code page 65001. Minimum size is 80×24, with larger layouts tested at 120×40. Resizes redraw on the next event.

## Local data and CLI smoke test

The database is `%LOCALAPPDATA%\NetworkMaster\netmaster.db` on Windows or `$XDG_DATA_HOME/networkmaster/netmaster.db` (normally `~/.local/share`) on Linux. `NETMASTER_DATA_DIR` overrides this; `--data-dir` takes precedence over the environment. Use a temporary directory for smoke tests:

```text
cargo run -p nm-cli -- --data-dir ./target/smoke inventory add 192.0.2.10 --family airos --name test
cargo run -p nm-cli -- --data-dir ./target/smoke inventory list --json
cargo run -p nm-cli -- --data-dir ./target/smoke inventory enroll <id-from-add>
cargo run -p nm-cli -- --data-dir ./target/smoke audit tail
```

Adding does not enroll or resolve DNS. M0 opens no network connection. See [CLI.md](CLI.md) for credentials, stable exit codes and the complete future command tree.

## Validation

`scripts/check.sh` runs every check; the git hooks and the CI `lint` job call the same script, so a local pass means the same thing everywhere. Run it from Git Bash on Windows:

```text
bash scripts/check.sh            # static: fast checks that do not compile
bash scripts/check.sh rust       # clippy, rustdoc, cargo-deny, AI credential boundary
bash scripts/check.sh test       # cargo test for the workspace
bash scripts/check.sh all        # everything above, which is what pre-push runs
```

`SKIP=clippy,test bash scripts/check.sh all` skips named checks for one run. A missing optional tool is reported and skipped locally; `--strict` (used by CI) makes it a failure.

| Check | Tool | Configuration |
|-------|------|---------------|
| Rust formatting and lints | rustfmt, clippy (pedantic, `-D warnings`), rustdoc (`-D warnings`) | `rustfmt.toml`, `clippy.toml`, `[workspace.lints]` |
| Dependencies | cargo-deny (advisories, licenses, bans, sources), cargo-machete (unused) | `deny.toml`, `[package.metadata.cargo-machete]` |
| Invariants | socket boundary, AI credential boundary | `scripts/check-no-direct-connect.sh`, `scripts/check-dependency-boundaries.py` |
| Secrets | gitleaks over staged changes or the full history | `.gitleaks.toml` |
| Spelling | typos | `typos.toml` |
| Whitespace | `git diff --check` | `.editorconfig`, `.gitattributes` |
| TOML | taplo | `.taplo.toml` |
| Shell | shellcheck, shfmt | `.shellcheckrc`, `.editorconfig` |
| Python | ruff (lint and format) | `ruff.toml` |
| Markdown | markdownlint-cli2, lychee (offline: relative links and anchors) | `.markdownlint-cli2.jsonc`, `lychee.toml` |
| GitHub Actions | actionlint, zizmor (actions are pinned to commit SHAs) | `zizmor.yml` |

Install the non-Cargo tools once. The CI `lint` job pins the exact versions:

```text
cargo install --locked cargo-deny cargo-machete typos-cli taplo-cli lychee
go install github.com/rhysd/actionlint/cmd/actionlint@latest
go install github.com/zricethezav/gitleaks/v8@latest
npm install --global markdownlint-cli2
uv tool install ruff          # or: pipx install ruff
scoop install shellcheck shfmt zizmor   # Linux: use the distribution packages or `pipx install zizmor`
```

### Git hooks

Enable the versioned hooks once per clone with `bash scripts/install-hooks.sh`, which sets `core.hooksPath` to `.githooks`:

- **pre-commit** runs the static stage on staged files only, which usually takes a few seconds.
- **pre-push** runs `check.sh all`, the same checks as CI apart from the platform matrix and the PTY and egress smoke tests.

Hooks check the working-tree copy of each staged file, so stage whole files rather than partial hunks. `git commit --no-verify` or `git push --no-verify` bypasses a hook once; CI still runs every check.

Python 3 is needed for the graph check and the Linux TUI PTY smoke test (`python3 scripts/check-tui-pty.py`). On Windows use Git Bash for the shell script. On Linux `bash scripts/check-egress.sh` runs local CLI operations in a network namespace, or tests the deny-all factory if namespaces are unavailable. `NETMASTER_NET=deny` makes AppService construct that factory and skip DNS entirely. CI runs the Windows and Ubuntu matrix plus a Linux egress workflow.

Golden terminal output is in `crates/nm-tui/tests/snapshots`. Update only after inspecting the rendered output: use `INSTA_UPDATE=always cargo test -p nm-tui --test screens` in a POSIX shell, or set `$env:INSTA_UPDATE='always'` in PowerShell. Then remove the environment override and rerun tests. The credential compile-fail baseline is checked with trybuild; inspect any compiler diagnostic update before accepting it.

## Crate relationships

```text
                 +-------------+  +-------------+  +-------------+
                 |   nm-tui    |  |   nm-cli    |  |   nm-mcp    |
                 |  (ratatui)  |  |   (clap)    |  |   (rmcp)    |
                 +------+------+  +------+------+  +------+------+
                        +----------------+----------------+
                                         v
                              +--------------------+
                              |      nm-app        |
                              |  (application svc) |
                              +---------+----------+
          +-------------+---------------+---------------+-------------+
          v             v               v               v             v
   +------------+ +-----------+  +------------+  +-----------+ +-----------+
   | nm-collect | |nm-analyze |  |   nm-ai    |  | nm-store  | | nm-creds  |
   | transports | | rules     |  | providers  |  | sqlite    | | arena     |
   +-----+------+ +-----------+  | redaction  |  | snapshots | +-----------+
         |                       +------------+  +-----------+
         v
   +---------------------+
   | nm-collect-ubiquiti |
   +---------------------+
                              +------------+
                              |  nm-core   | shared types, IDs, metadata
                              +------------+
```

The diagram represents the product layers; in M0 vendor/analysis/AI/MCP crates are stubs. Vendor collectors implement nm-collect contracts, so their Rust dependency points toward nm-collect. See ADR 0003 for metadata and audit placement.

## Invariants and extension points

- No writes: private `SshCommand` construction in one allowlist module, a forbidden-verb integration test and closed HTTP login endpoint enum. No transport exists yet.
- Enrollment: candidates default to false; `TargetGate` resolves enrolled inventory once, and RealNet checks the IP before creating an outbound TCP connection.
- Secrets: secrecy allocations zeroize on drop. The arena has closure access and no owned-secret getter or Serialize implementation. Metadata can persist, secret-derived scrub patterns cannot be logged.
- AI isolation: cargo-deny restricts direct creds dependents, and the Python graph check rejects indirect paths too.
- Audit: collectors queue bounded events to a single writer; flush reports errors and acts as a durability barrier. SQLite triggers prohibit audit updates/deletes through the application connection.
- Offline behavior: no telemetry or startup DNS; namespace and deny-all tests verify local operations.

Copy the ADR template for architectural changes. Add dependency versions to `[workspace.dependencies]` and inherit them in each consumer; Cargo CLI workspace support changes over time, so direct manifest edits are supported. Run all validation commands after lockfile changes. Future transports must obtain sockets through NetFactory and enforce the planned HTTP/UDP policies when they are implemented.

## Interactive acceptance

The automated TUI snapshots cover three screens at both sizes. The human matrix is separate: cmd, PowerShell 5, PowerShell 7, Windows Terminal and Linux xterm. For each, launch, navigate, switch themes, resize, quit and confirm the cursor/normal terminal return. Test Ctrl+C with an active job once scan jobs exist. Record available host results in [M0-VALIDATION.md](M0-VALIDATION.md); automated snapshots do not establish compatibility with every terminal host.
