# M1 local validation

Date: 2026-10-06 (Asia/Manila)
Scope: Implementation and local tests, per the user's instruction. Hardware acceptance remains pending.

## Results

| Check | Environment | Result |
|---|---|---|
| `cargo test --locked --workspace --no-fail-fast` | Windows MSVC / Rust 1.92.0 | Passed |
| `cargo test --locked --workspace --no-fail-fast` | Ubuntu under WSL / Rust 1.92.0 | Passed |
| `cargo fmt --all -- --check` | Windows | Passed |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Windows | Passed |
| `cargo deny check advisories bans licenses sources` | Windows | Passed with the documented RSA advisory applicability exception |
| `python scripts/check-dependency-boundaries.py` | Windows | Passed |
| `bash scripts/check-no-direct-connect.sh` | Ubuntu under WSL | Passed |
| `bash scripts/check-egress.sh` | Ubuntu under WSL | Passed in an isolated network namespace; deny-all tests also passed |
| `python3 scripts/check-tui-pty.py <binary>` | Ubuntu under WSL / xterm PTY | Passed |
| `git diff --check` | Windows | Passed |

The workspace suite covers 57 tests, including compile-fail checks. Golden coverage includes 28 parser/merged-facts snapshots across two synthetic firmware shapes and 26 terminal snapshots: seven screens, all six Devices tabs and scan progress, at 80×24 and 120×40. Snapshot updates were inspected and rerun without the update override.

## Evidence covered locally

- CSV quoting, duplicates, invalid families/headers and stable inventory hashing; keyboard add → profile assignment → enrollment → credential forgetting.
- Three synthetic discovery reply fixtures, unknown TLVs and truncated datagrams. Discovery creates candidates and enrollment is explicit.
- In-process SSH replay with password and RSA key authentication, first-seen/matching/changed host keys, wrong credentials, legacy-only group1/RSA/CBC/SHA-1 negotiation and modern negotiation on an opted-in device.
- Per-command timeout, 4 MiB output truncation and audit recording when an in-flight command future is dropped. A command transport error ends its session to preserve sequential execution.
- Global/per-site concurrency high-water assertions, per-device budgets, cancellation and persisted partial snapshots.
- Fourteen-command dry-run/real-audit parity, known-station omission of `wstalist`, partial exit code 4 and scrubbed fixture capture through the CLI.
- Planted secret removal, preservation of SNMP presence/default booleans, consistent IP/MAC/bridge-ID/hostname/SSID tokenization, parser precedence and interface counter preservation.
- Offline enrolled-hostname dry runs without DNS, credential isolation and centralized socket construction.
- Real TUI event loop startup, navigation, resize, quit/Ctrl+C and restoration of terminal modes/cursor in a Linux PTY.

## Remaining acceptance

No real radios were contacted. The two airOS fixture sets and discovery datagrams are synthetic and explicitly marked; they do not establish compatibility with actual airOS 6.x/8.x releases. Real AP plus three-station scans, bench discovery, firmware command availability/timing, CPU impact, comparison with radio web UIs and real scrubbed captures remain in [HARDWARE-TESTING.md](HARDWARE-TESTING.md).

The manual Windows console matrix (cmd, PowerShell 5/7 and Windows Terminal) also remains pending. Automated Windows builds and TestBackend snapshots establish code and layout coverage, not every console host's interactive behavior.

See [ADR 0004](adr/0004-continue-in-rust.md) for the Rust decision, [ADR 0005](adr/0005-ssh-transport.md) for transport/dependency policy and the scoped RSA advisory exception, and [NETWORK-FOOTPRINT.md](NETWORK-FOOTPRINT.md) for traffic limits.
