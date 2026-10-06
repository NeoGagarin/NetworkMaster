# Plan 00 — Foundation (M0: Skeleton)

**Goal:** A Cargo workspace that builds on Windows and Linux, launches an empty but real TUI from cmd, PowerShell and Windows Terminal, persists to SQLite, holds credentials in memory safely, and already enforces the no-write and only-enrolled-targets invariants in types and CI. Nothing talks to a network yet.

**Exit criteria (SPEC §19, M0):** `netmaster` launches on all three Windows shells and on Linux. CI is green on both OSes. The forbidden-verb test exists and passes against an initially empty allowlist. The egress test exists and passes.

**Depends on:** nothing.
**Produces for later plans:** every crate skeleton, the domain types in `nm-core`, the store, the audit log, the credential arena, `TargetGate`, the `SshCommand` newtype, the TUI event loop, the CLI shell, CI.

---

## 1. Scope

In scope:

- Repository hygiene: licenses, README, CONTRIBUTING, SECURITY.md, CODE_OF_CONDUCT, ADR template, CHANGELOG, `.editorconfig`, `rust-toolchain.toml`, `deny.toml`.
- Workspace with all eleven crates from SPEC §4, most of them stubs.
- `nm-core` domain types from SPEC §5, complete enough that later plans only add fields.
- `nm-store` with migrations for every table in SPEC §14, plus repository functions for devices, sites, profiles, settings and audit.
- `nm-creds` with session-only `CredArena` and the `with_secret` API.
- `nm-collect` with the `Collector` trait, `CollectionPlan`, `TargetGate`, the `SshCommand` newtype, an empty allowlist, and a `NetFactory` abstraction that tests can replace with a deny-all implementation.
- `nm-app` with `AppService`, a `JobRunner` using cancellation tokens, and job event channels.
- `nm-tui` with the event loop, screen router, Dashboard, Settings and Help screens, theme tokens.
- `nm-cli` with clap subcommand tree (most subcommands print "not implemented in M0").
- CI: build, test, clippy, fmt, deny, egress, forbidden-verb, on `windows-latest` and `ubuntu-latest`.

Out of scope: any transport implementation, any parser, any rule, any AI code, discovery.

---

## 2. Tasks

### 00-01 Repository bootstrap

**Where:** repo root.
**What:**

- `LICENSE-APACHE`, `LICENSE-MIT`, `README.md` (two paragraphs and a "status: pre-alpha" banner), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SECURITY.md` (contact, 90-day window, statement of the no-write invariant), `CHANGELOG.md` (Keep a Changelog format), `.gitignore`, `.editorconfig`, `.gitattributes` (`* text=auto eol=lf`).
- `rust-toolchain.toml` pinning a stable channel by version (not `stable`), with `components = ["clippy", "rustfmt"]`.
- `rustfmt.toml`: `edition = "2021"`, `max_width = 100`.
- `deny.toml`: allow `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `MPL-2.0`; deny `GPL-*`, `AGPL-*`; `[bans]` section includes a placeholder for the `nm-ai` → `nm-creds` ban (filled in 00-06).
- `docs/adr/0000-template.md` and `docs/adr/0001-language-rust.md`, `docs/adr/0002-license-dual.md`, `docs/adr/0003-layered-core-three-frontends.md`, each a one-page record of the decision already made in SPEC §3 and §18.
**Accept:** `git log` shows one commit; `cargo deny check licenses` passes once 00-02 lands.

### 00-02 Workspace and crate skeletons

**Where:** `Cargo.toml`, `crates/*/Cargo.toml`, `crates/*/src/lib.rs` or `main.rs`.
**What:**

- Root `Cargo.toml` with `[workspace] members = ["crates/*"]`, `resolver = "2"`, `[workspace.package]` for `version = "0.0.1"`, `edition`, `license = "Apache-2.0 OR MIT"`, `repository`, and `[workspace.dependencies]` listing every crate from SPEC §4.1 with versions, so member crates use `dep = { workspace = true }`.
- `[workspace.lints.clippy]` with `pedantic = "warn"` plus a short allow list; `[workspace.lints.rust] unsafe_code = "forbid"` for every crate except `nm-creds` (which may need `deny` with a documented exception for zeroize).
- Eleven crates, each with `lib.rs` containing `#![doc = include_str!("../README.md")]` and a one-paragraph `README.md`. `nm-cli` has `main.rs`.
- `[profile.release]`: `lto = "fat"`, `codegen-units = 1`, `strip = true`, `panic = "abort"` is **not** set (we want backtraces in bug reports), `opt-level = 3`.
**Accept:** `cargo build --workspace` succeeds on Windows and Linux. `cargo tree -i nm-creds` shows no path from `nm-ai` (trivially true now; the ban test in 00-06 makes it permanent).

### 00-03 `nm-core` domain types

**Where:** `crates/nm-core/src/{lib,ids,device,snapshot,facts,finding,error,time}.rs`.
**What:**

- `ids.rs`: newtype ULIDs via `ulid` crate: `DeviceId`, `SiteId`, `CredentialProfileId`, `SnapshotId`, `FindingId`, `AiSessionId`. Each derives `Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize`, implements `Display` and `FromStr`, and has `fn new() -> Self`.
- `device.rs`: `Device`, `ManagementAddress { host: HostOrIp, port: Option<u16> }`, `HostOrIp` enum, `Vendor`, `DeviceFamily`, `DeviceRole`, `EnrollmentSource` exactly as SPEC §5. `Device::is_enrolled()`. `DeviceFamily::default_port(&self) -> u16`.
- `facts.rs`: `DeviceFacts` and every sub-struct in SPEC §5, with every field `Option` or `Vec` so partial collection is representable without sentinels. Add `#[serde(default)]` on every struct. Add `pub struct RedactedConfig { pub format: ConfigFormat, pub text: String, pub secrets_removed: u32 }`.
- `snapshot.rs`: `Snapshot`, `DeviceResult`, `Outcome`, `RawArtifact { kind: ArtifactKind, name: String, bytes: Vec<u8>, sha256: [u8; 32], redacted: bool }`, `Coverage { expected: Vec<String>, collected: Vec<String>, missing: Vec<String> }`.
- `finding.rs`: `Finding`, `Severity` (ordered, `Ord` impl: Info < Low < Medium < High < Critical), `Category`, `Confidence`, `Evidence { device_id, metric_path: String, observed: serde_json::Value, threshold: Option<serde_json::Value> }`, `RuleId(String)` newtype with a validating constructor enforcing `^(UBNT|GEN)-(SEC|PERF|REL|CAP|HYG|RF)-\d{3}$`.
- `error.rs`: `NmError` enum with `thiserror`, variants for Store, Creds, Collect, Analyze, Ai, Io, Parse, with `#[from]` where unambiguous.
- `time.rs`: `Timestamp` wrapper over `time::OffsetDateTime` serialized as RFC 3339 UTC.
**Accept:** unit tests: id round-trip through string; `Severity` ordering; `RuleId` rejects `UBNT-FOO-001`; every facts struct deserializes from `{}`.

### 00-04 `nm-store` with migrations and repositories

**Where:** `crates/nm-store/src/{lib,db,migrations,repo/*}.rs`, `crates/nm-store/migrations/0001_initial.sql`.
**What:**

- `Db::open(path: &Path) -> Result<Db>` and `Db::open_in_memory()` for tests. Sets `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000`.
- `rusqlite_migration::Migrations` with `0001_initial.sql` creating every table in SPEC §14 plus indexes: `devices(address)`, `device_results(snapshot_id)`, `findings(snapshot_id, severity)`, `audit_log(ts)`.
- Data directory resolution in `paths.rs`: `%LOCALAPPDATA%\NetworkMaster` on Windows via `dirs::data_local_dir()`, `$XDG_DATA_HOME/networkmaster` elsewhere; override with `NETMASTER_DATA_DIR` env var (used by tests and CI).
- Repositories, each a struct borrowing `&Db` with plain functions, no ORM: `DeviceRepo` (insert, update, get, list with `DeviceFilter { site, family, enrolled, source }`, set_enrolled, delete), `SiteRepo`, `ProfileRepo` (metadata only), `SettingsRepo` (typed get/set via serde), `AuditRepo` (append, tail(n), query by time range), `SnapshotRepo` (create, finish, get, list, insert_device_result, insert_raw_artifact, insert_findings, latest_for_inventory_hash). Snapshot bodies store `facts_json` as serialized `DeviceFacts`.
- `AuditEvent { ts, actor: Actor, action: AuditAction, target: String, detail: serde_json::Value, bytes_out: u64, bytes_in: u64 }` where `AuditAction` is an enum: `SshConnect, SshCommand, HttpRequest, UdpProbe, AiRequest, AiToolCall, CredentialCreated, CredentialForgotten, ScanStarted, ScanFinished, DryRun, Export, McpServe`.
**Accept:** tests on in-memory DB: migrations apply from empty; applying twice is a no-op; CRUD round-trip for each repo; audit `tail(3)` returns newest first; `NETMASTER_DATA_DIR` is respected.

### 00-05 `nm-creds` session-only arena

**Where:** `crates/nm-creds/src/{lib,arena,profile,secret}.rs`.
**What:**

- `CredentialProfile { id, name, kind: CredentialKind, storage: StorageMode, scope_hint }` and `CredentialKind` enum: `SshPassword { username }`, `SshKey { username, has_passphrase }`, `ApiToken`, `HttpBasic { username }`, `SnmpV2c`, `SnmpV3 { username, auth_proto, priv_proto }`. Note: the enum carries *non-secret* parts only.
- `SecretMaterial` enum wrapping `secrecy::SecretString` / `SecretVec<u8>` per kind. `#[derive(Zeroize, ZeroizeOnDrop)]` where applicable.
- `CredArena` (`Arc<Mutex<HashMap<CredentialProfileId, SecretMaterial>>>`) with `insert`, `forget(id)`, `forget_all()`, `contains(id)`, and `with_secret<R>(&self, id, f: impl FnOnce(&SecretMaterial) -> R) -> Result<R, CredsError>`. There is intentionally **no** `get()` that returns an owned secret.
- `StorageMode::SessionOnly` is the only variant implemented now; `WindowsCredentialManager` variant exists in the enum and returns `CredsError::NotImplemented` (plan 05 fills it).
- `fingerprints(&self) -> Vec<SecretFingerprint>` returning hashed, base64, URL-encoded and hex forms of each secret for the scrubber in plan 03. Fingerprints are themselves `Zeroize`.
- `impl Drop for CredArena` zeroizes everything; a `ctrlc`-style handler is wired in `nm-cli` (00-10) so Ctrl+C still drops the arena.
**Accept:** tests: `with_secret` sees the value; `forget` then `with_secret` errors; `Debug` for `SecretMaterial` prints `[REDACTED]`; a test asserts `CredArena` does not implement `Serialize` (compile-fail test via `trybuild`).

### 00-06 `nm-collect` invariants: `Collector`, `TargetGate`, `SshCommand`, `NetFactory`

**Where:** `crates/nm-collect/src/{lib,collector,plan,gate,allowlist,net}.rs`, `deny.toml`.
**What:**

- `collector.rs`: the `Collector` trait from SPEC §8.1 with `async_trait`. `CollectCtx { gate: Arc<TargetGate>, creds: Arc<CredArena>, audit: AuditSink, cancel: CancellationToken, net: Arc<dyn NetFactory>, limits: Limits }`. `Limits { per_command_timeout: Duration, per_device_budget: Duration }`.
- `plan.rs`: `CollectionPlan(Vec<PlannedAction>)`, `PlannedAction { transport: Transport, target: ManagementAddress, action: Action }`, `Action` enum: `SshCommand(SshCommand)`, `HttpGet { path: String }`, `HttpLogin { endpoint: LoginEndpoint }`, `UdpProbe { port: u16 }`, `SnmpGet { oids: Vec<String> }`. `impl Display for CollectionPlan` renders the dry-run text.
- `allowlist.rs`:

  ```rust
  /// INVARIANT: every command in this file is read-only. See SPEC §1.3 N1 and §15.2.
  /// Adding a command requires: (1) it appears in a `const` below, (2) the forbidden-verb
  /// test passes, (3) a reviewer other than the author approves.
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
  pub struct SshCommand(&'static str);
  impl SshCommand { pub fn as_str(&self) -> &'static str { self.0 } }
  // Private constructor: only this module can make one.
  const fn cmd(s: &'static str) -> SshCommand { SshCommand(s) }
  pub mod airos { use super::*; pub const ALL: &[SshCommand] = &[]; }
  pub mod edgeos { use super::*; pub const ALL: &[SshCommand] = &[]; }
  pub fn all_families() -> impl Iterator<Item = (&'static str, &'static [SshCommand])> { ... }
  ```

  The field is private and the constructor is private, so transports can only ever run an allowlisted command. The lists are empty in M0 and filled in plans 01 and 02.
- `allowlist_test.rs` (in `tests/`): the forbidden-verb test from SPEC §15.2 iterating `all_families()`. It must pass on empty lists and must fail if someone adds `cmd("set system host-name x")` (prove this once with a temporary test and then remove it; record in the commit message).
- `gate.rs`: `TargetGate::new(enrolled: &[Device]) -> Self` resolves each hostname once via `tokio::net::lookup_host` and stores `HashSet<IpAddr>` plus `HashMap<IpAddr, DeviceId>`. `gate.check(ip) -> Result<DeviceId, GateError::NotEnrolled>`. Resolution failures are recorded per device and surfaced as `Outcome::Unreachable`.
- `net.rs`: `trait NetFactory { async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream>; async fn udp_bind(&self, bind: SocketAddr) -> io::Result<UdpSocket>; }` with `RealNet` (calls `gate.check` **before** connecting; UDP bind is allowed only on local interfaces) and `DenyAllNet` (always `PermissionDenied`) for tests. All transports in later plans take `Arc<dyn NetFactory>`; none call `TcpStream::connect` directly. A clippy-style check for this is a `grep` in CI (`! grep -rn "TcpStream::connect" crates/ --include=*.rs | grep -v net.rs`).
- `deny.toml` `[bans]`: `skip-tree` is not what we want; use `[[bans.deny]] name = "nm-creds" wrappers = ["nm-collect", "nm-app"]` so only those crates may depend on it. Verify `cargo deny check bans` fails if `nm-ai` adds the dependency (test once, revert).
**Accept:** forbidden-verb test passes; `cargo deny check bans` passes; a unit test shows `RealNet` refuses an IP not in the gate before any socket is opened.

### 00-07 `nm-app` service layer and job runner

**Where:** `crates/nm-app/src/{lib,service,jobs,events}.rs`.
**What:**

- `AppService { db: Db, creds: Arc<CredArena>, collectors: CollectorRegistry, jobs: JobRunner, settings: Settings }` constructed by `AppService::open(config: AppConfig)`.
- `CollectorRegistry` maps `DeviceFamily` → `Arc<dyn Collector>`; empty in M0.
- `JobRunner`: `spawn<J: Job>(&self, job: J) -> JobHandle` where `trait Job { async fn run(self, ctx: JobCtx) -> Result<JobOutcome>; }` and `JobCtx { cancel: CancellationToken, events: mpsc::Sender<JobEvent> }`. `JobHandle { id, cancel(), done: oneshot }`. Only one scan job may run at a time (`Mutex<Option<JobId>>`).
- `JobEvent` enum: `Started { total }`, `DeviceStarted(DeviceId)`, `DeviceFinished(DeviceId, Outcome)`, `Progress { done, total }`, `Log(String)`, `Finished(JobOutcome)`, `Cancelled`, `Failed(String)`.
- `AuditSink`: cloneable handle that writes `AuditEvent` through a bounded channel to a single writer task so audit writes never block collectors and are strictly ordered.
**Accept:** test: a `SleepJob` emits events, is cancelled mid-way, and the runner reports `Cancelled`; a second spawn while one runs returns `JobError::Busy`.

### 00-08 `nm-tui` shell: event loop, router, three screens, theme

**Where:** `crates/nm-tui/src/{lib,app,event,action,theme,widgets/*,screens/{dashboard,settings,help}}.rs`.
**What:**

- Elm-style: `App { screen: ScreenId, dashboard: DashboardState, settings: SettingsState, help: HelpState, status_line: String, modal: Option<Modal>, theme: Theme }`. `enum Action { Key(KeyEvent), Tick, Job(JobEvent), Navigate(ScreenId), Quit, ... }`. `fn update(app: &mut App, action: Action, svc: &AppService) -> Vec<Effect>` and `fn view(app: &App, frame: &mut Frame)`.
- Event loop in `run(svc: AppService) -> Result<()>`: `tokio::select!` over `crossterm::event::EventStream`, a 250 ms tick, and the job event channel. Terminal setup/teardown with a panic hook that restores the terminal before printing the panic (use `color-eyre` or a hand-rolled hook).
- Global keys: digits `0–9` switch screens, `?` help, `q` quit (with confirm modal when a job is active), `Ctrl+C` cancels active job then quits on second press.
- `theme.rs`: `Theme { bg, fg, accent, muted, severity: [Color; 5], border }` with `Theme::default_dark()`, `Theme::high_contrast()`, `Theme::no_color()`. Honor `NO_COLOR`.
- `widgets/`: `TitleBar`, `StatusLine`, `KeyHints`, `ConfirmModal`, `Table` wrapper with stable column widths.
- Dashboard shows: device counts by family and enrolled state (from `DeviceRepo`), last snapshot time ("never"), findings by severity (zeros), coverage ("—"), and three quick-action hints. Settings shows theme, data dir, version, and a read-only list of providers (empty). Help shows global keys.
- `--ascii` flag and auto-detection: on Windows, if `GetConsoleOutputCP() != 65001`, use ASCII borders.
**Accept:** `TestBackend` snapshot tests for each screen at 80×24 and 120×40 with `insta`; manual check on cmd, PowerShell 5, PowerShell 7, Windows Terminal, and `xterm` on Linux; resizing the window redraws without artifacts.

### 00-09 `nm-cli` command tree

**Where:** `crates/nm-cli/src/{main,cli,commands/*}.rs`.
**What:**

- `clap` derive matching SPEC §13 exactly, including subcommands that will be implemented later. Unimplemented ones print `not implemented yet (planned for M<n>)` and exit 2.
- Implemented now: `netmaster` (TUI), `netmaster inventory add|list|enroll`, `netmaster creds add` (session-only; prompts for secret with `rpassword`, or `--secret-from-stdin`), `netmaster audit tail`, `netmaster forget --all-credentials`, `netmaster --version`.
- Global flags: `--data-dir`, `--json` where applicable, `--ascii`, `--no-color`, `-v/-vv` for `tracing` level. `tracing` goes to stderr only, never to stdout, so `--json` output is clean.
- Exit codes documented in `docs/CLI.md`: 0 ok, 1 generic error, 2 not implemented / usage, 3 nothing to do, 4 partial failure (used by scan later), 130 interrupted.
- Ctrl+C handling: `tokio::signal::ctrl_c` drops `AppService` so `CredArena` zeroizes.
**Accept:** `netmaster inventory add 192.0.2.10 --family airos --name test && netmaster inventory list --json | jq '.[0].enrolled'` prints `false`; `netmaster inventory enroll <id>` flips it; `netmaster audit tail` shows the `CredentialCreated` event after `creds add`.

### 00-10 CI pipeline

**Where:** `.github/workflows/{ci,egress}.yml`, `scripts/check-no-direct-connect.sh`.
**What:**

- `ci.yml`: matrix `windows-latest`, `ubuntu-latest`; steps: checkout, `dtolnay/rust-toolchain` from `rust-toolchain.toml`, `Swatinem/rust-cache`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `scripts/check-no-direct-connect.sh`.
- `egress.yml` (Linux only): builds `netmaster`, then runs `unshare --user --map-root-user --net sh -c 'netmaster inventory list && netmaster audit tail'` and asserts exit 0. In M1+ this adds `netmaster scan --dry-run`. If `unshare` is unavailable on the runner, fall back to running tests with `NETMASTER_NET=deny`, which makes `AppService` construct `DenyAllNet`.
- Dependabot or Renovate for Cargo, weekly, grouped.
**Accept:** both workflows green on `main`.

### 00-11 Developer documentation

**Where:** `docs/{DEVELOPMENT,CLI,adr/*}.md`, `CONTRIBUTING.md`.
**What:** how to build on Windows (MSVC toolchain, no extra C deps thanks to rustls and bundled SQLite), how to run tests, how the crates relate (copy the diagram from SPEC §3.4), the invariants and where they are enforced, how to write an ADR, how to add a crate dependency (`cargo add --workspace` then `cargo deny check`).
**Accept:** a new contributor can go from clone to running TUI using only `DEVELOPMENT.md`.

---

## 3. Testing summary for this plan

| What | How |
|------|-----|
| Domain types | unit tests in `nm-core` |
| Store | in-memory SQLite tests per repo |
| Creds | arena tests, `trybuild` compile-fail for `Serialize` |
| Invariants | forbidden-verb test, `cargo deny` bans, grep for direct connects, `DenyAllNet` |
| TUI | `insta` snapshots via `TestBackend` |
| CLI | `assert_cmd` integration tests with a temp data dir |
| Egress | `unshare --net` workflow |

---

## 4. Risks specific to this plan

- **Windows console quirks.** Legacy conhost under PowerShell 5 sometimes leaves the cursor visible or misreports size. Test early on a real Windows 10 1809 VM, not only on Windows 11.
- **Over-designing `nm-core`.** Resist adding fields "for later." Every field must be used by plan 02 at the latest.
- **russh version churn.** Pin it in `workspace.dependencies` now even though it is unused until plan 01, so the lockfile is stable.

---

## 5. Done checklist

- [x] All eleven crates build; `nm-cli` produces `netmaster.exe`.
- [ ] TUI launches and quits cleanly on cmd, PowerShell 5, PowerShell 7, Windows Terminal, Linux xterm.
- [x] Inventory add/list/enroll and creds add work from the CLI.
- [x] Audit log records credential creation.
- [x] Forbidden-verb test, bans check, direct-connect grep, egress workflow all exist and pass locally (remote workflow run pending).
- [x] ADRs 0001–0003 written; `DEVELOPMENT.md` written.
- [x] `CHANGELOG.md` has an `Unreleased` section describing M0.

Implementation and local checks are recorded in [M0-VALIDATION.md](../M0-VALIDATION.md).
The complete native terminal matrix and green hosted workflows remain acceptance follow-ups;
cmd, PowerShell 5/7 in ConPTY and a Linux xterm-compatible PTY have passed locally.
