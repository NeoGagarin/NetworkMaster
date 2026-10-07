# Plan 01 — airOS Collection (M1)

**Goal:** Enroll real airMAX, airFiber and LTU radios by hand, by CSV, or by Layer 2 discovery; connect over SSH with host-key pinning and an explicit legacy-algorithm opt-in; run the airOS allowlist; parse the output into `DeviceFacts`; show a dry run before the real scan; render devices in the TUI. First real network traffic in the project.

**Exit criteria (SPEC §19, M1):** Scan a real airMAX AP and at least three stations. Facts render in the Devices screen. The dry-run plan matches the audit log of the real run line for line. Fixtures for at least one airOS 6.x and one airOS 8.x device are committed.

**Depends on:** Plan 00.
**Produces for later plans:** SSH transport, UDP discovery, the Inventory, Scan and Devices screens, the fixture-capture tool, the first filled allowlist, `Partial` outcome handling, per-site concurrency.

---

## 1. Scope

In scope:

- Inventory screen with manual add, CSV import, candidate/enrolled distinction, multi-select, bulk profile assignment, sites.
- Ubiquiti discovery over UDP 10001.
- SSH transport on `russh` with pinning, legacy algorithms per device, per-command timeouts, sequential commands per device, bounded concurrency per site and globally.
- airOS collector: plan, collect, parse, coverage.
- Fixture capture command with scrubbing.
- Dry-run view, Scan screen with live progress and cancel, Devices screen with detail panes.
- `netmaster scan`, `netmaster scan --dry-run`, `netmaster inventory discover|import`, `netmaster fixture capture`.

Out of scope: rules, findings, HTTP collection for airOS (deferred; SSH is primary), EdgeOS, any AI.

---

## 2. Tasks

### 01-01 Inventory domain operations in `nm-app`

**Where:** `crates/nm-app/src/inventory.rs`.
**What:**

- `InventoryService` over `DeviceRepo`/`SiteRepo`: `add_manual(addr, family, name, site)`, `import_csv(reader) -> ImportReport { added, skipped_duplicates, errors: Vec<(line, reason)> }`, `enroll(ids)`, `unenroll(ids)`, `assign_profile(ids, profile_id)`, `set_site(ids, site_id)`, `remove(ids)`, `inventory_hash() -> [u8; 32]` (sha256 over sorted enrolled device ids and addresses; stored on snapshots so diffs know whether inventories match).
- CSV format per SPEC §6.2: header `address,name,family,site`; `family` values `airos|edgeos|edgeswitch|unifi|uisp|auto`; `site` auto-creates the site if missing. Duplicate detection by `(address, port)`.
- `HostOrIp` parsing accepts `host`, `host:port`, `ip`, `ip:port`, `[v6]:port`.
**Accept:** unit tests for CSV happy path, duplicate, bad family, missing header; `inventory_hash` is stable across row order.

### 01-02 Ubiquiti discovery (UDP 10001)

**Where:** `crates/nm-collect-ubiquiti/src/discovery.rs`, `crates/nm-collect/src/net.rs` (local interface enumeration).
**What:**

- `list_local_interfaces() -> Vec<LocalIface { name, ipv4, broadcast }>` using the `if-addrs` crate (or `network-interface`). Loopback excluded.
- `discover(net, iface, window: Duration) -> Vec<DiscoveredDevice>`: bind UDP on `iface.ipv4:0` with `SO_BROADCAST`, send the 4-byte probe `01 00 00 00` to `255.255.255.255:10001` **and** to the subnet broadcast address, listen for `window` (default 3 s), parse replies.
- Reply parser (`discovery/parse.rs`): version byte, command byte, length, then TLVs. Known tags to decode: `0x01` MAC+IP pair (10 bytes), `0x02` MAC+IP (alternate), `0x03` firmware string, `0x0A` uptime (u32), `0x0B` hostname, `0x0C` short model, `0x0D` ESSID, `0x0E` wmode, `0x14` model/full name. Unknown tags are kept raw. Parsing is pure; fixture the raw bytes of at least three device replies.
- `DiscoveredDevice { mac, ip, hostname, model, firmware, essid, raw_tags }` → converted to candidate `Device` with `source = Discovery`, `family` guessed from firmware prefix (`XW`, `XC`, `WA`, `XM`, `TI`, `AF`, `LTU` → `AirOs`; `ER-`, `EdgeRouter` → `EdgeOs`; `US-`, `ES-` → `EdgeSwitch`/UniFi), otherwise `Unknown`.
- Audit: one `UdpProbe` event per probe sent, with the interface name.
- TUI: Inventory screen → `d` opens a modal to pick the interface, runs discovery with a spinner, then shows candidates with checkboxes. Nothing is enrolled until the user confirms.
**Accept:** fixture tests for reply parsing; on a bench segment with two radios, both appear as candidates; running it on a segment with discovery disabled shows "no replies — many operators disable UBNT discovery" and no error.

### 01-03 SSH transport on `russh`

**Where:** `crates/nm-collect/src/ssh/{mod,client,hostkeys,algos,runner}.rs`.
**What:**

- `SshTransport::connect(ctx, device, profile) -> Result<SshSession>`. Uses `ctx.net.tcp_connect` (so `TargetGate` applies), then `russh::client::connect_stream`.
- `Handler` implementation whose `check_server_key` consults `HostKeyStore` (backed by `ssh_host_keys` table): unknown → record and accept (pin-on-first-use, logged as `SshConnect { first_seen: true }`); known and matching → accept; mismatch → `SshError::HostKeyChanged { expected, got }` and the device is marked `Outcome::Unreachable` with that reason. A fact `system.ssh_host_key_changed = true` is recorded for plan 02's rule.
- Auth: password, or key (`russh_keys::load_secret_key`), from the `CredArena` through `with_secret`. The password never leaves the closure except into `russh`'s authenticate call.
- `algos.rs`: `Preferred::DEFAULT` first; if the server's KEX or host-key algorithm list contains only legacy entries, surface `SshError::LegacyAlgorithmsRequired(Vec<String>)`. The device record gets a `ssh_legacy_ok: bool` flag the user can set (TUI modal: "This device only offers deprecated SSH algorithms (dh-group1-sha1, ssh-rsa). Allow for this device? [y/N]"). When allowed, reconnect with a `Preferred` that includes `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `ssh-rsa`, `aes128-cbc`, `3des-cbc`, `hmac-sha1`. Record `system.ssh_legacy_algorithms = true` as a fact.
- `runner.rs`: `run(&mut self, cmd: SshCommand) -> Result<CommandOutput { stdout: Vec<u8>, stderr: Vec<u8>, exit: Option<u32>, duration }>`. Opens a new channel per command (`channel_open_session` → `exec`), reads to EOF, applies `per_command_timeout`, caps output at 4 MiB (anything larger is truncated and flagged). Commands run **sequentially** per device. Every command writes an `AuditEvent::SshCommand { device, command, exit, bytes_in, duration }`.
- `SshCommand` is the only type `run` accepts. There is no `run_raw`. A doc test demonstrates that constructing `SshCommand` outside the allowlist does not compile.
**Accept:** integration test against an in-process `russh` server (in `crates/nm-collect/tests/ssh_server.rs`) that replays fixture outputs keyed by command string: connect, auth, run three commands, verify audit events; host-key mismatch test; timeout test; legacy-algorithm test where the fake server advertises only `ssh-rsa`.

### 01-04 Concurrency and scheduling

**Where:** `crates/nm-app/src/scan.rs`.
**What:**

- `ScanJob { devices: Vec<Device>, dry_run: bool }` implementing `Job`.
- Scheduling: a global `Semaphore(settings.max_concurrent_devices, default 8)` and a per-site `Semaphore(settings.max_concurrent_per_site, default 2)`. Devices with no site share a virtual site. Order: controllers first (none yet), then routers, then APs, then stations, so topology-relevant data lands early if the user cancels.
- Per-device budget via `tokio::time::timeout(limits.per_device_budget)`; on expiry the device result is `Partial` with what was collected so far.
- Dry run: calls `collector.plan(device)` for each device, writes `AuditEvent::DryRun` entries with the rendered plan, emits them as `JobEvent::Log` lines, never constructs a transport.
- At job end: `SnapshotRepo::finish` with `inventory_hash`; `JobOutcome::Scan { snapshot_id, ok, partial, failed }`. CLI exit code 0 if all ok, 4 if any partial/failed.
**Accept:** test with a `FakeCollector` that sleeps: with 10 devices across 2 sites and per-site limit 2, at most 4 run concurrently (assert via an atomic high-water mark); cancellation mid-run yields a snapshot with the finished devices and `Cancelled` outcome for the rest.

### 01-05 airOS allowlist

**Where:** `crates/nm-collect/src/allowlist.rs` (`pub mod airos`).
**What:** Fill `airos::ALL` with the SPEC §8.3 list, as named consts so collectors reference `airos::MCA_STATUS` rather than indices:

```text
VERSION        cat /etc/version
BOARD_INFO     cat /etc/board.info
UPTIME         uptime
FREE           free
LOADAVG        cat /proc/loadavg
MCA_STATUS     mca-status
MCA_DUMP       mca-dump
WSTALIST       wstalist
IWCONFIG       iwconfig
IFCONFIG       ifconfig
NET_DEV        cat /proc/net/dev
SYSTEM_CFG     cat /tmp/system.cfg
BRCTL          brctl show
ARP            cat /proc/net/arp
```

Validate each on the bench against airOS 6.x and 8.x and record which are missing on which firmware in `docs/HARDWARE-TESTING.md`. If `mca-dump` is absent on 6.x, keep it in the list (the collector handles `Partial`) but order it after `mca-status`.
**Accept:** forbidden-verb test still passes; `netmaster scan --dry-run` prints the fourteen commands per airOS device.

### 01-06 airOS collector and parsers

**Where:** `crates/nm-collect-ubiquiti/src/airos/{mod,collector,parse/{mca_status,mca_dump,wstalist,system_cfg,iwconfig,ifconfig,proc_net_dev,arp,board_info,version}}.rs`.
**What:**

- `AirOsCollector::plan` returns the allowlist in a fixed order with `WSTALIST` only when the device's role is `Ap` or unknown (stations return an empty list anyway; skipping saves time on 32 MB radios).
- `collect`: connect, run commands in order, store each raw output as a `RawArtifact` (after `scrub_secrets` from 01-07), parse, merge into `DeviceFacts`, compute `Coverage`. Any single command failure is recorded in `Coverage.missing` and `Outcome::Partial`; auth failure is `Outcome::AuthFailed`; connection failure is `Outcome::Unreachable`.
- Parsers (pure, `&[u8] -> Result<X, ParseError>`), each fixture-tested:
  - `version`: `XW.ar934x.v6.3.6.33347.200602.1140` → `{ platform: "XW", soc: "ar934x", version: "6.3.6", build: "33347" }`.
  - `board_info`: `board.sysid`, `board.name`, `board.shortname`, `board.hwaddr`, `board.subtype`.
  - `mca_status`: first line is comma-separated `key=value`, remaining lines are `key=value`. Extract `deviceName`, `firmwareVersion`, `uptime`, `wlanOpmode`, `ssid`, `freq`, `chanbw`, `signal`, `noise`, `ccq`, `txrate`, `rxrate`, `chainrssi` variants, `wlanTxRate`/`wlanRxRate`, `lanSpeed`/`lanPlugged`, `loadavg`, `memTotal`/`memFree`. Treat every key as optional; keep a `BTreeMap<String,String>` of everything seen for drill-down.
  - `mca_dump`: JSON. Map `host.{hostname,uptime,fwversion,devmodel,netrole,loadavg,totalram,freeram,cpuload}`, `wireless.{mode,essid,frequency,chwidth,txpower,signal,noisef,ccq,txrate,rxrate,chainrssi[],distance,polling.{enabled,quality,capacity,priority}}`, `interfaces[].{ifname,hwaddr,enabled,status.{plugged,speed,duplex,tx_bytes,rx_bytes,tx_errors,rx_errors,tx_dropped,rx_dropped}}`, `services.{dhcpc,dhcpd,pppoe}`, `firewall.*`, `genuine`. Unknown fields ignored via `#[serde(flatten)] extra: Map`.
  - `wstalist`: JSON array. Map `mac`, `name`, `signal`, `noisefloor`, `ccq`, `tx`, `rx`, `chainrssi[]`, `distance`, `uptime`, `airmax.{quality,capacity,priority}`, `remote.{hostname,platform,version,signal,noisefloor,tx_power,rx_chainmask}`, `stats.{rx_bytes,tx_bytes,...}`. Becomes `RadioFacts.stations`.
  - `system_cfg`: `key=value` lines. Extract service flags: `sshd.status`, `telnetd.status`, `httpd.status`, `httpd.https.status`, `httpd.port`, `snmp.status`, `snmp.community` (**presence and is-default only; value replaced**), `discovery.status`, `ntpclient.status`, `ntpclient.1.server`, `upnpd.status`, `netmode`, `wireless.1.{ssid,security,hide_ssid}`, `radio.1.{freq,chanbw,txpower,countrycode,obey}`, `users.1.name` (value kept; it is a username), `users.1.password` (**removed**), `resolv.host.1.name`, `netconf.N.{devname,ip,netmask,status}`, `route.N.*`. Output is `RedactedConfig` plus a typed `ServicesFacts`.
  - `iwconfig`: fallback for frequency, bitrate, signal when `mca-dump` is missing.
  - `ifconfig` + `proc_net_dev`: interface names, MACs, up/down, byte and error counters.
  - `arp`: `NeighborFacts::Arp { ip, mac, iface }`.
- Merge precedence: `mca_dump` > `mca_status` > `iwconfig`/`ifconfig` for overlapping fields. Record which source each top-level section came from in `Coverage`.
**Accept:** `insta` golden tests for every parser on every fixture; a merged `DeviceFacts` golden per fixture device; bench scan of one AP and three stations produces `Outcome::Ok` on 8.x and `Ok` or `Partial(mca-dump)` on 6.x.

### 01-07 Secret scrubbing at parse time and fixture capture

**Where:** `crates/nm-collect/src/scrub.rs`, `crates/nm-cli/src/commands/fixture.rs`.
**What:**

- `scrub_secrets(family, artifact_name, bytes) -> (Vec<u8>, u32 removed)`: per-family regex set. airOS: `^users\.\d+\.password=.*$` → `users.N.password=<redacted>`, `^snmp\.community=.*$` → `snmp.community=<redacted>`, `^wireless\.\d+\.(wpa\.psk|wep\.key\.\d+|wpa\.1x\..*password)=.*$`, `^pwd\.?.*=`, `^ntpclient\..*\.password=`. Also any value that looks like an `$1$`/`$5$`/`$6$` crypt hash anywhere. Applied to **every** raw artifact before it is stored, not only `system.cfg`.
- `netmaster fixture capture --device <id> --out fixtures/airos/<model>-<fw>/`: runs the collector, writes one file per command named after the const (`mca-status.txt`, `mca-dump.json`, ...), applies `scrub_secrets`, then applies a fixture-only tokenizer that rewrites IPs to `192.0.2.x`/`198.51.100.x` (RFC 5737 documentation ranges), MACs to `02:00:00:xx:xx:xx` with consistent mapping, hostnames to `fixture-host-N`, SSIDs to `fixture-ssid-N`. Writes `meta.toml` with model, firmware, role, capture date, and `partial: [..]`. Prints a reminder to eyeball the files before committing.
**Accept:** tests with planted secrets in each pattern; a captured fixture directory contains no RFC 1918 addresses and no real MACs (`grep` assertions in the test).

### 01-08 Inventory screen

**Where:** `crates/nm-tui/src/screens/inventory/*`.
**What:**

- Table columns: `✓` (enrolled), name, address, family, role, site, profile, source. Sort by any column with `s`. Filter with `/` (substring over name, address, site). `Space` toggles selection, `a` selects all visible, `Esc` clears selection.
- Actions on selection: `e` enroll, `u` unenroll, `p` assign profile (picker modal listing profiles), `t` set site (picker with "new site…"), `x` remove (confirm modal).
- `n` add manual (form modal: address, family dropdown, name, site). `i` import CSV (file path input; shows `ImportReport`). `d` discovery (01-02).
- Candidates render dimmed; enrolled render normal. Status line shows "N enrolled / M candidates".
**Accept:** `TestBackend` snapshots with a seeded inventory; keyboard-only completion of: add → assign profile → enroll.

### 01-09 Credentials screen

**Where:** `crates/nm-tui/src/screens/credentials/*`.
**What:** list profiles with name, kind, storage mode, device count; `n` new (form: name, kind, username, secret with masked input, storage mode locked to Session-only with a note "persistent storage arrives in M5"); `f` forget (zeroizes, unassigns from devices, confirm modal); `Enter` shows devices using the profile. Secrets are never displayed after entry, not even masked length.
**Accept:** snapshot tests; after `f`, `CredArena::contains` is false and devices show `—` for profile.

### 01-10 Scan screen with dry run

**Where:** `crates/nm-tui/src/screens/scan/*`.
**What:**

- Top pane: scope selector (all enrolled / by site / by family / selection from Inventory), concurrency settings (global, per-site), legacy SSH policy reminder.
- `r` dry run: renders the full `CollectionPlan` for every device in a scrollable pane, grouped by device, with counts ("14 SSH commands × 23 devices, 0 HTTP, 0 UDP"). `Enter` on a device expands its commands.
- `s` start scan: confirm modal restating "read-only; N devices; commands shown in dry run". Progress table: device, state (queued / connecting / running `<cmd>` / done / partial / failed), elapsed. Footer: done/total, ETA, `c` to cancel. On completion, `Enter` jumps to the Devices screen for the new snapshot.
- Legacy-algorithm prompt surfaces here as a modal when a device needs it; "allow for this device" persists `ssh_legacy_ok`.
**Accept:** snapshot tests with a `FakeCollector`; bench run shows live per-device state; cancel leaves a usable partial snapshot; dry-run text equals the audit log's `SshCommand` sequence for the real run (automated check in `netmaster scan --dry-run --json` vs `netmaster audit tail --json` in an integration test using the fake SSH server).

### 01-11 Devices screen

**Where:** `crates/nm-tui/src/screens/devices/*`.
**What:**

- Left: device list for the selected snapshot (default latest), with outcome glyph and coverage percentage. Right: tabbed detail: `System` (model, firmware, uptime, load, memory, services table with enabled/disabled), `Interfaces` (table with speed, duplex, counters, errors), `Radio` (mode, SSID, freq, width, TX power, noise, per-chain RSSI as a small bar, CCQ, airtime, rates, airMAX quality/capacity; on APs a stations table), `Config` (redacted text, scrollable, `/` search), `Raw` (list of artifacts; `Enter` views one), `Coverage` (expected vs collected vs missing).
- Snapshot picker with `[`/`]` to step between snapshots.
**Accept:** snapshot tests from fixture-derived facts; bench verification that chain RSSI and station lists match the radio's web UI within rounding.

### 01-12 CLI parity

**Where:** `crates/nm-cli/src/commands/{inventory,scan,fixture}.rs`.
**What:** `inventory import --file`, `inventory discover --interface <name> [--json]`, `scan [--dry-run] [--site] [--family] [--concurrency] [--per-site] [--json]`, `fixture capture`. `--json` emits one JSON object per line for progress (NDJSON) and a final summary object.
**Accept:** `assert_cmd` tests against the fake SSH server; exit code 4 on a partial scan.

### 01-13 Hardware validation and docs

**Where:** `docs/HARDWARE-TESTING.md`, `docs/NETWORK-FOOTPRINT.md`, `fixtures/airos/*`.
**What:** Record per model and firmware: which commands exist, time per command, total per-device time, CPU impact observed on the radio's web UI during collection. Document the exact traffic footprint: one TCP/22 session per device, N exec channels, one UDP broadcast per discovery run. Commit at least two scrubbed fixture sets.
**Accept:** the documents exist and match what the bench showed; an issue template `hardware-report.yml` asks for model, firmware, and `netmaster scan --json` output.

---

## 3. Testing summary

| What | How |
|------|-----|
| Discovery parser | raw-bytes fixtures |
| SSH transport | in-process `russh` server replaying fixtures; host-key, timeout, legacy-algo cases |
| Scheduling | `FakeCollector` with high-water-mark assertions |
| Parsers | `insta` goldens per fixture |
| Scrubber | planted-secret tests, grep assertions on captured fixtures |
| TUI | `TestBackend` snapshots |
| Dry run == real | integration test comparing plan output and audit log |
| Egress workflow | now also runs `netmaster scan --dry-run` in the no-network namespace |

---

## 4. Risks specific to this plan

- **`russh` legacy algorithm support.** Confirm early (first day) that `russh` can negotiate `diffie-hellman-group1-sha1` and `ssh-rsa` with an airOS 6.x radio. If it cannot, the fallback is spawning the system `ssh.exe` (Windows 10+ ships OpenSSH) with an explicit `-oKexAlgorithms=+...` and the same allowlist; write an ADR either way.
- **Output format drift across airOS versions.** `mca-status` keys differ between XM/XW/XC/WA platforms. The `BTreeMap` of all keys plus per-platform fixtures keeps this manageable. Never fail a parse because of an unknown key.
- **Radio load.** Watch the AP's CPU graph during a scan. If `wstalist` on an AP with 60 stations takes more than two seconds, add a settings knob to skip it on heavily loaded sectors.

---

## 5. Implementation status (2026-10-06)

The user requested completion of implementation and local tests while leaving hardware validation pending. Tasks 01-01 through 01-12 are implemented and locally exercised. Task 01-13 has documentation, a hardware-report template and two explicitly synthetic fixture sets; real captures and bench measurements remain pending. See [M1-VALIDATION.md](../M1-VALIDATION.md) for local evidence and [HARDWARE-TESTING.md](../HARDWARE-TESTING.md) for the outstanding bench matrix. The milestone's real-hardware exit criteria have not been met.

## 6. Done checklist

- [ ] Discovery finds bench radios; nothing is enrolled without a tick.
- [x] Replay SSH verifies pinning, explicit legacy negotiation and changed-key rejection; TUI provides the per-device prompt.
- [x] All fourteen commands are planned, replayed and parsed locally; partial results survive failures, budgets and cancellation.
- [x] CLI replay integration verifies dry-run commands equal the real-run audit sequence.
- [x] Inventory, Credentials, Scan and Devices screens implemented and snapshot-tested at both supported sizes.
- [x] Two synthetic fixture sets added and hardware/traffic documents written.
- [ ] Capture and commit two scrubbed real-device fixture sets during hardware acceptance.
- [x] Egress workflow includes an enrolled hostname dry run in the isolated namespace and deny-all fallback.
- [x] Continue in Rust; decision recorded in ADR 0004, with hardware compatibility pending.
