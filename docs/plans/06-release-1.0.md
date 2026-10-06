# Plan 06 — Release 1.0 (M6)

**Goal:** Turn a working tool into a product people can install, trust and keep using: snapshot diffing with trend-based rules, SNMP for EdgeSwitch, a maintained firmware table, visual polish, signed and reproducible releases, package-manager distribution, a hardware compatibility matrix, and a security pass. Lock the public plugin API.

**Exit criteria (SPEC §19, M6):** A signed 1.0 release on GitHub with Windows MSI and portable zip, Linux tarballs, SBOM and checksums. `winget install` works. `SECURITY.md`, `HARDWARE-TESTING.md` and the docs set are complete. Every non-negotiable in SPEC §1.3 has a named test.

**Depends on:** all previous plans.

---

## 1. Scope

In scope:
- Snapshot diffing engine, diff rules (GEN-REL-001 and friends), trend views, `netmaster diff`.
- SNMP transport (v2c, v3) GET/GETNEXT/GETBULK only; EdgeSwitch collector via IF-MIB and vendor MIB basics; generic SNMP facts for any Ubiquiti device with SNMP enabled.
- Firmware/EOL table maintenance workflow.
- TUI polish: themes, ASCII fallback audit, resize robustness, help overlays, first-run flow from SPEC §12.4.
- Packaging: `cargo-dist`, MSI, portable zip, Linux tarballs, SBOM, Sigstore, Authenticode path, winget, scoop.
- Security pass: fuzzing targets, `cargo-audit`, dependency review, threat model walkthrough, invariant test naming.
- Docs completion and 1.0 release checklist.
- Public API freeze: `Collector`, `Rule`, `Provider` traits and the MCP tool schemas.

Out of scope: new vendors, scheduled scans, web UI.

---

## 2. Tasks

### 06-01 Snapshot diffing engine
**Where:** `crates/nm-analyze/src/diff.rs`, `crates/nm-store/src/repo/snapshots.rs`.
**What:**
- `SnapshotDiff::compute(prev: &Snapshot, cur: &Snapshot) -> SnapshotDiff` with: `devices_added/removed`, `firmware_changes`, `outcome_changes` (ok→failed is itself notable), per-interface counter deltas normalized per hour (`rx_errors_per_h`, `tx_drops_per_h`, `bytes_per_h`), radio drift per device (`signal_delta_db`, `noise_delta_db`, `ccq_delta`, `chain_imbalance_delta`), station churn per AP (joined/left MACs), routing changes (OSPF neighbor set and state changes, route count delta), service changes (anything in `ServicesFacts` that flipped), config diff (unified diff of `RedactedConfig.text`, capped), findings `resolved/new/persisting` by `(rule_id, device set)`.
- Counter wrap handling: if `cur < prev` for a monotonic counter, treat as wrap or reboot (check uptime) and mark the delta `unreliable`.
- `SnapshotView.previous` is now populated with the most recent earlier snapshot sharing the same `inventory_hash`; if the inventory changed, `previous` is the most recent regardless but `inventory_changed = true` is set and diff rules downgrade confidence.
- `netmaster diff <a> <b> [--json|--md]` and a `Diff` tab in the Findings screen plus a `Trend` tab in Devices showing the last N snapshots' key metrics as sparklines (ratatui `Sparkline`).
**Accept:** unit tests with synthetic snapshot pairs incl. wrap/reboot; golden Markdown diff.

### 06-02 Diff and trend rules
**Where:** `crates/nm-analyze/src/rules/diff.rs`.
**What:**
| ID | Severity | Rule |
|----|----------|------|
| GEN-REL-001 | Medium | Interface error or drop rate increased above `errors_per_h` (default 100) between snapshots |
| GEN-REL-006 | Medium | Device reachable previously, unreachable now |
| GEN-REL-007 | Low | Device rebooted since last snapshot (uptime reset) more than once in 7 days across snapshots |
| UBNT-RF-015 | Medium | Signal degraded by more than 4 dB on a link with no TX power change |
| UBNT-RF-016 | Medium | Noise floor rose by more than 5 dB on a sector |
| UBNT-RF-017 | Low | Station churn above 30% on a sector between snapshots |
| GEN-HYG-007 | Info | Config changed since last snapshot (shows the redacted diff as evidence) |
| GEN-SEC-016 | High | A security-relevant service was enabled since last snapshot (telnet, http, snmp default, upnp, discovery on WAN) |
| GEN-REL-008 | High | OSPF neighbor present previously is missing now |
All `Confidence::Likely`, downgraded to `Heuristic` when `inventory_changed`.
**Accept:** positive/negative tests; `RULES.md` regenerated.

### 06-03 SNMP transport
**Where:** `crates/nm-collect/src/snmp/{mod,client,v3}.rs`.
**What:** Evaluate `snmp2` vs `async-snmp` (ADR 0009). Requirements: async over `ctx.net.udp_bind`, v2c and v3 (authPriv with SHA/AES at minimum), GET, GETNEXT, GETBULK, walk helper with OID subtree bound, timeouts and retries, no SET symbol anywhere (verify with a test that the public API has no `set` method; if the chosen crate exposes one, wrap it so ours does not). Community strings and v3 secrets via `with_secret`. Audit: `AuditEvent::SnmpRequest { device, pdu_type, oid_count }`.
**Accept:** tests against an in-process SNMP agent fixture (`snmpsim`-style replay implemented in Rust for the handful of OIDs we use); v3 auth failure test.

### 06-04 EdgeSwitch and generic SNMP collector
**Where:** `crates/nm-collect-ubiquiti/src/edgeswitch/*`, `crates/nm-collect-ubiquiti/src/snmp_generic.rs`.
**What:**
- `SnmpGenericCollector` for any family with SNMP enabled: `SNMPv2-MIB` (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysName`, `sysLocation`), `IF-MIB` `ifTable`/`ifXTable` (name, alias, type, speed/highSpeed, admin/oper, in/out octets 64-bit, errors, discards), `IP-MIB` `ipAddrTable`, `BRIDGE-MIB` `dot1dTpFdbTable` (MAC → port, capped), `LLDP-MIB` `lldpRemTable` if present. Merged into `DeviceFacts` with `source = "snmp"`; direct SSH/HTTP facts win on conflict.
- `EdgeSwitchCollector` = generic SNMP plus the EdgeSwitch private MIB basics that are stable (PoE per-port power and status from `POWER-ETHERNET-MIB`, CPU/memory if the private OIDs are confirmed on the bench). Rules: `UBNT-CAP-003` now evaluable on EdgeSwitch PoE budget; `GEN-REL-002` on duplex; `GEN-REL-001` on counters.
- Any enrolled device with an `SnmpV2c`/`SnmpV3` profile assigned gets the generic collector **in addition** to its primary collector, giving 64-bit counters even on airOS.
**Accept:** fixture tests; bench EdgeSwitch yields interface table and PoE facts.

### 06-05 Firmware and EOL table workflow
**Where:** `crates/nm-analyze/data/firmware.toml`, `scripts/firmware-table/`, `docs/FIRMWARE-TABLE.md`.
**What:** Schema: `[[entry]] family, platform (airOS XW/XC/WA/..., EdgeOS model class, UniFi model), current, minimum_recommended, eol, notes, source_url, checked`. A maintainer script (no runtime fetch; N5) that pulls Ubiquiti's release feeds and proposes a diff for human review. `netmaster firmware-table show|check-staleness` (warns in the Dashboard if the bundled table is older than 120 days, with instructions to update NetworkMaster, never to fetch). Users may override with a local `firmware.toml`.
**Accept:** table validates on load; staleness warning renders; script documented.

### 06-06 First-run flow and TUI polish
**Where:** `crates/nm-tui/src/screens/firstrun/*`, theme and widget fixes.
**What:** Implement SPEC §12.4 onboarding as a skippable wizard: profile (operator/learner → sets teach mode and default redaction), the "what this tool will never do" page with the six non-negotiables, attestation checkbox "I administer the devices I will enroll", first device or controller import, credential profile, dry run, scan. Polish: theme switcher live preview; `--ascii` audit on every screen under code page 437 and 850; resize storm test (rapid resizes do not panic); help overlay per screen (`?` shows screen-specific keys over the current view); consistent empty states with the next action named; toasts for background completions.
**Accept:** snapshot tests for the wizard; manual run on cmd with `chcp 437`; fuzz-ish resize test.

### 06-07 Packaging and signing
**Where:** `dist-workspace.toml`, `.github/workflows/release.yml`, `packaging/{winget,scoop}/`.
**What:**
- `cargo-dist` targets: `x86_64-pc-windows-msvc` (MSI via WiX and portable zip), `aarch64-pc-windows-msvc` (zip), `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` (tar.xz). Installer: per-user by default, adds to `PATH`, Start menu shortcut launching Windows Terminal if present else conhost; no services, no scheduled tasks, no telemetry consent screen because there is nothing to consent to.
- SBOM (`cargo cyclonedx`) attached to each release; `SHA256SUMS` and Sigstore `cosign` signatures via GitHub OIDC; provenance attestation with `actions/attest-build-provenance`.
- Authenticode: apply to SignPath Foundation (or equivalent) for open-source signing; until approved, release notes explain the SmartScreen warning and how to verify checksums and Sigstore signatures. Track in an issue; do not ship 1.0 blocked on it.
- Reproducibility: `rust-toolchain.toml` pinned, `Cargo.lock` committed, `SOURCE_DATE_EPOCH` from the tag's commit time, `--remap-path-prefix`; a CI job builds twice and compares hashes.
- `winget` manifest PR to `microsoft/winget-pkgs` via `wingetcreate`; `scoop` manifest in a project bucket. Both automated in `release.yml` on tag.
- Version scheme: semver; 1.0.0 tag; `netmaster --version` prints version, commit, build date, target.
**Accept:** a `v1.0.0-rc.1` pre-release exercises the whole pipeline; reproducible-build job passes; `winget install <publisher>.NetworkMaster` works on a clean VM.

### 06-08 Security pass
**Where:** `fuzz/`, `.github/workflows/security.yml`, `docs/SECURITY.md`, `docs/THREAT-MODEL.md`.
**What:**
- `cargo-fuzz` targets for every parser entry point (airOS, EdgeOS, discovery TLV, UISP/UniFi JSON mappers, SNMP decode, SSE parsers) running nightly for 10 minutes each with corpus from fixtures.
- `cargo-audit` and `cargo-deny advisories` on every PR and nightly.
- Invariant test naming: each SPEC §1.3 rule has at least one test whose name starts with `invariant_n1_` … `invariant_n6_`; CI asserts all six prefixes exist (`cargo test -- --list | grep`). Examples: `invariant_n1_no_mutating_verbs_in_allowlist`, `invariant_n1_http_has_no_write_methods`, `invariant_n2_gate_blocks_unenrolled_ip`, `invariant_n3_scrubber_blocks_planted_secret`, `invariant_n3_nm_ai_has_no_creds_dependency`, `invariant_n4_every_transport_writes_audit`, `invariant_n5_dry_run_and_analyze_succeed_without_network`, `invariant_n6_device_strings_never_in_system_prompt`.
- `THREAT-MODEL.md`: SPEC §15.1 expanded with per-threat test references.
- A self-review pass over `unsafe` (should be none outside `nm-creds` zeroize glue), over every `expect`/`unwrap` in non-test code (replace with errors), and over panics reachable from device input (fuzzing should find these first).
- Memory hygiene check: run the TUI under a debugger, create a credential, forget it, dump process memory, grep for the secret (manual, documented procedure in `SECURITY.md`; expect zero hits).
**Accept:** fuzzers run clean for the nightly window; invariant prefix check in CI; manual memory check recorded.

### 06-09 Public API freeze
**Where:** `crates/{nm-collect,nm-analyze,nm-ai}/src/lib.rs`, `docs/PLUGIN-API.md`, `docs/MCP-TOOLS.md`.
**What:** Mark `Collector`, `Rule`, `RuleMeta`, `Provider`, `SnapshotView`, `DeviceFacts` and the MCP tool schemas as stable with `#[doc = "Stable since 1.0"]`. Add `cargo-semver-checks` to CI for those crates. `PLUGIN-API.md`: how to add a vendor collector (trait, allowlist procedure, fixtures, parsers, registration) and a rule (trait, catalog, tests, explanation style). `MCP-TOOLS.md`: every tool, its schema, an example response (redacted), and the compatibility promise.
**Accept:** `cargo semver-checks` passes against the rc tag; a contributor can add a trivial rule following the doc alone.

### 06-10 Documentation set and release checklist
**Where:** `README.md`, `docs/*`, `CHANGELOG.md`, `.github/ISSUE_TEMPLATE/*`, `.github/release-checklist.md`.
**What:** README: 60-second pitch, screenshot/asciinema of a scan and a report, install (winget/scoop/zip), five-minute start, the six non-negotiables, link to docs. Docs index. Issue templates: bug, hardware report, bad recommendation, rule proposal, vendor request. Release checklist: all CI green, fuzz nightly clean, `RULES.md`/schema/`MCP-TOOLS.md` current, `CHANGELOG` finalized, hardware matrix updated, rc tested on Windows 10 1809 VM and Windows 11 and Ubuntu LTS, memory check done, tag, verify artifacts and signatures, publish winget/scoop, announce.
**Accept:** checklist executed for `v1.0.0`.

### 06-11 Hardware compatibility matrix
**Where:** `docs/HARDWARE-TESTING.md` → `docs/COMPATIBILITY.md`.
**What:** Table per model/firmware: collection method, commands available, time per device, known quirks, who tested and when. Seeded from the bench; grown via the hardware-report issue template. Linked from the Dashboard's "Report compatibility" hint.
**Accept:** matrix covers every bench device and at least the common airMAX models by family.

---

## 3. Testing summary

| What | How |
|------|-----|
| Diff engine | synthetic pairs, wrap/reboot cases, golden Markdown |
| Diff rules | positive/negative |
| SNMP | in-process agent replay; no-SET API test |
| EdgeSwitch | fixtures, bench |
| First-run | snapshots |
| Packaging | rc pipeline, reproducible-build job, clean-VM install |
| Security | fuzz nightly, audit, invariant prefix check, manual memory check |
| API freeze | `cargo-semver-checks` |

---

## 4. Risks specific to this plan

- **Code signing lead time.** Start the SignPath (or alternative) application at the beginning of this plan, not the end.
- **winget review delays.** Submit the manifest with the rc; expect days to weeks.
- **SNMP crate maturity.** If neither candidate meets the bar, implement the minimal BER/SNMP subset in-house (GET/GETNEXT/GETBULK over v2c is small; v3 is not). Decide in ADR 0009 within the first week; v3 may slip to 1.1 with v2c shipping in 1.0.
- **Scope pressure before 1.0.** Anything not in this plan goes to the post-1.0 backlog. The release checklist is the gate, not a feature list.

---

## 5. Done checklist

- [ ] Diff engine and nine diff rules shipped; Trend tab works.
- [ ] SNMP transport (at least v2c) and EdgeSwitch collector shipped; no SET exists.
- [ ] Firmware table workflow and staleness warning in place.
- [ ] First-run wizard, themes, ASCII fallback, resize robustness done.
- [ ] Signed, reproducible, SBOM-attached `v1.0.0` release; winget and scoop published.
- [ ] Six invariant test prefixes enforced in CI; fuzzers nightly; `THREAT-MODEL.md` written.
- [ ] Public API frozen with `cargo-semver-checks`; `PLUGIN-API.md` and `MCP-TOOLS.md` written.
- [ ] README, docs index, issue templates, compatibility matrix complete.
- [ ] Post-1.0 backlog opened with MikroTik, Cambium, Cisco, generic SNMP-only vendors, scheduled snapshots.
