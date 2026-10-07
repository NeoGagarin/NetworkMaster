# airOS hardware validation

Date: 2026-10-06 (Asia/Manila)
Status: **Pending hardware access**, as requested. No real radios were contacted for this implementation.

The fixture directories `fixtures/airos/synthetic-xw-6.3.6` and `fixtures/airos/synthetic-wa-8.7.11` are synthetic examples of the specified output shapes. Their metadata explicitly says `synthetic = true`; they are parser/replay coverage and do not establish compatibility with those firmware versions. The three discovery replies are synthetic too.

| Bench target | Commands present/missing | Per-command duration | Total duration | CPU impact | UI agreement |
|---|---|---|---|---|---|
| airOS 6.x AP/station | Pending | Pending | Pending | Pending | Pending |
| airOS 8.x AP | Pending | Pending | Pending | Pending | Pending |
| Three enrolled stations | Pending | Pending | Pending | Pending | Pending |

To perform acceptance, add the bench management addresses as candidates, assign session SSH profiles and enroll only the intended targets. Set known station roles where available, so `wstalist` is skipped. Run `netmaster scan --dry-run --json`, inspect the plan, then `netmaster scan --json`. Legacy negotiation requires `inventory allow-legacy <device-id>` or the TUI modal's explicit acknowledgement. Never reset a pin merely to make a scan pass.

Host key pins are per device, not per key algorithm. If a radio negotiates one host key type on the first scan and another on a later scan, for example ed25519 and then ssh-rsa after the legacy opt-in, the second scan reports a changed key. Record on the bench whether any 8.x device does this; if so, the pin store needs per-algorithm records before 1.0.

Capture both actual firmware families using `netmaster fixture capture --device <id> --out <new-directory>`. Re-enter assigned session credentials when prompted; `--secret-from-stdin` is available for an operator-controlled pipeline. Review every artifact and `meta.toml` before committing. Record command exit status and `duration_ms` from `audit tail --json`, total device elapsed time, and the CPU graph observed in the radio UI. Compare chain RSSI and AP station lists with the UI within rounding. Mark missing `mca-dump` as partial rather than discarding the remaining facts. Record whether `wstalist` exceeds two seconds on a busy AP; add a skip setting if bench evidence requires it.

The local replay tests exercise modern and opted-in legacy SSH, authentication failure, key mismatch, timeouts, output truncation, parser fallbacks, audit parity and partial exit code 4. They cannot measure a real radio's CPU impact, actual command availability, or discovery behavior on an operator's network.

## M2 EdgeOS and analysis acceptance

Status: **Pending ER-X and real airOS access.** EdgeOS parser fixtures are synthetic
and do not verify the wrapper path or individual operational commands on hardware.

Enroll an ER-X as family edgeos and inspect its dry-run plan. Operational commands
use `/opt/vyatta/bin/vyatta-op-cmd-wrapper`; no interactive shell or aliases run.
Capture `show configuration commands` first. OSPF and BGP commands are skipped
when the parsed configuration lacks those protocols. Skipped commands remain in
expected coverage and are recorded separately from missing commands.

Validate each command listed in the EdgeOS allowlist on current 2.0.x firmware.
`show interfaces ethernet detail` is provisional: record its availability and
remove it from active collection if that firmware does not support it. Record any
different wrapper path here before introducing a fixed alternative; do not use
`vbash -ic`. Capture actual ER-X fixtures and an OSPF adjacency between two routers
if available. Review redaction and compare routes, interface negotiation, DHCP
counts, firewall counters and offload status with the UI.

Run `analyze`, review RF findings on the real airOS fleet, and compare the Topology
screen with the AP station list. Check inferred WAN interfaces; the Devices
Interfaces tab's `R` form records a persistent role override. Confirm valid
OSPF 2-Way adjacencies are understood before treating findings as faults.

For PERF-001, the operator may temporarily disable offload by hand in the web UI,
scan, confirm the finding, restore offload and scan again. Record the initial and
restored states and threshold tuning in ADR 0006. No bench action was performed
by this implementation.
