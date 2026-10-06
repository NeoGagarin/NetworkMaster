# Plan 02 — EdgeOS Collection and Rules Engine (M2)

**Goal:** Collect from EdgeRouters over SSH, build the deterministic analysis engine, implement the initial rule catalog, show findings in the TUI, produce a Markdown report with no AI involved, and infer a first topology. At the end of this plan the tool is already useful without any model.

**Exit criteria (SPEC §19, M2):** Findings produced on a real ER-X plus the airOS fleet from plan 01. `docs/RULES.md` is generated from the catalog in CI and the build fails if it is stale.

**Depends on:** Plan 01.
**Produces for later plans:** `SnapshotView`, the `Rule` trait and catalog, `Finding` persistence, the Findings screen, the report renderer, topology graph, platform capability table (used by the AI system prompt in plan 03).

---

## 1. Scope

In scope:
- EdgeOS allowlist, collector, parsers (including a config-tree parser for `show configuration commands`).
- `nm-analyze`: `SnapshotView`, `Rule` trait, `RuleMeta`, thresholds config, catalog registry, evaluation runner, `RULES.md` generator.
- All SPEC §9.3 rules that do not need a second snapshot (diff rules land in plan 06).
- Findings screen, `netmaster analyze`, `netmaster findings`, `netmaster report`, `netmaster rules list|export-md`.
- Topology inference v1 and the Topology screen.
- Platform capability table (`capabilities.toml`).

Out of scope: EdgeSwitch (plan 06), SNMP, diff rules, AI.

---

## 2. Tasks

### 02-01 EdgeOS allowlist
**Where:** `crates/nm-collect/src/allowlist.rs` (`pub mod edgeos`).
**What:** Named consts. Operational commands are wrapped at runtime by the collector as `/opt/vyatta/bin/vyatta-op-cmd-wrapper <args>` so they work on a non-interactive exec channel. The allowlist stores the **full** wrapped string so the forbidden-verb test sees exactly what is sent.
```
VERSION         /opt/vyatta/bin/vyatta-op-cmd-wrapper show version
INTERFACES      /opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces
IF_ETH_DETAIL   /opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces ethernet detail     (verify on bench; drop if absent)
ROUTE_SUMMARY   /opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route summary
ROUTE           /opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route
OSPF_NEIGHBOR   /opt/vyatta/bin/vyatta-op-cmd-wrapper show ip ospf neighbor
OSPF_INTERFACE  /opt/vyatta/bin/vyatta-op-cmd-wrapper show ip ospf interface
BGP_SUMMARY     /opt/vyatta/bin/vyatta-op-cmd-wrapper show ip bgp summary
OFFLOAD         /opt/vyatta/bin/vyatta-op-cmd-wrapper show ubnt offload
DHCP_LEASES     /opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp leases
DHCP_STATS      /opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp statistics
FW_STATS        /opt/vyatta/bin/vyatta-op-cmd-wrapper show firewall statistics
NAT_STATS       /opt/vyatta/bin/vyatta-op-cmd-wrapper show nat statistics
CONFIG_CMDS     /opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands
UPTIME          uptime
LOADAVG         cat /proc/loadavg
MEMINFO         cat /proc/meminfo
NET_DEV         cat /proc/net/dev
ARP             cat /proc/net/arp
```
Validate on the bench first thing. If the wrapper path differs on a firmware, record the alternative in `HARDWARE-TESTING.md`; do **not** add `vbash -ic` variants because they can run arbitrary aliases.
**Accept:** forbidden-verb test passes; every command returns output on an ER-X running the current 2.0.x firmware; absent commands documented.

### 02-02 EdgeOS collector and parsers
**Where:** `crates/nm-collect-ubiquiti/src/edgeos/{mod,collector,parse/*}.rs`.
**What:**
- Collector mirrors the airOS one. `OSPF_*` and `BGP_SUMMARY` are run only if the config tree (parsed first from `CONFIG_CMDS`) contains `protocols ospf` / `protocols bgp`; otherwise they are listed in `Coverage.expected` as skipped-by-config, not missing. Order: `CONFIG_CMDS` first for this reason.
- Parsers:
  - `version`: `Version: v2.0.9-hotfix.7`, `Build ID`, `HW model: EdgeRouter X 5-Port`, `HW S/N` (serial → tokenized in fixtures), `Uptime`.
  - `interfaces`: the summary table (`Interface  IP Address  S/L  Description`) → name, addresses, state/link, description.
  - `if_eth_detail` (if present): per-interface RX/TX packets, bytes, errors, dropped, speed/duplex lines.
  - `route_summary` and `route`: protocol counts; routes with protocol code, prefix, next hop, interface, metric.
  - `ospf_neighbor`: `Neighbor ID  Pri  State  Dead Time  Address  Interface  RXmtL RqstL DBsmL` → `OspfNeighbor { router_id, state: OspfState, address, interface }`; `OspfState` parsed from `Full/DR`, `2-Way/DROther`, `ExStart/...`, `Init/...`.
  - `ospf_interface`: interface, area, cost, state, DR/BDR, timers.
  - `bgp_summary`: neighbor, AS, state/prefix count (numeric means Established).
  - `offload`: key/value tree → `OffloadFacts { ipv4_forwarding, ipv4_vlan, ipv4_pppoe, ipv6_*, ipsec }` as `Option<bool>`.
  - `dhcp_leases` and `dhcp_stats`: pool name, size, leased, available → `DhcpFacts.pools`.
  - `fw_stats` / `nat_stats`: rule counts and hit counters per rule set.
  - `config_cmds` (`config_tree.rs`): parse `set a b c 'value'` lines into a `ConfigTree` (ordered map of path → values). Secrets removed at parse: any leaf named `password`, `encrypted-password`, `plaintext-password`, `pre-shared-secret`, `community`, `secret`, `key`, `passphrase`, `authentication-key`, `md5-key`, and any `$1$`/`$5$`/`$6$` crypt string. The redacted tree is re-serialized as `set ...` lines into `RedactedConfig`. Typed extraction into facts: `service ssh port`, `service telnet`, `service gui http-port|https-port|listen-address`, `service snmp community <name>` (presence + is-default), `service ubnt-discover`, `service upnp`, `service dhcp-server shared-network-name *`, `system ntp server`, `system host-name`, `interfaces ethernet ethN {address, description, duplex, speed, firewall {in,out,local} name}`, `firewall name * {default-action, rule *}`, `protocols ospf {area, parameters router-id}`, `protocols bgp N`, `system offload {ipv4,ipv6} {forwarding,vlan,pppoe}`.
  - `uptime`, `loadavg`, `meminfo`, `net_dev`, `arp`: reuse the shared Linux parsers from plan 01 (move them to `nm-collect-ubiquiti/src/common/linux.rs`).
- WAN detection heuristic for rules: an interface is WAN-facing if it has a default route via it, or `description` matches `/wan|internet|upstream|uplink/i`, or it has `pppoe` or `dhcp` address with a public resulting IP. Recorded as `InterfaceFacts.role: Option<InterfaceRole>` with a `confidence`.
**Accept:** `insta` goldens for each parser from ER-X fixtures (one with OSPF between two routers if two are available); `ConfigTree` round-trip test (parse → redact → serialize → parse yields the same tree minus secrets); planted-secret test for every secret leaf name.

### 02-03 `SnapshotView` and rules engine core
**Where:** `crates/nm-analyze/src/{lib,view,rule,catalog,config,runner}.rs`.
**What:**
- `SnapshotView<'a>`: borrowed, indexed access over one `Snapshot` plus inventory: `devices()`, `device(id)`, `by_family(f)`, `by_site(s)`, `radios()`, `routers()`, `sites()`, `profiles_in_use()` (metadata only), `previous: Option<&Snapshot>` (None until plan 06). Precomputed indexes: MAC → device, IP → device, site → devices.
- `trait Rule: Send + Sync { fn meta(&self) -> &'static RuleMeta; fn evaluate(&self, view: &SnapshotView, cfg: &RuleConfig) -> Vec<Finding>; }`
- `RuleMeta { id: RuleId, title, category, default_severity, confidence, families: &'static [DeviceFamily], explanation_md: &'static str, thresholds: &'static [ThresholdSpec] }` where `ThresholdSpec { key, default: toml::Value, description }`.
- `RuleConfig`: loaded from `rules.toml` in the data dir, merged over defaults; `enabled: HashMap<RuleId, bool>`, `thresholds: HashMap<RuleId, HashMap<String, toml::Value>>`; typed getters `cfg.get_f64("imbalance_db")`.
- `catalog::all() -> &'static [&'static dyn Rule]` built from an explicit list (no `inventory`/`linkme` magic; one place to look).
- `runner::evaluate(view, cfg) -> Vec<Finding>`: runs every enabled rule whose `families` intersects the snapshot, catches panics per rule (`catch_unwind`) and converts them into a `GEN-HYG-999 "Rule crashed"` Info finding with the rule id, so one bad rule never hides the others. Sorts by severity desc, then rule id, then device.
- `netmaster rules export-md > docs/RULES.md` renders id, severity, category, families, thresholds with defaults, and the explanation. CI runs it and `git diff --exit-code docs/RULES.md`.
**Accept:** engine tests with a synthetic snapshot and a `PanicRule`; `RULES.md` generation is deterministic.

### 02-04 Rule implementations, security and hygiene
**Where:** `crates/nm-analyze/src/rules/{sec,hyg}.rs`, `crates/nm-analyze/data/defaults.toml`.
**What:** Implement UBNT-SEC-001 … 011 and GEN-HYG-001 … 005 from SPEC §9.3. Specifics:
- SEC-001 default credential: reads `view.profiles_in_use()` where each entry carries `is_vendor_default: bool`, computed in `nm-app` by comparing the entered username/password against `("ubnt","ubnt")` at profile-creation time and stored as profile metadata (never the secret). The rule never sees secrets.
- SEC-002 public management: `!ip.is_private() && !ip.is_shared(100.64/10) && !ip.is_link_local() && !ip.is_loopback()`.
- SEC-005: `services.snmp.enabled && services.snmp.community_is_default`.
- SEC-007: airOS `discovery.status=enabled` on a device whose `netmode` is `router` with a WAN interface, or EdgeOS `service ubnt-discover` not disabled on a router with a WAN interface.
- SEC-010: compare `system.firmware` to `data/firmware.toml` (a small table: family → platform → `current`, `eol_below`). Ship a first version from Ubiquiti's download pages at implementation time; plan 06 formalizes updates.
- SEC-011: EdgeRouter WAN interface with no `firewall in` and no `firewall local` name attached.
- Each rule's `explanation_md` is written for a junior engineer: what, why it matters, what to do, how to verify. Three to six sentences.
**Accept:** table-driven tests per rule: one positive and one negative synthetic snapshot each; explanations reviewed for plain language.

### 02-05 Rule implementations, RF, performance, reliability, capacity
**Where:** `crates/nm-analyze/src/rules/{rf,perf,rel,cap}.rs`.
**What:** Implement UBNT-RF-001 … 009, UBNT-PERF-001 … 003, GEN-REL-002 … 005, GEN-CAP-001 … 002. Specifics:
- RF-001 chain imbalance: `max(chains) - min(chains) > imbalance_db (default 6)`; evaluate on both the device's own radio facts and, on APs, each station entry (so a misaligned CPE shows up even if only the AP was scanned). Evidence lists each chain value.
- RF-003 airtime: `airtime.busy > airtime_pct (80)` using `mca-dump` `polling`/`athstats` fields where available; `Confidence::Likely`.
- RF-006 co-channel: group radios by site with `mode == Ap`; two sectors overlap if `|f1 - f2| < (w1 + w2) / 2`. `Confidence::Heuristic` because sites may be physically separated despite sharing a name.
- RF-007 modulation vs signal: a small expectation table (signal dBm → expected minimum MCS index per channel width) in `data/mcs_expect.toml`; flag when observed rate is more than two MCS steps below expectation. `Heuristic`.
- RF-009 distance: only when the site record has a `max_distance_m` set by the user (field on `Site`, added here).
- PERF-001 offload: `offload.ipv4_forwarding == Some(false)` on EdgeOS models where offload exists (`ER-X`, `ER-X-SFP`, `ER-4`, `ER-6P`, `ER-8`, `ER-12`, `ER-Lite`, `ER-PoE`). Critical-adjacent in practice; keep High.
- PERF-002: `loadavg.one_min > cpu_count * load_factor (1.0)` where `cpu_count` comes from `/proc/cpuinfo` if collected, else a per-model table.
- REL-002 duplex/speed: `duplex == Half`, or `speed < 1000` on an interface whose peer (via ARP/station match) is a gigabit-capable model.
- REL-003 / REL-004: any OSPF neighbor not `Full`; any BGP peer not Established.
- CAP-001: `leased / size > 0.9`.
- CAP-002: stations per sector above `max_stations (default 60)`; evidence includes model so the user can tune.
**Accept:** table-driven tests; a bench run on the real airOS fleet produces at least one RF finding and PERF-001 on an ER-X with offload toggled off (then back on; this is the one time you touch the router, by hand, in its web UI).

### 02-06 Findings persistence and `analyze` flow
**Where:** `crates/nm-app/src/analyze.rs`, `crates/nm-store/src/repo/findings.rs`.
**What:** `AnalyzeService::run(snapshot_id) -> Vec<Finding>`: builds `SnapshotView`, evaluates, replaces findings for that snapshot in the DB (idempotent), returns them. Scan completion triggers analyze automatically (setting `auto_analyze`, default true). `FindingsRepo::query(FindingFilter { snapshot, severity_min, category, device, rule })`.
**Accept:** running analyze twice yields identical rows; filter tests.

### 02-07 Findings screen
**Where:** `crates/nm-tui/src/screens/findings/*`.
**What:** Table: severity glyph and color, rule id, title, device count, category, confidence. Sort by severity default. Filters: `/` text, `1–5` severity threshold, `c` category cycle, `h` toggle heuristics. Detail pane: full explanation (Markdown rendered to styled spans: headings, bold, bullet lists), evidence table (device, metric path, observed, threshold), affected devices (Enter jumps to Devices screen on that device). `D` disables the rule (writes `rules.toml`, re-runs analyze, shows a toast). `E` exports the current filtered view as Markdown (02-08).
**Accept:** snapshot tests; disabling a rule removes its findings immediately.

### 02-08 Markdown report (no AI)
**Where:** `crates/nm-app/src/report.rs`, `crates/nm-cli/src/commands/report.rs`.
**What:** `render_report(snapshot, findings, options) -> String`: title, snapshot metadata (date, device counts by family and site, coverage summary), findings grouped by severity with evidence tables and explanations, per-site device summary, appendix with coverage gaps. Options: `--redact names|full|none` (reuses the Redactor skeleton introduced here in `nm-core::redact` as a simple consistent tokenizer; plan 03 extends it), `--min-severity`. The same renderer feeds the `E` key in the Findings screen.
**Accept:** golden test of a report from fixture data; renders cleanly in GitHub Markdown preview.

### 02-09 Topology inference v1 and screen
**Where:** `crates/nm-analyze/src/topology.rs`, `crates/nm-tui/src/screens/topology/*`.
**What:**
- `TopologyGraph { nodes: Vec<Node>, edges: Vec<Edge> }` with `Node::{Site, Device, UnknownStation { mac }}` and `Edge::{Wireless { ap, station, signal }, Ospf { a, b, state }, L2Adjacent { a, b, via: ArpOrBridge }}`.
- Inference: AP station MAC → enrolled device with that wireless MAC (from airOS `wireless` MAC or `ifconfig ath0`); unmatched MACs become `UnknownStation`. OSPF neighbor router-id or address → device by IP index. ARP: devices seeing each other's MACs on the same interface become `L2Adjacent` with low confidence.
- Screen: ASCII tree per site: `Site → AP (freq/width, N stations) → stations (signal, chains ok/!)`, then a routers section listing OSPF adjacencies with state. `Enter` on a node jumps to Devices.
- Exposed later to the model as `get_topology` (plan 03) and MCP (plan 04); serialize as JSON now.
**Accept:** unit tests with synthetic facts; bench tree shows the real AP with its stations.

### 02-10 Platform capability table
**Where:** `crates/nm-analyze/data/capabilities.toml`, `crates/nm-core/src/capabilities.rs`.
**What:** Per family: supported routing protocols, supported services, whether hardware offload exists, max channel widths, management surfaces. Example: `[edgeos] routing = ["static","ospf","ospfv3","bgp","rip","ripng"]; not_supported = ["eigrp","isis"]`. Loaded at startup, exposed via `Capabilities::for_family(f)`. Used now by rules (PERF-001 model list) and in plan 03 by the system prompt.
**Accept:** table loads; a test asserts `eigrp` is in `edgeos.not_supported`.

### 02-11 CLI parity
**Where:** `crates/nm-cli/src/commands/{analyze,findings,rules,report}.rs`.
**What:** `analyze [--snapshot] [--json]`, `findings [--severity] [--category] [--device] [--json]`, `rules list [--json]`, `rules export-md`, `rules disable|enable <id>`, `report --snapshot <id> --out <path> [--redact] [--min-severity]`.
**Accept:** `assert_cmd` tests; CI step `netmaster rules export-md | diff - docs/RULES.md`.

---

## 3. Testing summary

| What | How |
|------|-----|
| EdgeOS parsers | `insta` goldens; `ConfigTree` round-trip; planted secrets |
| Engine | synthetic snapshots; panic isolation |
| Rules | one positive and one negative test per rule, minimum |
| Report | golden Markdown |
| Topology | synthetic graphs |
| Screens | `TestBackend` snapshots |
| Docs drift | `RULES.md` diff in CI |

---

## 4. Risks specific to this plan

- **False positives.** Default thresholds are deliberately conservative. Every heuristic rule carries `Confidence::Heuristic` and renders dimmer. Review the first bench results with a skeptical eye and tune before committing defaults.
- **`show configuration commands` on large configs** can be several thousand lines. The 4 MiB cap from plan 01 is enough; parsing must be linear.
- **WAN heuristic** is wrong on double-NAT or policy-routed setups. Make `InterfaceRole` user-overridable per interface in the Devices screen (small form) and persist the override on the device record.

---

## 5. Done checklist

- [ ] All EdgeOS commands validated on bench; absent ones documented.
- [ ] Config tree parser redacts every listed secret leaf.
- [ ] 31 rules implemented with tests and explanations (all of §9.3 except GEN-REL-001).
- [ ] Findings screen, report, topology screen complete.
- [ ] `RULES.md` generated and drift-checked in CI.
- [ ] `capabilities.toml` in place.
- [ ] Bench: findings on the ER-X and the airOS fleet reviewed for plausibility; thresholds tuned; ADR 0005 records threshold rationale.
