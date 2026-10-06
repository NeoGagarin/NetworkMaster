# Plan 05 — Controllers: UISP and UniFi, Persistent Credentials (M5)

**Goal:** Import and collect from the two places WISPs and small ISPs already keep their Ubiquiti fleet: UISP (airMAX and EdgeOS) and the UniFi Network application. Prefer revocable read-only API tokens over device passwords. Add opt-in persistent credential storage in Windows Credential Manager now that the tool has earned some trust.

**Exit criteria (SPEC §19, M5):** Import 100+ devices from a UISP instance as candidates, enroll, and collect fleet statistics without any SSH. Findings on a UniFi site (channel plan, uplink, firmware). Credentials survive a restart when the user opts in, and `forget` removes them from Credential Manager.

**Depends on:** Plans 01 and 02. Can run in parallel with 03 and 04.
**Produces for later plans:** HTTP transport with TLS pinning, controller collectors, cross-source hygiene facts (GEN-HYG-004), UniFi radio facts for RF rules.

---

## 1. Scope

In scope:
- HTTP transport: GET-only plus allowlisted login POSTs, TLS verify with pin-on-first-use, pagination helper, rate limiting.
- UISP: import, collector, statistics, data links, outages.
- UniFi: Integration API (9.0+) collector; legacy API collector for older controllers; import.
- UniFi-specific rules.
- `keyring`-backed persistent credential storage; migration of a session-only profile to persistent and back.
- Controller-aware topology (UISP data-links, UniFi uplinks).

Out of scope: UniFi Protect/Access/Talk, UISP CRM, UniFi cloud (unifi.ui.com) remote access (local controller URL only), writing anything.

---

## 2. Tasks

### 05-01 HTTP transport
**Where:** `crates/nm-collect/src/http/{mod,client,tls,login}.rs`.
**What:**
- `HttpTransport::new(ctx, device, tls_policy)` builds a `reqwest::Client` whose connector uses `ctx.net` (via a custom resolver + `resolve_to_addrs` so `TargetGate` applies to the resolved IP) and whose TLS config is `rustls` with either WebPKI roots or a pinned leaf SPKI hash from `tls_pins` (new table: `device_id, spki_sha256, first_seen`). Policy: `Verify` (default) → on `UnknownIssuer`/self-signed, return `HttpError::UntrustedCert { spki_sha256, subject, not_after }` and let the UI ask "Pin this certificate for this device? [y/N]"; `Pinned` → accept only the pinned SPKI; mismatch is a High finding `UBNT-SEC-012 TLS certificate changed` and blocks collection.
- `get(path) -> Result<Response>`; the only POST is `login(endpoint: LoginEndpoint, body)` where `LoginEndpoint` is a closed enum: `UniFiOs`, `UniFiLegacy`, `AirOs8`, `AirOs6`. There is no generic `post`. Methods other than GET/POST do not exist on the type.
- Auth header injection via a closure provided by `nm-app` from the `CredArena` (`x-auth-token` for UISP, `X-API-KEY` for UniFi Integration, cookie + `X-CSRF-Token` for UniFi legacy).
- `Paginator` helper for `offset/limit` and `page/count` styles. Per-host rate limit (default 5 req/s) with a `governor` limiter; 429 honored.
- Response cap 8 MiB; JSON parsed with `serde_json::from_slice` into permissive structs (`#[serde(flatten)] extra`).
- Every request → `AuditEvent::HttpRequest { device, method, path, status, bytes_in }`. Query strings are logged; bodies are not.
**Accept:** `wiremock` tests: GET, pagination, 429 backoff, untrusted cert prompt flow (use a self-signed test server with `rustls` in tests), pin mismatch; a compile-time check (doc test) that `HttpTransport` has no `put`/`delete`/`patch` methods.

### 05-02 UISP import and collector
**Where:** `crates/nm-collect-ubiquiti/src/uisp/{mod,collector,import,parse,model}.rs`.
**What:**
- The UISP instance is itself a `Device` with `family = Uisp` and `role = Controller`, enrolled like any other, with an `ApiToken` profile. Base path `/nms/api/v2.1/`.
- Import (`inventory import --uisp`): `GET /devices` → candidates with `address = identification.ipAddress` (strip CIDR suffix), `display_name = identification.name`, `family` from `identification.type`/`role` (`airMax` → AirOs, `erouter` → EdgeOs, `eswitch` → EdgeSwitch, `airFiber`/`ltu` → AirOs), `site` from `identification.site.name` (auto-create), `source = UispImport`, plus `uisp_device_id` stored in `tags` as `uisp:<id>`. Devices already present by address are updated, not duplicated.
- Collector plan: `GET /devices`, `GET /sites`, `GET /data-links`, `GET /outages?count=200&page=1` (last 30 days), then for each enrolled device with a `uisp:` tag `GET /devices/{id}` and `GET /devices/{id}/statistics?interval=hour` (verify the parameter name against the instance's `/nms/api-docs` on the bench and record it). Bounded by the global concurrency semaphore, not per-site (it is one host).
- Parsing into facts **for the enrolled devices**, not for the controller: UISP's `overview` (`status`, `cpu`, `ram`, `uptime`, `signal`, `frequency`, `channelWidth`, `transmitPower`, `linkScore`, `lastSeen`), `interfaces[]` (name, mac, addresses, status, speed, statistics rx/tx bytes, errors, dropped), `firmware.current`/`latest`/`compatible`, `attributes.{ssid,apDevice}` → merged into the device's `DeviceFacts` with `source = "uisp"` in `Coverage`. Direct SSH facts take precedence over UISP facts when both exist.
- `data-links` → topology edges (`Wireless` with `from.device.identification.id` / `to.device...`, signal, capacity). `outages` → `ReliabilityFacts.outages_30d` per device (count, total minutes).
- New facts: `firmware.latest_available` enables a sharper SEC-010 variant `UBNT-SEC-013 Firmware update available per UISP` (Low; Info if the current build is within one minor).
**Accept:** `wiremock` fixtures recorded from a real UISP (scrubbed with the fixture tool, extended for JSON); import of a 100+ device fixture yields correct families and sites; collector merges without overwriting SSH-sourced values.

### 05-03 UniFi Integration API collector (UniFi Network 9+)
**Where:** `crates/nm-collect-ubiquiti/src/unifi/{mod,integration,legacy,parse,model,import}.rs`.
**What:**
- Controller is a `Device` with `family = UniFi`, `role = Controller`, `ApiToken` profile. Detection: `GET /proxy/network/integration/v1/sites` with `X-API-KEY`; 401/404 falls back to legacy (05-04) with an `HttpBasic` profile.
- Plan: `GET /sites` (paginated), per selected site `GET /sites/{id}/devices` (paginated), `GET /sites/{id}/devices/{deviceId}` for each adopted device (gives radios, ports, uplink), `GET /sites/{id}/clients` (paginated; client count and per-AP association only, no client names in facts by default — a setting enables them).
- Import: adopted devices → candidates with `family = UniFi`, `role` from `type` (`uap`→Ap, `usw`→Switch, `ugw`/`udm`/`uxg`→Gateway), `site`, `source = UniFiImport`, tag `unifi:<deviceId>`.
- Facts per UniFi device: `system` (model, firmware, uptime, state), `interfaces` from ports (speed, duplex, poe power, counters where present), `radio` from `radios[]` (band, channel, width, tx power, utilization, client count, retries if exposed), `uplink` → topology edge, `neighbors` from LLDP if exposed.
**Accept:** `wiremock` fixtures from a real controller; a UniFi site with two APs produces radio facts and an uplink edge.

### 05-04 UniFi legacy API collector
**Where:** `crates/nm-collect-ubiquiti/src/unifi/legacy.rs`.
**What:** Login `POST /api/auth/login` (UniFi OS) or `POST /api/login` (software controller) with `{username,password}` through `LoginEndpoint::UniFiLegacy`; capture cookie and `X-CSRF-Token`. Then `GET /proxy/network/api/s/{site}/stat/device`, `/stat/sta`, `/stat/health`, `/rest/networkconf`, `/rest/wlanconf` (software controller omits the `/proxy/network` prefix; detect by probing). Map `stat/device` into the same facts as 05-03 plus `radio_table_stats[]` (`cu_total`, `cu_self_tx`, `cu_self_rx`, `num_sta`, `tx_retries`, `channel`, `tx_power`). `wlanconf` gives SSIDs, security mode (WPA2/WPA3/open), hide flag. `networkconf` gives VLANs and subnets → `AddressFacts`. The account should be a read-only local admin; the onboarding text says so.
**Accept:** `wiremock` fixtures; same facts shape as 05-03 for overlapping fields (shared golden).

### 05-05 UniFi rules
**Where:** `crates/nm-analyze/src/rules/unifi.rs`, catalog updates.
**What:**
| ID | Severity | Rule |
|----|----------|------|
| UBNT-RF-010 | Medium | 2.4 GHz channel width 40 MHz on an AP (interference-prone) |
| UBNT-RF-011 | Medium | Co-channel 2.4 GHz APs at the same site (channels not 1/6/11 spaced) |
| UBNT-RF-012 | Medium | Channel utilization above 70% on any radio |
| UBNT-RF-013 | Low | TX power at maximum on all APs at a site with more than two APs (roaming/cell-overlap hint) |
| UBNT-RF-014 | Low | Retry rate above 15% on a radio |
| UBNT-SEC-014 | High | Open (no security) SSID that is not explicitly tagged `guest` |
| UBNT-SEC-015 | Medium | WPA2-only where every AP at the site supports WPA3 (transition mode suggestion) |
| UBNT-CAP-003 | Medium | Switch uplink negotiated below 1 Gbps or PoE budget above 90% |
| GEN-HYG-004 | Low | (now implementable) device reachable by SSH but absent from the controller its siblings are in |
| GEN-HYG-006 | Low | UniFi device firmware behind the controller's recommended version (`upgradable` flag) |
Explanations written for juniors as in plan 02. `RULES.md` regenerated.
**Accept:** positive/negative tests each; bench run on the UniFi site.

### 05-06 Persistent credentials via Credential Manager
**Where:** `crates/nm-creds/src/{store,windows,linux}.rs`.
**What:**
- `StorageMode::WindowsCredentialManager` implemented via `keyring::Entry::new("NetworkMaster", &profile_id.to_string())`. Secrets are serialized as JSON of `SecretMaterial` (the keyring value is one string). On Linux the same code path uses Secret Service; if no backend is available, `set_storage` returns `CredsError::NoPersistentBackend` and the UI explains.
- `CredArena::load_persistent(profiles)` at startup pulls persisted secrets into the arena; `set_storage(id, mode)` migrates: to persistent writes the entry; to session-only deletes the entry (and verifies deletion by reading back and expecting not-found).
- `forget(id)` and `forget_all()` delete entries and zeroize memory. `netmaster forget --all-credentials` also enumerates orphaned entries under the `NetworkMaster` service name and removes them, printing each.
- Settings: default storage mode for new profiles (`SessionOnly` unless the user changes it); the Credentials screen's storage field is now editable with a one-line consequence note.
**Accept:** Windows integration test (gated, runs on `windows-latest`): create persistent profile, restart `AppService`, `with_secret` succeeds, `forget`, restart, `with_secret` fails; Credential Manager UI shows and then does not show the entry (manual check once).

### 05-07 Controller-aware inventory and Devices screens
**Where:** `crates/nm-tui/src/screens/{inventory,devices}/*`.
**What:** Inventory import modal gains UISP and UniFi tabs (URL, API key profile picker, site multi-select for UniFi, "import as candidates" button, result summary). Devices detail gets a `Controller` tab showing what the controller reports about the device (status, last seen, firmware latest, outages 30d, link score) side-by-side with directly collected values where both exist. The TLS pin prompt appears as a modal with subject, SPKI fingerprint and expiry.
**Accept:** snapshot tests; import of the UISP fixture through the TUI.

### 05-08 Topology v2
**Where:** `crates/nm-analyze/src/topology.rs`.
**What:** Merge UISP `data-links` and UniFi uplinks into the graph with `source` on each edge. Prefer direct observation (wstalist) over controller data for the same pair; keep both as evidence. The Topology screen shows edge source glyphs.
**Accept:** synthetic merge tests; bench graph includes both SSH-observed and UISP-reported links without duplicates.

### 05-09 CLI parity and docs
**Where:** `crates/nm-cli/src/commands/inventory.rs`, `docs/CONTROLLERS.md`.
**What:** `inventory import --uisp <url> --token-profile <id> | --token-from-stdin`, `inventory import --unifi <url> --token-profile <id> [--site ...] [--legacy --user-profile <id>]`, `creds set-storage <profile> session|persistent`. `CONTROLLERS.md`: how to create a UISP API token, how to create a UniFi API key or read-only local admin, what each gives the tool, what it does not.
**Accept:** `assert_cmd` tests with `wiremock`; docs reviewed against the real UIs with version numbers noted.

---

## 3. Testing summary

| What | How |
|------|-----|
| HTTP transport | `wiremock`, self-signed TLS server, method-absence doc test |
| UISP / UniFi parsing | recorded, scrubbed JSON fixtures; goldens |
| Import | 100+ device fixture |
| Rules | positive/negative per rule |
| Credential Manager | gated Windows integration test |
| Topology merge | synthetic |

---

## 4. Risks specific to this plan

- **UniFi Integration API coverage gaps.** Radio utilization and retries may only be in the legacy API for some versions. The two collectors share the facts shape so the legacy one can fill gaps; document the matrix in `CONTROLLERS.md`.
- **UISP endpoint names drift between versions.** The OpenAPI document at `/nms/api-docs` is the reference; add a `uisp doctor` subcommand that lists which expected endpoints exist on the instance.
- **Self-signed everything.** Nearly every UISP and UniFi install is self-signed. The pin-on-first-use flow must be smooth or users will reach for a global "ignore TLS" switch, which this project will not ship.

---

## 5. Done checklist

- [ ] HTTP transport GET-only with allowlisted logins; TLS pinning flow tested.
- [ ] UISP import of 100+ devices; fleet statistics collected without SSH.
- [ ] UniFi Integration and legacy collectors produce the same facts shape.
- [ ] Ten new rules with tests; `RULES.md` regenerated.
- [ ] Credential Manager persistence opt-in works and `forget` removes entries.
- [ ] Topology v2 merges controller links.
- [ ] `CONTROLLERS.md` written; ADR 0008 records "controller tokens before device passwords" onboarding order.
