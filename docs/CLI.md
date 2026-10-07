# CLI reference (M2)

`netmaster` launches the TUI with no subcommand. Run `netmaster --help` or `<subcommand> --help` for exact arguments. Global options can follow subcommands: `--data-dir PATH`, `--json`, `--ascii`, `--no-color`, `-v` and `-vv`. Logs, credential prompts and diagnostics go to stderr; JSON results go to stdout.

## Inventory and enrollment

```text
netmaster inventory add <addr> [--family airos|edgeos|edgeswitch|unifi|uisp|auto] [--role ap|station|ptp|router|switch|gateway|controller] [--site S] [--name N]
netmaster inventory import --file devices.csv
netmaster inventory discover --interface "Ethernet" [--json]
netmaster inventory list [--json]
netmaster inventory enroll <id>... | --all-candidates
netmaster inventory unenroll <id>...
netmaster inventory allow-legacy <id>...
```

Addresses accept IPv4, IPv6, DNS names and optional ports (`[::1]:22` for an IPv6 port). Add/import/discovery create candidates. Enrollment and local edits perform no DNS or connection. CSV requires `address,name,family,site` headers; duplicate addresses/ports are skipped, bad rows reported and missing sites created. Discovery sends two UDP probes on the explicitly selected interface and listens for three seconds. Set known station roles to skip `wstalist`. airOS and EdgeOS have SSH collectors; other families can be inventoried for later milestones.

## Session credentials

```text
netmaster creds add <name> --kind ssh-password --username readonly [--secret-from-stdin]
netmaster creds add <name> --kind ssh-key --username readonly --key-file key [--has-passphrase]
netmaster creds assign <profile-id> --devices <id>... | --site S | --family F
netmaster forget --all-credentials
```

Supported metadata kinds are ssh-password, ssh-key, api-token, http-basic, snmp-v2c and snmp-v3; Collection uses SSH. Passwords and passphrases use hidden prompts or stdin and never command-line arguments. Persistent `--persist` storage returns exit 2 until M5.

**Session-only means this process only.** `creds add` saves metadata and drops the secret on exit. A later CLI scan/capture prompts again for each assigned profile. With `--secret-from-stdin`, supply one line per required secret, in profile-ID order; an encrypted key needs its passphrase. `--key-file` supplies the key material for the current scan/capture. The TUI retains newly entered credentials until forgotten or quit; forgetting a profile unassigns its devices. Global `forget --all-credentials` clears the arena and retains metadata.

## Collection and capture

```text
netmaster scan --dry-run [--site S] [--family airos|edgeos] [--json]
netmaster scan [--site S] [--family airos|edgeos] [--concurrency N] [--per-site N] [--secret-from-stdin] [--key-file key] [--json]
netmaster fixture capture --device <id> --out fixtures/airos/<model>-<fw> [--secret-from-stdin] [--key-file key] [--json]
netmaster audit tail [-n 100] [--json]
```

Inspect the dry run before scanning. It prints fourteen SSH commands per unknown-role/AP airOS device and thirteen per known station, with no credential prompt, DNS or network activity. Real collection pins the first host key, blocks changed keys, retains partial facts and persists a snapshot. Legacy-only servers require explicit per-device opt-in and a subsequent scan. Defaults are eight devices globally and two per site. Ctrl+C during a scan cancels collection and saves a usable partial snapshot before exit 130.

Scan `--json` emits progress as NDJSON, followed by a summary containing the snapshot ID and ok/partial/failed counts. Discovery and capture also emit NDJSON with a final summary. Inventory listing and audit tail retain their JSON-array format; audit tail lists newest events first. Capture scrubs secrets and tokenizes identifiers consistently across artifacts; review all files before committing.

## Reserved commands

Controller imports (`inventory import --uisp|--unifi`), diff, ai, export and mcp remain later milestones. They return exit 2 with a structured error under `--json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Usage error or unimplemented feature |
| 3 | Nothing to do, including an empty scan scope |
| 4 | Partial/failed collection or CSV row errors |
| 130 | Interrupted; scans finish saving their partial snapshot |

## Analysis, findings and reports

All analysis and report commands operate on local snapshots without networking or AI.
Scan completion analyzes automatically unless the stored app setting auto_analyze is false.

```text
netmaster analyze [--snapshot ID] [--json]
netmaster findings [--snapshot ID] [--severity info|low|medium|high|critical] [--category security|performance|reliability|capacity|hygiene|rf-health] [--device ID] [--rule ID] [--json]
netmaster rules list [--json]
netmaster rules export-md
netmaster rules disable <rule-id>
netmaster rules enable <rule-id>
netmaster report --snapshot ID --out report.md [--redact full|names|none] [--min-severity LEVEL]
netmaster topology [--snapshot ID] [--json]
```

Analyze defaults to the latest completed snapshot. Findings queries stored results across
snapshots unless --snapshot is supplied. Enable/disable saves rules.toml in the data
directory and reanalyzes the latest completed snapshot. Unknown IDs and invalid
thresholds fail explicitly. Full report redaction is the default; names hides identity
labels while preserving addresses. None preserves the displayed identity information.
The topology command emits the serializable inferred graph as JSON.

Example local rules.toml:

```toml
[enabled]
UBNT-RF-006 = false

[thresholds.UBNT-RF-001]
imbalance_db = 8

[thresholds.GEN-CAP-002]
max_stations = 45
```

In the TUI, 5 opens Findings and 7 opens Topology. Findings supports / text search,
1–5 minimum severity, c category cycle, h heuristic visibility, Up/Down selection,
PgUp/PgDn explanation scrolling, and Left/Right affected-device selection. Enter opens
the selected device. D disables the selected rule and refreshes findings; E exports the
filtered view with full redaction to report-SNAPSHOT.md in the data directory.

The Devices Interfaces tab supports R to set a persistent interface role or return to
auto inference. The Inventory site form accepts an optional maximum link distance in
meters, enabling RF-009. Heuristic topology edges and findings require operator review.
