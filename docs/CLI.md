# CLI reference (M0)

`netmaster` launches the TUI with no subcommand. Run `netmaster --help` or `<subcommand> --help` for exact arguments. Global options can appear after subcommands: `--data-dir PATH`, `--json`, `--ascii`, `--no-color`, `-v` and `-vv`. Logs and diagnostic text go to stderr; JSON command results go to stdout.

## Implemented commands

```text
netmaster
netmaster inventory add <addr> [--family airos|edgeos|edgeswitch|unifi|uisp|unknown] [--site S] [--name N]
netmaster inventory list [--json]
netmaster inventory enroll <id>... | --all-candidates
netmaster creds add <name> --kind ssh-password --username readonly [--secret-from-stdin]
netmaster audit tail [-n 100] [--json]
netmaster forget --all-credentials
netmaster --version
```

Addresses accept IPv4, IPv6, DNS names and optional ports (`[::1]:22` for an IPv6 port). Inventory additions are candidates. Enrollment is explicit and performs no connection. A site name is created locally if missing; an existing site ID can also be used.

Credential kinds are ssh-password, ssh-key, api-token, http-basic, snmp-v2c and snmp-v3. SSH/HTTP/SNMPv3 need `--username`; ssh-key needs `--key-file` and optionally `--has-passphrase`. Password/token/community input is hidden with rpassword or read as one line from stdin; secrets are never command-line arguments. SNMPv3 currently uses two interactive prompts; `--auth-proto` and `--priv-proto` select metadata. `--scope-hint` is non-secret metadata.

**Session-only means this process only.** `creds add` persists profile metadata and a CredentialCreated audit event, then drops the secret on exit. It does not make the secret available to a later netmaster process. Persistent `--persist` storage returns exit 2 until M5. `forget --all-credentials` wipes the current arena, keeps profile metadata and logs CredentialForgotten. No keyring integration exists in M0.

## Reserved command tree

```text
netmaster inventory import --file devices.csv
netmaster inventory import --uisp https://uisp.example --token-from-stdin
netmaster inventory import --unifi https://controller --token-from-stdin [--site default]
netmaster inventory discover --interface "Ethernet"
netmaster creds assign <profile> --devices <id>... | --site S | --family F
netmaster scan [--dry-run] [--site S] [--concurrency N] [--json]
netmaster analyze [--snapshot <id>] [--json]
netmaster findings [--severity high] [--json]
netmaster diff <snapshot-a> <snapshot-b>
netmaster report --snapshot <id> --out report.md
netmaster ai run --provider anthropic --model MODEL [--redact full|names|none] [--teach] [--out report.md]
netmaster export --snapshot <id> --out ./review/
netmaster mcp serve [--snapshot <id>] [--no-redact]
netmaster fixture capture --device <id> --out fixtures/
```

Unimplemented commands return 2 with `not implemented yet (planned for M<n>)`. `--json` returns a structured error object for these commands. No reserved command executes device actions in M0.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Usage error or unimplemented feature |
| 3 | Nothing to do (for example, no candidates to enroll) |
| 4 | Partial failure (reserved for scan) |
| 130 | Interrupted |
