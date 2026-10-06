# Security policy

NetworkMaster has a permanent **no-write invariant**: no configuration management, remediation commands or arbitrary remote command execution. Only explicitly enrolled targets may be contacted. Credentials are session-only in M0 and must never appear in SQLite, logs, fixtures, findings or AI payloads. Security boundaries are documented in [DEVELOPMENT.md](docs/DEVELOPMENT.md) and tested in CI.

Contact the maintainer privately at the author email of the repository's initial commit: `git log --reverse --format=%ae` (first line). This is the disclosure contact until a public repository and dedicated address are assigned. After publishing, the maintainer must enable GitHub private vulnerability reporting and replace this contact with its verified reporting URL. Do not open a public issue containing device data, passwords or exploit details.

We request a **90-day coordinated disclosure window** after initial contact. The maintainer will acknowledge receipt, assess impact and coordinate a fix and disclosure date with the reporter. An earlier disclosure may be agreed for an actively exploited issue. Pre-alpha releases are supported only at the current source revision.
