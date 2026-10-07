# M2 network footprint

Startup, inventory edits/import, credential metadata, stored snapshots, and dry runs perform no DNS, TCP, UDP or HTTP requests. `NETMASTER_NET=deny` also prevents discovery and collection socket creation.

A real scan resolves enrolled hostnames once while preparing the target gate. Each airOS device uses one TCP connection to its explicit port or TCP/22 and one SSH session. Fourteen allowlisted exec channels run sequentially; an explicitly known station skips `wstalist` and uses thirteen. No shell, arbitrary command, HTTP request, agent forwarding, or configuration write is exposed. Default concurrency is eight devices globally and two per site; unassigned devices share one virtual site. The command timeout is 20 seconds and the device budget is 120 seconds. Each command retains at most 4 MiB combined stdout/stderr.

Opting into legacy SSH enables deprecated algorithms only for that device. The default remains modern, and a modern server on an opted-in device still negotiates modern algorithms. A key mismatch stops authentication and command execution. A failed negotiation may require a later scan after opt-in; it is a separate audited connection attempt.

Discovery is an explicit interface-scoped action. It binds the selected local IPv4 address on an ephemeral UDP port, enables broadcasting, and sends **two four-byte probes** (`01 00 00 00`): one to `255.255.255.255:10001`, one to that interface's subnet broadcast address on port 10001. Each send has its own `UdpProbe` audit event containing the interface name. Replies are accepted during a three-second window and become candidates. Enrollment remains explicit. There is no periodic discovery, port sweep or automatic subnet scan.

Fixture capture runs the same collector on one explicitly enrolled device. It scrubs secrets and consistently tokenizes identifiers before writing local files. Review files before publishing them. No fixture upload is performed.

EdgeOS scans use the same pinned SSH transport, timeouts and output limits. The
allowlist has nineteen commands, including the provisional ethernet detail command.
The fixed operational wrapper runs on non-interactive exec channels. Configuration
is read first; absent OSPF and BGP branches skip three operational commands, leaving
sixteen. No interactive shell variants, configuration writes or service restarts run.
Findings, analysis, reports, rule exports and topology inference perform no network IO.
