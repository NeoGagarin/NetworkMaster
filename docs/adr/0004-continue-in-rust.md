# ADR 0004: Continue in Rust for M1

Date: 2026-10-06 (Asia/Manila)
Status: Accepted; hardware acceptance remains pending.

The M0 workspace already has the credential, audit, target-gate, storage and terminal boundaries needed by M1. The airOS collector now exercises these contracts through the CLI and TUI. Local replay tests cover SSH authentication, first-use pinning, changed-key rejection, legacy negotiation, command limits, parser precedence and dry-run/audit parity. Scheduling tests demonstrate the global and per-site limits and preservation of partial results.

Continue in Rust. A Go rewrite would duplicate these boundaries without evidence of a benefit. Keep the vendor parsers pure, use the current russh release, and retain the explicit per-device legacy policy. Reconsider only if real 6.x/8.x bench validation exposes an unresolved transport or terminal limitation. This decision does not assert completion of the plan's real AP and three-station exit criterion.
