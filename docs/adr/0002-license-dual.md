# ADR 0002: Apache-2.0 OR MIT

Date: 2026-10-06
Status: accepted

## Context

SPEC §18 seeks open contribution and commercial adoption by small ISPs. Patent clarity and compatibility with Rust ecosystem dependencies matter. A copyleft SaaS restriction would discourage some intended contributors.

## Decision

License project code under Apache-2.0 OR MIT. Include both full license texts. Require dependency licenses to satisfy the closed allowlist in `deny.toml`, excluding GPL and AGPL. Contributions use the same dual license.

## Consequences

Users can select either permitted license; Apache provides a patent grant. Commercial reuse is allowed. Cargo-deny checks resolved dependencies, including platform-specific crates, in CI. A dependency outside the policy requires a deliberate policy decision before adoption.
