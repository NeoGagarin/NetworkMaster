# ADR 0001: Rust and a Cargo workspace

Date: 2026-10-06
Status: accepted

## Context

SPEC §3 requires a native executable for Windows terminals and Linux. The application will hold credentials and parse untrusted device output. Distribution without a separate language runtime and memory safety are central constraints.

## Decision

Use Rust 2021 with a pinned stable toolchain (initially 1.92.0), Tokio, Ratatui/crossterm and bundled SQLite. Forbid unsafe code throughout the workspace. Go remains the fallback described in SPEC §3.2, not a parallel implementation.

## Consequences

The workspace can share domain types and enforce module boundaries in Cargo. Contributors need Rust and a native C compiler for bundled SQLite; Windows uses the MSVC toolchain. Rust has a learning cost, while less mature SNMP support is deferred to M6. Updating the toolchain requires both OS checks and a lockfile review.
