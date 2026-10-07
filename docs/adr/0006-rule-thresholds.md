# ADR 0006: Conservative single-snapshot assessment thresholds

Date: 2026-10-06
Status: Accepted for synthetic validation; bench tuning pending

## Context

M2 needs useful findings without AI or a second snapshot. Missing facts must not
be interpreted as disabled features. A single snapshot cannot establish sustained
CPU pressure, poor CCQ, traffic utilization or changing error counters.

## Decision

Implement all 34 rule IDs listed in Plan 02: 11 security, 9 RF, 3 performance,
4 reliability, 2 capacity and 5 hygiene rules. The plan's count of 31 was an
arithmetic error. GEN-REL-001 remains a later snapshot-diff rule.

Use the specified initial limits: 6 dB chain difference, 70% CCQ, 80% airtime,
−75 dBm station signal, −90 dBm noise, CPU load/core ratio 1, 10% available
memory, 24-hour uptime, 90% DHCP pool utilization and 60 stations per sector.
Comparisons are strict at the documented boundary. Thresholds are registered in
the catalog and can be overridden in rules.toml. Invalid keys and numeric domains
are rejected. The bundled defaults table is checked against catalog values.

Mark observations requiring operational interpretation as Likely or Heuristic.
Explanations tell the operator to confirm persistence and context. In particular,
OSPF 2-Way may be normal on broadcast networks, discovery presence does not prove
WAN exposure, and ARP adjacency needs reciprocal observations. Explicit interface
role overrides take precedence over inferred WAN roles without altering saved
snapshot observations.

Wide-channel review requires an observed throughput field. Negotiated link rates
and cumulative byte counters are not substituted for traffic measurements. Distance
checks require a user-supplied site limit. Unknown models do not receive a guessed
CPU count or an offload capability finding.

Firmware baselines were checked against Ubiquiti's
[airOS firmware listing](https://www.ui.com/compliance/eulock/?direct=true) and
[ER-X downloads](https://www.ui.com.cn/download/software/er-x) on 2026-10-06.
The airOS listing describes EU variants; version comparisons are review prompts,
not instructions to install regional images. No EOL floor is asserted without
vendor evidence. Analysis never fetches firmware data at runtime.

Stable finding IDs include the snapshot ID, rule, devices and evidence. Atomic
replacement preserves identical rows on repeated analysis and allows rule toggles
to refresh a snapshot immediately. One rule panic produces GEN-HYG-999 while
other rules continue.

## Consequences

The defaults and positive/negative boundaries are reproducible offline. Synthetic
fixtures cannot establish firmware command availability or operational accuracy.
Real ER-X/AP/station review must tune the defaults and update this ADR with measured
evidence before hardware acceptance is marked complete.

ADR 0005 already documents SSH transport, so this threshold decision uses 0006.
