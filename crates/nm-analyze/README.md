# nm-analyze

Offline, deterministic assessment of borrowed snapshots and inventory metadata.
The explicit catalog registers 34 single-snapshot rules with explanations and numeric
thresholds. The runner isolates rule panics, assigns stable finding IDs and sorts by
severity, rule and device. Topology inference matches observed MAC and IP identities.
This crate has no network transport or credential secret dependency.
