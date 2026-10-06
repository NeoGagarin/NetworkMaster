CREATE TABLE sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, notes TEXT NOT NULL);
CREATE TABLE credential_profiles (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, storage TEXT NOT NULL,
    keyring_ref TEXT, scope_hint TEXT NOT NULL
);
CREATE TABLE devices (
    id TEXT PRIMARY KEY, display_name TEXT NOT NULL, address TEXT NOT NULL, port INTEGER,
    vendor TEXT NOT NULL, family TEXT NOT NULL, role TEXT, site_id TEXT REFERENCES sites(id),
    profile_id TEXT REFERENCES credential_profiles(id), source TEXT NOT NULL,
    enrolled INTEGER NOT NULL CHECK(enrolled IN (0,1)), tags_json TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX devices_address ON devices(address);
CREATE TABLE ssh_host_keys (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, PRIMARY KEY(device_id, algorithm)
);
CREATE TABLE snapshots (
    id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, inventory_hash TEXT NOT NULL, notes TEXT NOT NULL
);
CREATE TABLE device_results (
    snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL, outcome TEXT NOT NULL, facts_json TEXT NOT NULL,
    coverage_json TEXT NOT NULL, PRIMARY KEY(snapshot_id, device_id)
);
CREATE INDEX device_results_snapshot ON device_results(snapshot_id);
CREATE TABLE raw_artifacts (
    snapshot_id TEXT NOT NULL, device_id TEXT NOT NULL, kind TEXT NOT NULL,
    name TEXT NOT NULL, bytes BLOB NOT NULL, sha256 BLOB NOT NULL CHECK(length(sha256)=32),
    redacted INTEGER NOT NULL CHECK(redacted=1), PRIMARY KEY(snapshot_id, device_id, name),
    FOREIGN KEY(snapshot_id, device_id) REFERENCES device_results(snapshot_id, device_id) ON DELETE CASCADE
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL, severity INTEGER NOT NULL CHECK(severity BETWEEN 0 AND 4),
    category TEXT NOT NULL, title TEXT NOT NULL, evidence_json TEXT NOT NULL,
    devices_json TEXT NOT NULL, confidence TEXT NOT NULL, explanation TEXT NOT NULL
);
CREATE INDEX findings_snapshot_severity ON findings(snapshot_id, severity);
CREATE TABLE rule_overrides (rule_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, thresholds_json TEXT NOT NULL);
CREATE TABLE ai_sessions (
    id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES snapshots(id), provider TEXT NOT NULL,
    model TEXT NOT NULL, redaction_mode TEXT NOT NULL, started_at TEXT NOT NULL,
    token_in INTEGER, token_out INTEGER, cost_estimate REAL
);
CREATE TABLE ai_messages (
    session_id TEXT NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL, role TEXT NOT NULL, content_json TEXT NOT NULL, PRIMARY KEY(session_id, seq)
);
CREATE TABLE redaction_maps (
    session_id TEXT NOT NULL REFERENCES ai_sessions(id) ON DELETE CASCADE,
    token TEXT NOT NULL, real_value_encrypted BLOB NOT NULL, PRIMARY KEY(session_id, token)
);
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, target TEXT NOT NULL, detail_json TEXT NOT NULL,
    bytes_out INTEGER NOT NULL CHECK(bytes_out>=0), bytes_in INTEGER NOT NULL CHECK(bytes_in>=0)
);
CREATE INDEX audit_log_ts ON audit_log(ts);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
