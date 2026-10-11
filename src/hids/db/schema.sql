-- HIDS SQLite WAL Schema

CREATE TABLE IF NOT EXISTS host_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,
    host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    source_component TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON host_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category ON host_events (category);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    matched_event_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    evidence TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS fim_baselines (
    file_path TEXT PRIMARY KEY,
    sha256_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mode_permissions TEXT NOT NULL,
    owner_uid INTEGER NOT NULL,
    group_gid INTEGER NOT NULL,
    modified_time TEXT NOT NULL,
    is_directory INTEGER NOT NULL DEFAULT 0,
    last_scanned TEXT NOT NULL
);
