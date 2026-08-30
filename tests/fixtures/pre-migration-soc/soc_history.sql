CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT, source_type TEXT, category TEXT,
    host TEXT, src_ip TEXT, dst_ip TEXT, user TEXT, event_id TEXT,
    severity TEXT,
    action TEXT, message TEXT,
    raw TEXT,
    mitre TEXT,
    event_hash TEXT UNIQUE
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_ip ON events(src_ip, dst_ip);
CREATE INDEX idx_events_sev ON events(severity);

CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT, hostname TEXT, mac TEXT, category TEXT,
    vendor TEXT, model TEXT, os TEXT, ports TEXT,
    source TEXT, status TEXT, risk REAL DEFAULT 0
);
CREATE INDEX idx_assets_ip ON assets(ip);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    asset_ip TEXT, name TEXT, cve TEXT,
    severity TEXT, cvss REAL DEFAULT 0,
    details TEXT, source TEXT, status TEXT DEFAULT 'OPEN'
);
CREATE INDEX idx_vuln_ip ON vulnerabilities(asset_ip);

CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ioc TEXT, ioc_type TEXT, provider TEXT,
    score REAL DEFAULT 0, verdict TEXT, details TEXT,
    source_event_id INTEGER
);
CREATE INDEX idx_ioc ON iocs(ioc);

CREATE TABLE connectors (
    name TEXT PRIMARY KEY,
    kind TEXT,
    config_json TEXT,
    enabled INTEGER DEFAULT 0,
    interval INTEGER DEFAULT 0,
    last_run TEXT, last_error TEXT
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    question TEXT, model TEXT, context TEXT, answer TEXT
);

INSERT INTO events (
    ts, source, source_type, category, host, severity, message, raw, event_hash
) VALUES (
    '2026-08-01T00:00:00+00:00', 'pre-migration-fixture', 'test', 'fixture',
    'fixture-host', 'INFO', 'non-vacuous pre-migration row',
    'fixture event before audit_index migration', 'pre-migration-event-1'
);
