"""
CyberSentinel Database Schemas & DDL.
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    timestamp   REAL NOT NULL,
    source      TEXT,
    destination TEXT,
    protocol    TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    bytes_out   INTEGER,
    bytes_in    INTEGER,
    packets_out INTEGER,
    packets_in  INTEGER,
    duration    REAL,
    threat_flag INTEGER DEFAULT 0,
    threat_class TEXT,
    raw_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(source);

CREATE TABLE IF NOT EXISTS alerts (
    id                  TEXT PRIMARY KEY,
    timestamp           REAL NOT NULL,
    flow_id             TEXT,
    source              TEXT,
    destination         TEXT,
    protocol            TEXT,
    threat_class        TEXT,
    confidence          REAL,
    risk_score          INTEGER,
    severity            TEXT,
    evidence_json       TEXT,
    current_state       TEXT,
    predicted_next_state TEXT,
    prediction_confidence REAL,
    model_version       TEXT,
    correlation_id      TEXT,
    correlated_threats_json TEXT,
    raw_json            TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(source);
CREATE INDEX IF NOT EXISTS idx_alerts_class ON alerts(threat_class);

CREATE TABLE IF NOT EXISTS threat_states (
    source          TEXT PRIMARY KEY,
    current_state   TEXT NOT NULL DEFAULT 'NORMAL',
    last_updated    REAL NOT NULL,
    history_json    TEXT
);

CREATE TABLE IF NOT EXISTS model_metadata (
    model_name      TEXT PRIMARY KEY,
    model_type      TEXT,
    model_file      TEXT,
    feature_count   INTEGER,
    decision_threshold REAL,
    training_date   TEXT,
    dataset         TEXT,
    metrics_json    TEXT,
    features_json   TEXT,
    loaded          INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS system_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL NOT NULL,
    flows_per_sec   REAL,
    alerts_total    INTEGER,
    active_threats  INTEGER,
    cpu_percent     REAL,
    memory_percent  REAL
);

CREATE INDEX IF NOT EXISTS idx_metrics_ts ON system_metrics(timestamp DESC);
"""
