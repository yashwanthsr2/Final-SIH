"""
CyberSentinel SQLite Database Access Layer.

Stores:
- flows
- alerts
- model_metadata
- threat_states
- system_metrics

All operations are thread-safe via a connection-per-thread approach.
Uses only Python's built-in sqlite3 — no extra dependencies.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import DB_PATH


# ============================================================
# THREAD-LOCAL CONNECTION POOL
# ============================================================

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection, creating it if needed."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn


# ============================================================
# SCHEMA INITIALISATION
# ============================================================

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
    flows_total     INTEGER,
    alerts_total    INTEGER,
    ingestion_rate  REAL,
    inference_latency_ms REAL,
    memory_mb       REAL
);
"""


def init_db() -> None:
    """Create all tables if they do not exist."""
    conn = _get_conn()
    conn.executescript(SCHEMA_SQL)
    conn.commit()


# ============================================================
# FLOWS
# ============================================================

def insert_flow(flow: Dict[str, Any]) -> str:
    """Insert a normalised flow record. Returns the flow ID."""
    flow_id = flow.get("id") or str(uuid.uuid4())
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO flows
            (id, timestamp, source, destination, protocol,
             src_port, dst_port, bytes_out, bytes_in,
             packets_out, packets_in, duration,
             threat_flag, threat_class, raw_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            flow_id,
            flow.get("timestamp", time.time()),
            flow.get("source"),
            flow.get("destination"),
            flow.get("protocol"),
            flow.get("src_port"),
            flow.get("dst_port"),
            flow.get("bytes_out", 0),
            flow.get("bytes_in", 0),
            flow.get("packets_out", 0),
            flow.get("packets_in", 0),
            flow.get("duration", 0.0),
            1 if flow.get("threat_flag") else 0,
            flow.get("threat_class"),
            json.dumps(flow),
        ),
    )
    conn.commit()
    return flow_id


def get_flows(
    limit: int = 100,
    offset: int = 0,
    source: Optional[str] = None,
    threat_only: bool = False,
) -> List[Dict[str, Any]]:
    """Retrieve flows with optional filters."""
    conn = _get_conn()
    where_clauses = []
    params: List[Any] = []

    if source:
        where_clauses.append("source = ?")
        params.append(source)
    if threat_only:
        where_clauses.append("threat_flag = 1")

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    params += [limit, offset]

    rows = conn.execute(
        f"SELECT * FROM flows {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()

    return [dict(r) for r in rows]


def count_flows() -> int:
    conn = _get_conn()
    return conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]


# ============================================================
# ALERTS
# ============================================================

def insert_alert(alert: Dict[str, Any]) -> str:
    """Persist an alert. Returns the alert ID."""
    alert_id = alert.get("alert_id") or str(uuid.uuid4())
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts
            (id, timestamp, flow_id, source, destination, protocol,
             threat_class, confidence, risk_score, severity,
             evidence_json, current_state, predicted_next_state,
             prediction_confidence, model_version, correlation_id,
             correlated_threats_json, raw_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            alert_id,
            alert.get("timestamp", time.time()),
            alert.get("flow_id"),
            alert.get("source"),
            alert.get("destination"),
            alert.get("protocol"),
            alert.get("threat_class") or alert.get("primary_threat"),
            alert.get("confidence", alert.get("score", 0.0)),
            alert.get("risk_score", 0),
            alert.get("severity", "LOW"),
            json.dumps(alert.get("evidence", [])),
            alert.get("current_state", "UNKNOWN"),
            alert.get("predicted_next_state", "UNKNOWN"),
            alert.get("prediction_confidence", 0.0),
            alert.get("model_version", "v1.0"),
            alert.get("correlation_id"),
            json.dumps(alert.get("correlated_threats", [])),
            json.dumps(alert),
        ),
    )
    conn.commit()
    return alert_id


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve alerts with optional filters."""
    conn = _get_conn()
    where_clauses = []
    params: List[Any] = []

    if severity:
        where_clauses.append("severity = ?")
        params.append(severity.upper())
    if threat_class:
        where_clauses.append("threat_class = ?")
        params.append(threat_class)
    if source:
        where_clauses.append("source = ?")
        params.append(source)

    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    params += [limit, offset]

    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()

    results = []
    for row in rows:
        d = dict(row)
        # Deserialise JSON fields
        for json_field in ("evidence_json", "correlated_threats_json", "raw_json"):
            raw = d.pop(json_field, None)
            if json_field == "evidence_json":
                d["evidence"] = json.loads(raw) if raw else []
            elif json_field == "correlated_threats_json":
                d["correlated_threats"] = json.loads(raw) if raw else []
            elif json_field == "raw_json" and raw:
                full = json.loads(raw)
                # Merge full alert data (preserving all fields)
                for k, v in full.items():
                    if k not in d:
                        d[k] = v
        results.append(d)

    return results


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    for json_field in ("evidence_json", "correlated_threats_json", "raw_json"):
        raw = d.pop(json_field, None)
        if json_field == "evidence_json":
            d["evidence"] = json.loads(raw) if raw else []
        elif json_field == "correlated_threats_json":
            d["correlated_threats"] = json.loads(raw) if raw else []
        elif json_field == "raw_json" and raw:
            full = json.loads(raw)
            for k, v in full.items():
                if k not in d:
                    d[k] = v
    return d


def count_alerts(severity: Optional[str] = None, threat_class: Optional[str] = None) -> int:
    conn = _get_conn()
    where_clauses = []
    params: List[Any] = []
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity.upper())
    if threat_class:
        where_clauses.append("threat_class = ?")
        params.append(threat_class)
    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    return conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]


def clear_alerts() -> int:
    conn = _get_conn()
    n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.execute("DELETE FROM alerts")
    conn.commit()
    return n


def get_threat_summary() -> Dict[str, Any]:
    """Return aggregate threat statistics from the database."""
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    by_class = conn.execute(
        "SELECT threat_class, COUNT(*) as cnt FROM alerts GROUP BY threat_class ORDER BY cnt DESC"
    ).fetchall()
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    ).fetchall()
    recent_24h = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp > ?",
        (time.time() - 86400,),
    ).fetchone()[0]

    return {
        "total_alerts": total,
        "recent_24h": recent_24h,
        "by_threat_class": [dict(r) for r in by_class],
        "by_severity": [dict(r) for r in by_severity],
    }


# ============================================================
# THREAT STATES
# ============================================================

def upsert_threat_state(source: str, state: str, history: Optional[List] = None) -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO threat_states (source, current_state, last_updated, history_json)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            current_state = excluded.current_state,
            last_updated = excluded.last_updated,
            history_json = excluded.history_json
        """,
        (source, state, time.time(), json.dumps(history or [])),
    )
    conn.commit()


def get_threat_state(source: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM threat_states WHERE source = ?", (source,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["history"] = json.loads(d.pop("history_json", "[]"))
    return d


# ============================================================
# MODEL METADATA
# ============================================================

def upsert_model_metadata(meta: Dict[str, Any]) -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO model_metadata
            (model_name, model_type, model_file, feature_count,
             decision_threshold, training_date, dataset,
             metrics_json, features_json, loaded)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(model_name) DO UPDATE SET
            model_type = excluded.model_type,
            feature_count = excluded.feature_count,
            decision_threshold = excluded.decision_threshold,
            metrics_json = excluded.metrics_json,
            features_json = excluded.features_json,
            loaded = excluded.loaded
        """,
        (
            meta["model_name"],
            meta.get("model_type", ""),
            meta.get("model_file", ""),
            meta.get("feature_count", 0),
            meta.get("decision_threshold", 0.5),
            meta.get("training_date", ""),
            meta.get("dataset", ""),
            json.dumps(meta.get("metrics", {})),
            json.dumps(meta.get("features", [])),
            1 if meta.get("loaded") else 0,
        ),
    )
    conn.commit()


def get_all_models() -> List[Dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM model_metadata").fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["metrics"] = json.loads(d.pop("metrics_json", "{}"))
        d["features"] = json.loads(d.pop("features_json", "[]"))
        results.append(d)
    return results


# ============================================================
# SYSTEM METRICS
# ============================================================

def insert_metric(metric: Dict[str, Any]) -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO system_metrics
            (timestamp, flows_total, alerts_total, ingestion_rate,
             inference_latency_ms, memory_mb)
        VALUES (?,?,?,?,?,?)
        """,
        (
            metric.get("timestamp", time.time()),
            metric.get("flows_total", 0),
            metric.get("alerts_total", 0),
            metric.get("ingestion_rate", 0.0),
            metric.get("inference_latency_ms", 0.0),
            metric.get("memory_mb", 0.0),
        ),
    )
    conn.commit()


def get_recent_metrics(limit: int = 60) -> List[Dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ============================================================
# TIMELINE
# ============================================================

def get_timeline(hours: int = 24, bucket_minutes: int = 10) -> List[Dict[str, Any]]:
    """
    Return threat count bucketed into time intervals for the timeline chart.
    Covers the last `hours` hours in `bucket_minutes`-minute buckets.
    """
    conn = _get_conn()
    since = time.time() - hours * 3600
    bucket_sec = bucket_minutes * 60

    rows = conn.execute(
        """
        SELECT
            CAST(timestamp / ? AS INTEGER) * ? AS bucket,
            COUNT(*) as count,
            GROUP_CONCAT(DISTINCT threat_class) as classes
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY bucket
        ORDER BY bucket
        """,
        (bucket_sec, bucket_sec, since),
    ).fetchall()

    return [
        {
            "bucket": int(r["bucket"]),
            "timestamp_iso": _ts_to_iso(int(r["bucket"])),
            "count": r["count"],
            "classes": (r["classes"] or "").split(","),
        }
        for r in rows
    ]


def _ts_to_iso(ts: int) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
