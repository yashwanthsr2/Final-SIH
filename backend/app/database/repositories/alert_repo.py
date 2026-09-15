"""
CyberSentinel Alert Repository.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from backend.app.database.connection import get_connection

def insert_alert(alert: Dict[str, Any]) -> str:
    """Persist an alert. Returns the alert ID."""
    alert_id = alert.get("alert_id") or alert.get("id") or str(uuid.uuid4())
    conn = get_connection()
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
    conn = get_connection()
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
        results.append(d)

    return results

def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
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
    conn = get_connection()
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
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.execute("DELETE FROM alerts")
    conn.commit()
    return n

def get_threat_summary() -> Dict[str, Any]:
    """Return aggregate threat statistics from the database."""
    conn = get_connection()
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
