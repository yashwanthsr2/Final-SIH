"""
CyberSentinel System, Model, and Metrics Repository.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from backend.app.database.connection import get_connection

def upsert_threat_state(source: str, state: str, history: Optional[List] = None) -> None:
    conn = get_connection()
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
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM threat_states WHERE source = ?", (source,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["history"] = json.loads(d.pop("history_json", "[]"))
    return d

def upsert_model_metadata(meta: Dict[str, Any]) -> None:
    conn = get_connection()
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
            json.dumps(meta.get("metrics") or meta.get("final_test") or {}),
            json.dumps(meta.get("features", [])),
            1 if meta.get("loaded") else 0,
        ),
    )
    conn.commit()

def get_all_models() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM model_metadata").fetchall()
    results = []
    for row in rows:
        d = dict(row)
        m = json.loads(d.pop("metrics_json", "{}"))
        d["metrics"] = m
        d["final_test"] = m
        d["features"] = json.loads(d.pop("features_json", "[]"))
        results.append(d)
    return results

def insert_metric(metric: Dict[str, Any]) -> None:
    conn = get_connection()
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
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]
