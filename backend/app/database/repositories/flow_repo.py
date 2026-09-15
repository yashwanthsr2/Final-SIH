"""
CyberSentinel Flow Repository.
"""

from __future__ import annotations

import datetime
import json
import time
import uuid
from typing import Any, Dict, List, Optional
from backend.app.database.connection import get_connection

def insert_flow(flow: Dict[str, Any]) -> str:
    """Insert a normalised flow record. Returns the flow ID."""
    flow_id = flow.get("id") or flow.get("flow_id") or str(uuid.uuid4())
    conn = get_connection()
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
            flow.get("source") or flow.get("source_ip"),
            flow.get("destination") or flow.get("destination_ip"),
            flow.get("protocol"),
            flow.get("src_port") or flow.get("source_port"),
            flow.get("dst_port") or flow.get("destination_port"),
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
    conn = get_connection()
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
    conn = get_connection()
    return conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

def get_timeline(hours: int = 24, bucket_minutes: int = 10) -> List[Dict[str, Any]]:
    """Return threat count bucketed into time intervals for the timeline chart."""
    conn = get_connection()
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
            "timestamp_iso": datetime.datetime.fromtimestamp(int(r["bucket"]), tz=datetime.timezone.utc).isoformat() + "Z",
            "count": r["count"],
            "classes": (r["classes"] or "").split(","),
        }
        for r in rows
    ]
