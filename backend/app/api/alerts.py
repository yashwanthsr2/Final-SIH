"""
CyberSentinel Alerts & Detection API Router.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.app.schemas.threat import DetectionRequest
from backend.app.services.alert_service import analyze_request
from backend.app.api.websocket import broadcast_sync
from backend.app.digital_twin import get_twin
import backend.app.database as db

router = APIRouter(tags=["Alerts"])

@router.get("/api/alerts")
@router.get("/alerts")
def get_alerts(
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    severity: Optional[str] = None,
    threat_class: Optional[str] = None,
    source: Optional[str] = None,
):
    alerts = db.get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        threat_class=threat_class,
        source=source,
    )
    total = db.count_alerts(severity=severity, threat_class=threat_class)
    return {"count": total, "returned": len(alerts), "alerts": alerts}

@router.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert

@router.delete("/api/alerts")
@router.delete("/alerts")
def clear_alerts():
    n = db.clear_alerts()
    return {"status": "cleared", "removed": n}

@router.post("/detect")
async def detect(request: DetectionRequest):
    result = analyze_request(request)
    broadcast_sync({"type": "alert", "data": result})
    return result
