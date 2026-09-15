"""
CyberSentinel Flows API Router.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query
import backend.app.database as db
from backend.app.services.flow_service import get_flow_service

router = APIRouter(tags=["Flows"])

@router.get("/api/flows")
def get_flows(
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    source: Optional[str] = None,
    threat_only: bool = False,
):
    flows = db.get_flows(limit=limit, offset=offset, source=source, threat_only=threat_only)
    total = db.count_flows()
    return {"total": total, "returned": len(flows), "flows": flows}

@router.get("/api/live/flows")
def get_live_flows(limit: int = Query(default=50, le=200)):
    from backend.app.services.live_service import get_live_service
    flows = get_live_service().get_recent_flows()
    if not flows:
        flows = get_flow_service().get_recent_flows(limit=limit)
    return {"flows": flows[:limit]}
