"""
CyberSentinel Threats & Timeline API Router.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query
import backend.app.database as db
from backend.app.correlation import get_engine as get_corr_engine

router = APIRouter(tags=["Threats"])

@router.get("/api/threats")
@router.get("/api/threat-summary")
def threat_summary():
    summary = db.get_threat_summary()
    corr = get_corr_engine().get_all_active_sources()
    return {**summary, "active_correlated_sources": corr}

@router.get("/api/timeline")
def get_timeline(hours: int = Query(default=24, ge=1, le=168)):
    points = db.get_timeline(hours=hours)
    return {"hours": hours, "points": points}
