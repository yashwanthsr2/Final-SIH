"""
CyberSentinel Health & System Metrics API Router.
"""

from __future__ import annotations

import time
from fastapi import APIRouter
from backend.app.core.config import APP_VERSION, MODEL_VERSION
from backend.app.services.metrics_service import get_system_telemetry
from backend.app.api.websocket import ws_manager

router = APIRouter(tags=["Health"])
_start_time = time.time()

@router.get("/health")
@router.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "CyberSentinel",
        "version": APP_VERSION,
        "model_version": MODEL_VERSION,
        "detectors": ["DDoS", "C2", "DNS", "ENCRYPTED_TRAFFIC", "RECON", "EXFILTRATION"],
        "uptime_seconds": round(time.time() - _start_time, 1),
        "passive_only": True,
        "no_payload_decryption": True,
    }

@router.get("/api/metrics")
def metrics():
    base = get_system_telemetry()
    return {
        **base,
        "active_websocket_connections": ws_manager.active_count,
    }
