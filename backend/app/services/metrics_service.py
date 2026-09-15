"""
CyberSentinel Metrics & Telemetry Service.
"""

from __future__ import annotations

import time
from typing import Any, Dict
import backend.app.database as db
from backend.app.core.config import APP_VERSION

_start_time = time.time()

def get_system_telemetry() -> Dict[str, Any]:
    uptime = time.time() - _start_time
    return {
        "flows_total": db.count_flows(),
        "alerts_total": db.count_alerts(),
        "uptime_seconds": round(uptime, 1),
        "detectors_active": 6,
        "version": APP_VERSION,
    }
