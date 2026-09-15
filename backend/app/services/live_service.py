"""
CyberSentinel Live Passive Interface & Baseline Service.
"""

from __future__ import annotations

import psutil
from typing import Any, Dict, List, Optional
from backend.app.core.baseline_engine import get_baseline_engine
from backend.app.ingestion.zeek_ingest import ZeekLiveSensor

try:
    from backend.app.ingestion.live_interface import LiveMonitor
    _live_monitor_available = True
except Exception:
    LiveMonitor = None
    _live_monitor_available = False

def _live_alert_callback(payload: Dict[str, Any]) -> Dict[str, Any]:
    from backend.app.schemas.threat import DetectionRequest
    from backend.app.services.alert_service import analyze_request
    from backend.app.services.broadcast_service import broadcast_sync
    
    req = DetectionRequest(**payload)
    res = analyze_request(req)
    broadcast_sync({"type": "alert", "data": res})
    return res

class LiveService:
    def __init__(self):
        self.baseline = get_baseline_engine()
        self.live_monitor = None
        if _live_monitor_available and LiveMonitor is not None:
            try:
                self.live_monitor = LiveMonitor(
                    detect_callback=_live_alert_callback,
                    default_window_seconds=3,
                )
            except Exception as e:
                self.live_monitor = None

    def get_interfaces(self) -> List[Dict[str, Any]]:
        if self.live_monitor:
            return self.live_monitor.list_interfaces()
        addrs = psutil.net_if_addrs()
        return [{"name": k, "description": k} for k in addrs.keys()]

    def start(self, interface: Optional[str] = None) -> Dict[str, Any]:
        if self.live_monitor:
            return self.live_monitor.start(interface=interface or "Wi-Fi")
        return {"status": "error", "message": "Live monitor not available"}

    def stop(self) -> Dict[str, Any]:
        if self.live_monitor:
            return self.live_monitor.stop()
        return {"status": "error", "message": "Live monitor not available"}

    def get_status(self) -> Dict[str, Any]:
        if self.live_monitor:
            snap = self.live_monitor.snapshot()
            snap["zeek_available"] = bool(ZeekLiveSensor.find_zeek_binary())
            snap["interfaces"] = self.get_interfaces()
            return snap
        return {
            "running": False,
            "interfaces": self.get_interfaces(),
            "zeek_available": bool(ZeekLiveSensor.find_zeek_binary()),
            "baseline_state": self.baseline.state,
        }

    def get_recent_flows(self) -> List[Dict[str, Any]]:
        if self.live_monitor:
            return self.live_monitor.get_recent_flows()
        return []

_live_service = LiveService()

def get_live_service() -> LiveService:
    return _live_service
