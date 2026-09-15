"""
CyberSentinel FastAPI Backend
SIH26-26145 — NTRO / Blockchain & Cybersecurity

Passive AI threat detection platform.
No packets transmitted. No endpoint probing. No payload decryption.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from pydantic import BaseModel

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# ============================================================
# PATH SETUP
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ============================================================
# CORE IMPORTS
# ============================================================

from app.schemas import DetectionRequest, ReplaySpeedRequest, UnifiedAlert
from app.services.detection_service import analyze_request
from app.core.config import APP_VERSION, MODEL_VERSION, MAX_ALERTS_MEMORY
import app.core.database as db
from app.core.digital_twin import get_twin
from app.core.correlation import get_engine as get_corr_engine
from app.core.trajectory import get_engine as get_traj_engine
from app.core.baseline_engine import get_baseline_engine
from src.zeek_sensor import ZeekLiveSensor

# Live monitor is optional (needs Scapy/Npcap)
try:
    from src.live_monitor import LiveMonitor
    _live_monitor_available = True
except Exception:
    _live_monitor_available = False

# ============================================================
# STARTUP
# ============================================================

db.init_db()

_start_time = time.time()
_flows_processed = 0
_flows_lock = threading.Lock()

# ============================================================
# WEBSOCKET MANAGER
# ============================================================

class ConnectionManager:
    """Manages active WebSocket connections for the live feed."""

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        async with self._lock:
            dead = []
            for ws in self._connections:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._connections.remove(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)


ws_manager = ConnectionManager()

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="CyberSentinel Threat Detection API",
    description=(
        "SIH26-26145 — Passive AI-powered network threat detection platform. "
        "Detects, explains, correlates, and predicts cyber threats "
        "from unidirectional IP traffic metadata. "
        "No payloads decrypted. No packets transmitted."
    ),
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# LIVE MONITOR SETUP
# ============================================================

def _live_alert_callback(payload: Dict[str, Any]) -> Dict[str, Any]:
    request = DetectionRequest(**payload)
    result = analyze_request(request)
    _broadcast_sync({"type": "alert", "data": result})
    return result


if _live_monitor_available:
    LIVE_MONITOR = LiveMonitor(
        detect_callback=_live_alert_callback,
        default_window_seconds=5,
    )
else:
    LIVE_MONITOR = None

# ============================================================
# REPLAY ENGINE STATE
# ============================================================

_replay_running = False
_replay_speed = 1.0
_replay_lock = threading.Lock()

# ============================================================
# MODEL METADATA — load from disk once at startup
# ============================================================

def _load_model_metadata() -> List[Dict[str, Any]]:
    models_dir = PROJECT_ROOT / "models"
    metadata_files = list(models_dir.glob("*_metadata.json"))

    results = []
    for mf in metadata_files:
        try:
            with open(mf, encoding="utf-8") as f:
                meta = json.load(f)
            # Check if joblib file exists
            joblib_name = mf.stem.replace("_metadata", "_hgb") + ".joblib"
            joblib_path = models_dir / joblib_name
            meta["model_file"] = joblib_name
            meta["loaded"] = joblib_path.exists()
            meta["file_size_kb"] = (
                round(joblib_path.stat().st_size / 1024, 1)
                if joblib_path.exists() else 0
            )
            results.append(meta)
        except Exception:
            pass

    # Seed database
    for meta in results:
        try:
            db.upsert_model_metadata(meta)
        except Exception:
            pass

    return results


_MODEL_METADATA = _load_model_metadata()

# ============================================================
# DEMO SCENARIOS (verified — no randomness)
# ============================================================

def _load_verified_c2() -> Dict[str, float]:
    c2_path = PROJECT_ROOT / "evaluation" / "packaging" / "c2_verified_attack_input.csv"
    schema_path = PROJECT_ROOT / "models" / "c2_feature_schema.json"
    if not c2_path.exists() or not schema_path.exists():
        return {}
    df = pd.read_csv(c2_path)
    if df.empty:
        return {}
    with open(schema_path) as f:
        schema = json.load(f)
    features = schema.get("features", [])
    row = df.iloc[0]
    return {f: float(row[f]) for f in features if f in row.index}


VERIFIED_SCENARIOS: Dict[str, Dict[str, Any]] = {
    # Real positive from dns_source_features.parquet (model proba ~0.79)
    "dns": {
        "source": "147.32.84.165",
        "destination": "8.8.8.8",
        "domain": "tunnel.apt29-data.net",
        "time_window": "2011-08-10T13:33:00",
        "dns_features": {
            "dns_query_count": 2.0,
            "dns_total_packets": 4.0,
            "dns_total_bytes": 793.0,
            "dns_unique_destinations": 1.0,
            "dns_query_rate": 0.2,
            "dns_max_destination_count": 2.0,
            "dns_packet_concentration": 1.0,
            "dns_max_destination_bytes": 793.0,
            "dns_byte_concentration": 1.0,
            "dns_iat_mean": 2.255544,
            "dns_iat_std": 0.0,
            "dns_iat_median": 2.255544,
            "dns_iat_cv": 0.0,
            "query_rate_prev": 0.0,
            "query_rate_roll3": 0.2,
            "query_rate_roll6": 0.2,
            "query_rate_std6": 0.0,
            "query_rate_change": 0.0,
            "query_rate_z6": 0.0,
            "destination_change": 0.0,
            "bytes_per_query": 396.5,
            "packets_per_query": 2.0,
        },
    },
    # Real positive from c2_features.parquet (model proba ~0.54)
    "c2": {
        "source": "147.32.84.165",
        "destination": "198.51.100.24",
        "time_window": "2011-08-10T15:13:40",
        "c2_features": {
            "flow_count": 595.0,
            "unique_destinations": 73.0,
            "unique_ports": 34.0,
            "total_packets": 8337.0,
            "total_bytes": 4494266.0,
            "mean_packets": 14.011765,
            "mean_bytes": 7553.388235,
            "mean_duration": 356.795946,
            "max_destination_count": 223.0,
            "destination_concentration": 0.37479,
            "iat_mean": 9.602416,
            "iat_std": 80.3288,
            "iat_median": 0.009076,
            "iat_min": 0.000004,
            "iat_max": 1489.884621,
            "iat_cv": 8.365478,
            "max_pair_repetition": 215.0,
            "pair_repetition_ratio": 0.361345,
            "destination_entropy": 2.784545,
        },
    },
    # Real positive from encrypted_source_features.parquet (model proba ~0.54)
    "encrypted": {
        "source": "147.32.84.165",
        "destination": "185.220.101.5",
        "time_window": "2011-08-10T11:07:00",
        "encrypted_features": {
            "encrypted_flow_count": 1.0,
            "encrypted_total_packets": 7.0,
            "encrypted_total_bytes": 558.0,
            "encrypted_unique_destinations": 1.0,
            "encrypted_unique_ports": 1.0,
            "encrypted_mean_duration": 9.560554,
            "bytes_per_flow": 558.0,
            "packets_per_flow": 7.0,
            "flow_count_prev": 1.0,
            "flow_count_change": 0.0,
            "bytes_prev": 366.0,
            "bytes_change": 192.0,
            "destination_change": 0.0,
        },
    },
    # Statistical recon scenario (high port diversity + SYN scan)
    "recon": {
        "source": "10.0.0.45",
        "destination": "10.0.0.1",
        "time_window": "2025-01-15T09:22:00",
        "recon_features": {
            "unique_dst_ports": 48,
            "unique_destinations": 12,
            "flow_count": 320,
            "window_seconds": 60.0,
            "total_bytes": 14400,
            "mean_syn_count": 0.85,
            "total_packets": 320,
        },
    },
    # Statistical exfil scenario (8.5MB outbound asymmetric)
    "exfil": {
        "source": "192.168.1.102",
        "destination": "203.0.113.88",
        "time_window": "2025-01-15T02:14:00",
        "exfil_features": {
            "bytes_out": 8_500_000,
            "bytes_in": 1_200,
            "unique_destinations": 1,
            "flow_count": 3,
            "mean_flow_duration": 480.0,
            "window_seconds": 600.0,
        },
    },
}

# Correlated scenario: DNS + C2 + Encrypted from same source
VERIFIED_SCENARIOS["correlated"] = {
    "source": "147.32.84.165",
    "destination": "198.51.100.24",
    "domain": "c2.stealth-ops.org",
    "time_window": "2011-08-10T15:13:40",
    "c2_features": VERIFIED_SCENARIOS["c2"]["c2_features"],
    "dns_features": VERIFIED_SCENARIOS["dns"]["dns_features"],
    "encrypted_features": VERIFIED_SCENARIOS["encrypted"]["encrypted_features"],
}



# ============================================================
# ============================================================
# API ROUTES
# ============================================================
# ============================================================

# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
@app.get("/api/health")
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


# ============================================================
# METRICS
# ============================================================

@app.get("/api/metrics")
def get_metrics():
    alerts_total = db.count_alerts()
    flows_total = db.count_flows()
    uptime = time.time() - _start_time
    return {
        "flows_total": flows_total,
        "alerts_total": alerts_total,
        "active_websocket_connections": ws_manager.active_count,
        "uptime_seconds": round(uptime, 1),
        "replay_running": _replay_running,
        "replay_speed": _replay_speed,
        "detectors_active": 6,
        "version": APP_VERSION,
    }


# ============================================================
# ALERTS
# ============================================================

@app.get("/api/alerts")
@app.get("/alerts")
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


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@app.delete("/api/alerts")
@app.delete("/alerts")
def clear_alerts():
    n = db.clear_alerts()
    get_twin().clear()
    return {"status": "cleared", "removed": n}


# ============================================================
# THREATS
# ============================================================

@app.get("/api/threats")
@app.get("/api/threat-summary")
def threat_summary():
    summary = db.get_threat_summary()
    corr = get_corr_engine().get_all_active_sources()
    return {**summary, "active_correlated_sources": corr}


# ============================================================
# FLOWS
# ============================================================

@app.get("/api/flows")
def get_flows(
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    source: Optional[str] = None,
    threat_only: bool = False,
):
    flows = db.get_flows(limit=limit, offset=offset, source=source, threat_only=threat_only)
    total = db.count_flows()
    return {"count": total, "returned": len(flows), "flows": flows}


# ============================================================
# NETWORK (DIGITAL TWIN)
# ============================================================

@app.get("/api/network")
def get_network(
    include_ports: bool = False,
    limit_nodes: int = Query(default=120, le=300),
):
    twin = get_twin()
    return twin.get_graph(include_ports=include_ports, limit_nodes=limit_nodes)


# ============================================================
# TIMELINE
# ============================================================

@app.get("/api/timeline")
def get_timeline(hours: int = 24, bucket_minutes: int = 10):
    return {"timeline": db.get_timeline(hours=hours, bucket_minutes=bucket_minutes)}


# ============================================================
# TRAJECTORY
# ============================================================

@app.get("/api/trajectory")
def get_all_trajectories():
    return {"trajectories": get_traj_engine().get_all_trajectories()}


@app.get("/api/trajectory/{source}")
def get_trajectory(source: str):
    traj = get_traj_engine().get_trajectory(source)
    if not traj:
        # Return default for unknown source
        return {
            "source": source,
            "current_state": "NORMAL",
            "predicted_next_state": "NORMAL",
            "prediction_confidence": 0.0,
            "state_history": [],
        }
    return traj


# ============================================================
# MODELS
# ============================================================

@app.get("/api/models")
def get_models():
    models = db.get_all_models()
    if not models:
        models = _MODEL_METADATA
    return {"models": models, "total": len(models)}


@app.post("/api/reload-model")
def reload_model():
    """
    Reload model metadata from disk.
    Does not restart the server — updates the in-memory cache.
    """
    global _MODEL_METADATA
    _MODEL_METADATA = _load_model_metadata()
    return {"status": "reloaded", "models": len(_MODEL_METADATA)}


# ============================================================
# MAIN DETECTION ENDPOINT
# ============================================================

@app.post("/detect", response_model=UnifiedAlert)
@app.post("/api/detect", response_model=UnifiedAlert)
def detect(request: DetectionRequest):
    try:
        result = analyze_request(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


# ============================================================
# LIVE MONITORING
# ============================================================

class LiveStartBody(BaseModel):
    interface: Optional[str] = "Wi-Fi"


@app.get("/live/interfaces")
@app.get("/api/live/interfaces")
def live_interfaces():
    if LIVE_MONITOR is None:
        return {"interfaces": [{"name": "Wi-Fi", "description": "Default Wireless Interface"}], "capture_backend": "Driverless Native Socket", "passive_only": True}
    interfaces = LIVE_MONITOR.list_interfaces()
    return {"interfaces": interfaces, "capture_backend": "Scapy + Native Socket (Dual Backend)", "passive_only": True}


@app.post("/live/start")
@app.post("/api/live/start")
def live_start(body: Optional[LiveStartBody] = None, interface: Optional[str] = None):
    if LIVE_MONITOR is None:
        return {"status": "unavailable", "reason": "Monitor engine unavailable"}
    target = (body.interface if body else None) or interface or "Wi-Fi"
    return LIVE_MONITOR.start(interface=target)


@app.post("/live/stop")
@app.post("/api/live/stop")
def live_stop():
    if LIVE_MONITOR is None:
        return {"status": "unavailable"}
    return LIVE_MONITOR.stop()


@app.get("/live/status")
@app.get("/api/live/status")
def live_status():
    if LIVE_MONITOR is None:
        return {"running": False, "status": "unavailable"}
    return LIVE_MONITOR.snapshot()


class BaselineStartBody(BaseModel):
    duration: Optional[int] = None
    duration_seconds: Optional[int] = None


@app.post("/api/live/baseline/start")
def live_baseline_start(body: Optional[BaselineStartBody] = None):
    dur = 300
    if body:
        dur = body.duration_seconds or body.duration or 300
    engine = get_baseline_engine()
    return engine.start_learning(duration=dur)


@app.post("/api/live/baseline/stop")
def live_baseline_stop():
    engine = get_baseline_engine()
    return engine.stop()


@app.get("/api/live/baseline/status")
def live_baseline_status():
    engine = get_baseline_engine()
    return engine.get_status()


@app.get("/api/live/flows")
def live_flows():
    if LIVE_MONITOR:
        return {"flows": LIVE_MONITOR.get_recent_flows(), "source": "live_sensor"}
    return {"flows": [], "source": "none"}


@app.get("/api/live/zeek")
def live_zeek_info():
    return ZeekLiveSensor.get_version()


# ============================================================
# REPLAY ENGINE
# ============================================================

@app.post("/api/replay/start")
@app.post("/demo/replay-live")
def replay_start():
    global _replay_running
    with _replay_lock:
        if _replay_running:
            return {"status": "already_running"}
        _replay_running = True

    def worker():
        global _replay_running
        try:
            scenarios = ["recon", "dns", "c2", "encrypted", "exfil", "correlated"]
            for scenario in scenarios:
                payload = VERIFIED_SCENARIOS.get(scenario, {})
                if not payload:
                    continue
                try:
                    request = DetectionRequest(**payload)
                    result = analyze_request(request)
                    # Broadcast over WS
                    _broadcast_sync({"type": "alert", "data": result})
                except Exception:
                    pass
                interval = max(0.1, 0.9 / _replay_speed)
                time.sleep(interval)

            # DDoS scenario
            try:
                _run_ddos_demo_internal()
            except Exception:
                pass
        finally:
            _replay_running = False

    threading.Thread(target=worker, name="cybersentinel-replay", daemon=True).start()
    return {"status": "started", "mode": "verified_attack_replay"}


@app.post("/api/replay/stop")
def replay_stop():
    global _replay_running
    _replay_running = False
    return {"status": "stopped"}


@app.post("/api/replay/speed")
def replay_speed(request: ReplaySpeedRequest):
    global _replay_speed
    _replay_speed = request.speed
    return {"status": "ok", "speed": _replay_speed}


def _broadcast_sync(message: Dict[str, Any]) -> None:
    """Attempt to broadcast from a sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), loop)
    except Exception:
        pass


# ============================================================
# DEMO SCENARIOS
# ============================================================

@app.get("/demo")
def list_demos():
    return {"scenarios": list(VERIFIED_SCENARIOS.keys()) + ["ddos"]}


@app.post("/demo/ddos")
def demo_ddos():
    return _run_ddos_demo_internal()


def _run_ddos_demo_internal() -> Dict[str, Any]:
    csv_path = PROJECT_ROOT / "evaluation" / "packaging" / "verified_attack_input.csv"
    schema_path = PROJECT_ROOT / "models" / "dos_feature_schema.json"

    if not csv_path.exists():
        raise HTTPException(status_code=404, detail=f"DDoS demo input not found: {csv_path}")

    ddos_data = pd.read_csv(csv_path)
    if ddos_data.empty:
        raise HTTPException(status_code=500, detail="DDoS demo input is empty")

    with open(schema_path) as f:
        schema = json.load(f)

    features = schema.get("features", [])
    row = ddos_data.iloc[0]
    payload = {f: float(row[f]) for f in features if f in row.index}

    request = DetectionRequest(
        source="192.168.1.50",
        destination="10.0.0.1",
        time_window="VERIFIED-BENCHMARK-WINDOW",
        ddos_features=payload,
    )
    result = analyze_request(request)
    result["demo_source"] = "verified_ddos_csv"
    return result


@app.post("/demo/run-all")
def demo_run_all():
    results = {}

    for scenario, payload in VERIFIED_SCENARIOS.items():
        try:
            request = DetectionRequest(**payload)
            results[scenario] = analyze_request(request)
        except Exception as exc:
            results[scenario] = {"prediction": "ERROR", "error": str(exc)}

    try:
        results["ddos"] = _run_ddos_demo_internal()
    except Exception as exc:
        results["ddos"] = {"prediction": "ERROR", "error": str(exc)}

    return {
        "scenarios_run": len(results),
        "results": results,
        "alert_count": db.count_alerts(),
    }


@app.post("/demo/{scenario}")
def demo_scenario(scenario: str):
    if scenario not in VERIFIED_SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail={"error": "Unknown scenario", "available": list(VERIFIED_SCENARIOS.keys())},
        )
    payload = VERIFIED_SCENARIOS[scenario]
    try:
        request = DetectionRequest(**payload)
        result = analyze_request(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


# ============================================================
# WEBSOCKET — LIVE FEED
# ============================================================

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial state snapshot
        alerts = db.get_alerts(limit=10)
        await websocket.send_json({
            "type": "snapshot",
            "alerts": alerts,
            "metrics": {
                "alerts_total": db.count_alerts(),
                "flows_total": db.count_flows(),
            },
        })
        # Keep connection alive; updates are pushed from detection pipeline
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                # Send periodic heartbeat with current metrics
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": time.time(),
                    "alerts_total": db.count_alerts(),
                    "flows_total": db.count_flows(),
                    "replay_running": _replay_running,
                })
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket)


# ============================================================
# STATIC DASHBOARD
# ============================================================

STATIC_DIR = PROJECT_ROOT / "app" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return FileResponse(index_file)