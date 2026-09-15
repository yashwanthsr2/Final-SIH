"""
CyberSentinel Replay & Live Sensor Control API Router.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException

from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, EVALUATION_DIR
from backend.app.core.baseline_engine import get_baseline_engine
from backend.app.schemas.threat import DetectionRequest, ReplaySpeedRequest
from backend.app.services.alert_service import analyze_request
from backend.app.services.replay_service import VERIFIED_SCENARIOS, get_replay_service
from backend.app.services.live_service import get_live_service
from backend.app.ingestion.zeek_ingest import ZeekLiveSensor
from backend.app.api.websocket import broadcast_sync
import backend.app.database as db

router = APIRouter(tags=["Replay & Live"])

_replay_running = False
_replay_speed = 1.0
_replay_lock = threading.Lock()

def _run_ddos_demo_internal() -> Dict[str, Any]:
    csv_path = EVALUATION_DIR / "packaging" / "verified_attack_input.csv"
    schema_path = MODELS_DIR / "dos_feature_schema.json"
    if not schema_path.exists():
        schema_path = MODELS_DIR / "preprocessing" / "dos_feature_schema.json"

    if not csv_path.exists():
        csv_path = PROJECT_ROOT / "data" / "sample" / "small_demo_dataset.csv"

    ddos_data = pd.read_csv(csv_path)
    if ddos_data.empty:
        raise HTTPException(status_code=500, detail="DDoS demo input is empty")

    if schema_path.exists():
        with open(schema_path) as f:
            schema = json.load(f)
        features = schema.get("features", [])
    else:
        features = list(ddos_data.columns)

    row = ddos_data.iloc[0]
    payload = {f: float(row[f]) for f in features if f in row.index and pd.notnull(row[f])}

    request = DetectionRequest(
        source="192.168.1.50",
        destination="10.0.0.1",
        time_window="VERIFIED-BENCHMARK-WINDOW",
        ddos_features=payload,
    )
    result = analyze_request(request)
    result["demo_source"] = "verified_ddos_csv"
    broadcast_sync({"type": "alert", "data": result})
    return result

@router.get("/demo")
def list_demos():
    return {"scenarios": list(VERIFIED_SCENARIOS.keys()) + ["ddos"]}

@router.post("/demo/ddos")
def demo_ddos():
    return _run_ddos_demo_internal()

@router.post("/demo/run-all")
def demo_run_all():
    results = {}
    for scenario, payload in VERIFIED_SCENARIOS.items():
        try:
            req = DetectionRequest(**payload)
            res = analyze_request(req)
            broadcast_sync({"type": "alert", "data": res})
            results[scenario] = res
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

@router.post("/demo/{scenario}")
def demo_scenario(scenario: str):
    if scenario not in VERIFIED_SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail={"error": "Unknown scenario", "available": list(VERIFIED_SCENARIOS.keys())},
        )
    payload = VERIFIED_SCENARIOS[scenario]
    try:
        req = DetectionRequest(**payload)
        res = analyze_request(req)
        broadcast_sync({"type": "alert", "data": res})
        return res
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

@router.post("/api/replay/start")
@router.post("/demo/replay-live")
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
                    req = DetectionRequest(**payload)
                    res = analyze_request(req)
                    broadcast_sync({"type": "alert", "data": res})
                except Exception:
                    pass
                interval = max(0.1, 0.9 / _replay_speed)
                time.sleep(interval)
            try:
                _run_ddos_demo_internal()
            except Exception:
                pass
        finally:
            _replay_running = False

    threading.Thread(target=worker, name="cybersentinel-replay", daemon=True).start()
    return {"status": "started", "mode": "verified_attack_replay"}

@router.post("/api/replay/stop")
def replay_stop():
    global _replay_running
    _replay_running = False
    return {"status": "stopped"}

@router.post("/api/replay/speed")
def replay_speed(request: ReplaySpeedRequest):
    global _replay_speed
    _replay_speed = request.speed
    return {"status": "ok", "speed": _replay_speed}

class CSVReplayBody(BaseModel):
    file_path: Optional[str] = None
    window_size: int = 50

class PCAPReplayBody(BaseModel):
    file_path: Optional[str] = None
    window_seconds: float = 5.0

class DatasetReplayBody(BaseModel):
    file_path: Optional[str] = None
    limit: int = 100

import re

_VALID_IFACE_RE = re.compile(r"^[a-zA-Z0-9_\-\.\s]{1,64}$")

def _safe_resolve_path(raw_path: Optional[str], default_path: Path) -> Path:
    """Resolve file path and guarantee it resides strictly inside repository data directories."""
    if not raw_path:
        return default_path.resolve()
    candidate = Path(raw_path)
    target = (PROJECT_ROOT / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        target.relative_to(PROJECT_ROOT)
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail="Access denied: file path must reside within repository data directories."
        )
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Target replay file not found: {target.name}")
    return target

def _validate_interface(iface: str) -> str:
    cleaned = iface.strip()
    if cleaned.startswith("-") or not _VALID_IFACE_RE.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid interface name.")
    return cleaned

@router.post("/api/replay/csv")
def replay_csv_endpoint(body: Optional[CSVReplayBody] = None):
    from backend.app.services.replay_service import replay_flow_csv
    default_csv = PROJECT_ROOT / "data" / "sample" / "small_demo_dataset.csv"
    path = _safe_resolve_path(body.file_path if body else None, default_csv)
    win_sz = body.window_size if body else 50
    alerts = replay_flow_csv(path, window_size=win_sz)
    for a in alerts:
        broadcast_sync({"type": "alert", "data": a})
    return {"status": "completed", "file": str(path), "alerts_generated": len(alerts), "alerts": alerts}

@router.post("/api/replay/pcap")
def replay_pcap_endpoint(body: Optional[PCAPReplayBody] = None):
    from backend.app.ingestion.pcap_ingest import replay_pcap_to_alerts
    default_pcap = PROJECT_ROOT / "data" / "sample" / "test_sample.pcap"
    path = _safe_resolve_path(body.file_path if body else None, default_pcap)
    win_sec = body.window_seconds if body else 5.0
    alerts = replay_pcap_to_alerts(path, window_seconds=win_sec)
    for a in alerts:
        broadcast_sync({"type": "alert", "data": a})
    return {"status": "completed", "file": str(path), "alerts_generated": len(alerts), "alerts": alerts}

@router.post("/api/replay/dataset")
def replay_dataset_endpoint(body: Optional[DatasetReplayBody] = None):
    from backend.app.services.replay_service import replay_dataset_batch
    default_ds = PROJECT_ROOT / "data" / "modern_2025" / "UWF-ZeekDataSum25-1" / "Benign" / "part-00000-2ac3ee1a-f94a-44bb-9413-dbfa36b751da-c000.csv"
    path = _safe_resolve_path(body.file_path if body else None, default_ds)
    lim = body.limit if body else 100
    alerts = replay_dataset_batch(path, limit=lim)
    for a in alerts:
        broadcast_sync({"type": "alert", "data": a})
    return {"status": "completed", "file": str(path), "alerts_generated": len(alerts), "alerts": alerts}

# --- Live / Passive Sensor Endpoints ---

@router.get("/api/live/interfaces")
def get_live_interfaces():
    live_srv = get_live_service()
    return {"interfaces": live_srv.get_interfaces()}

@router.get("/live/status")
@router.get("/api/live/status")
def get_live_status():
    live_srv = get_live_service()
    return live_srv.get_status()

class LiveStartBody(BaseModel):
    interface: Optional[str] = None

@router.post("/api/live/start")
@router.post("/live/start")
def live_start(body: Optional[LiveStartBody] = None, interface: Optional[str] = None):
    live_srv = get_live_service()
    target = (body.interface if body else None) or interface or "Wi-Fi"
    clean_target = _validate_interface(target)
    return live_srv.start(interface=clean_target)


@router.post("/api/live/stop")
@router.post("/live/stop")
def live_stop():
    live_srv = get_live_service()
    return live_srv.stop()

@router.get("/api/live/zeek")
def get_live_zeek():
    return ZeekLiveSensor.get_version()

class BaselineStartBody(BaseModel):
    duration: Optional[int] = None
    duration_seconds: Optional[int] = None

@router.post("/api/live/baseline/start")
def live_baseline_start(body: Optional[BaselineStartBody] = None):
    dur = 300
    if body:
        dur = body.duration_seconds or body.duration or 300
    engine = get_baseline_engine()
    return engine.start_learning(duration=dur)

@router.post("/api/live/baseline/stop")
def live_baseline_stop():
    engine = get_baseline_engine()
    return engine.stop()

@router.get("/api/live/baseline/status")
def live_baseline_status():
    engine = get_baseline_engine()
    return engine.get_status()
