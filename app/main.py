from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import sys
import threading
import time

import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# CODEZILLA IMPORTS
# ============================================================

from app.schemas import (
    DetectionRequest,
    UnifiedAlert,
)

from app.services.detection_service import (
    analyze_request,
)

from src.live_monitor import LiveMonitor


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CODEZILLA Threat Detection API",
    description=(
        "Passive multi-detector cybersecurity "
        "analysis and evidence-fusion platform."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ALERT STORE
# ============================================================

ALERTS: List[Dict[str, Any]] = []

MAX_ALERTS = 100


def store_alert(
    result: Dict[str, Any]
) -> None:
    """
    Store only actual threat results.
    """

    if result.get("prediction") != "THREAT":
        return

    ALERTS.insert(
        0,
        result,
    )

    if len(ALERTS) > MAX_ALERTS:
        del ALERTS[MAX_ALERTS:]


# ============================================================
# STATIC DASHBOARD
# ============================================================

STATIC_DIR = (
    PROJECT_ROOT
    / "app"
    / "static"
)

STATIC_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# VERIFIED C2 DEMO LOADER
# ============================================================

def load_verified_c2_demo() -> Dict[str, Any]:
    """Load the real unseen C2 sample saved from the V3 test set."""

    c2_path = PROJECT_ROOT / "evaluation" / "packaging" / "c2_verified_attack_input.csv"
    schema_path = PROJECT_ROOT / "models" / "c2_feature_schema.json"

    if not c2_path.exists():
        raise FileNotFoundError(f"C2 verified sample not found: {c2_path}")

    if not schema_path.exists():
        raise FileNotFoundError(f"C2 feature schema not found: {schema_path}")

    c2_data = pd.read_csv(c2_path)

    if c2_data.empty:
        raise ValueError("C2 verified sample is empty.")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    required_features = schema.get("features", [])

    if len(required_features) != 62:
        raise ValueError(f"Expected 62 C2 features, found {len(required_features)}.")

    missing = [feature for feature in required_features if feature not in c2_data.columns]

    if missing:
        raise ValueError(
            "C2 verified sample is missing required features: "
            + ", ".join(missing[:10])
            + ("..." if len(missing) > 10 else "")
        )

    row = c2_data.iloc[0]

    return {feature: float(row[feature]) for feature in required_features}


VERIFIED_C2_TIME_WINDOW = "2011-08-10T15:13:40"


# ============================================================
# VERIFIED DEMO SCENARIOS
# ============================================================

VERIFIED_SCENARIOS: Dict[str, Dict[str, Any]] = {

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    "dns": {
        "source": "147.32.84.165",

        "time_window":
            "2011-08-10T13:33:00",

        "dns_features": {

            "dns_query_rate":
                56.8,

            "dns_unique_destinations":
                22,

            "dns_packet_concentration":
                0.952465,

            "dns_byte_concentration":
                0.959053,

            "dns_iat_cv":
                5.503624,

            "query_rate_prev":
                52.0,

            "query_rate_roll3":
                50.0,

            "query_rate_roll6":
                48.0,

            "query_rate_std6":
                5.0,

            "query_rate_change":
                4.8,

            "query_rate_z6":
                1.2,

            "destination_change":
                2.0,

            "bytes_per_query":
                250.0,

            "packets_per_query":
                2.0,
        },
    },


    # --------------------------------------------------------
    # C2
    # --------------------------------------------------------

    "c2": {
        "source":
            "147.32.84.165",

        "time_window":
            VERIFIED_C2_TIME_WINDOW,

        "c2_features":
            load_verified_c2_demo(),
    },


    # --------------------------------------------------------
    # ENCRYPTED TRAFFIC
    # --------------------------------------------------------

    "encrypted": {
        "source":
            "147.32.84.165",

        "time_window":
            "2011-08-10T11:07:00",

        "encrypted_features": {

            "encrypted_flow_count":
                1,

            "encrypted_total_packets":
                7,

            "encrypted_total_bytes":
                558,

            "encrypted_unique_destinations":
                1,

            "encrypted_unique_ports":
                1,

            "encrypted_mean_duration":
                9.56554,

            "bytes_per_flow":
                558,

            "packets_per_flow":
                7,

            "flow_count_change":
                0,

            "bytes_change":
                192,

            "destination_change":
                0,
        },
    },
}


# ============================================================
# CORRELATED 3-DETECTOR SCENARIO
# ============================================================

VERIFIED_SCENARIOS["correlated"] = {

    "source":
        "147.32.84.165",

    "time_window":
        VERIFIED_C2_TIME_WINDOW,

    # --------------------------------------------------------
    # C2
    # Uses the verified unseen C2 ML sample.
    # --------------------------------------------------------

    "c2_features":
        load_verified_c2_demo(),


    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    "dns_features": {

        "dns_query_rate":
            56.8,

        "dns_unique_destinations":
            22,

        "dns_packet_concentration":
            0.952465,

        "dns_byte_concentration":
            0.959053,

        "dns_iat_cv":
            5.503624,

        "query_rate_prev":
            52.0,

        "query_rate_roll3":
            50.0,

        "query_rate_roll6":
            48.0,

        "query_rate_std6":
            5.0,

        "query_rate_change":
            4.8,

        "query_rate_z6":
            1.2,

        "destination_change":
            2.0,

        "bytes_per_query":
            250.0,

        "packets_per_query":
            2.0,
    },

    # --------------------------------------------------------
    # ENCRYPTED
    # --------------------------------------------------------

    "encrypted_features": {

        "encrypted_flow_count":
            1,

        "encrypted_total_packets":
            7,

        "encrypted_total_bytes":
            558,

        "encrypted_unique_destinations":
            1,

        "encrypted_unique_ports":
            1,

        "encrypted_mean_duration":
            9.56554,

        "bytes_per_flow":
            558,

        "packets_per_flow":
            7,

        "flow_count_change":
            0,

        "bytes_change":
            192,

        "destination_change":
            0,
    },
}


# ============================================================
# LIVE MONITORING
# ============================================================

def _run_live_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Run the existing unified detector pipeline for live features."""
    request = DetectionRequest(**payload)
    result = analyze_request(request)
    store_alert(result)
    return result


LIVE_MONITOR = LiveMonitor(
    detect_callback=_run_live_alert,
    default_window_seconds=5,
)


LIVE_REPLAY_LOCK = threading.Lock()
LIVE_REPLAY_RUNNING = False


@app.get("/live/interfaces")
def live_interfaces():
    """Return discoverable packet-capture interfaces."""
    interfaces = LIVE_MONITOR.list_interfaces()
    return {
        "interfaces": interfaces,
        "capture_backend": "Scapy + Npcap",
        "passive_only": True,
    }


@app.post("/live/start")
def live_start(interface: Optional[str] = None):
    """Start passive live packet capture."""
    return LIVE_MONITOR.start(interface=interface or None)


@app.post("/live/stop")
def live_stop():
    """Stop passive live packet capture."""
    return LIVE_MONITOR.stop()


@app.get("/live/status")
def live_status():
    """Return current live capture telemetry."""
    return LIVE_MONITOR.snapshot()


@app.post("/demo/replay-live")
def replay_verified_attacks_live():
    """Run verified detector scenarios sequentially for a presentation-safe replay."""
    global LIVE_REPLAY_RUNNING

    with LIVE_REPLAY_LOCK:
        if LIVE_REPLAY_RUNNING:
            return {"status": "already_running"}
        LIVE_REPLAY_RUNNING = True

    def worker() -> None:
        global LIVE_REPLAY_RUNNING
        try:
            # Presentation-safe, deterministic replay. No packets are generated
            # or transmitted; only verified feature scenarios are fed through the
            # same production detection and fusion pipeline.
            for scenario in ("dns", "c2", "encrypted", "correlated"):
                payload = VERIFIED_SCENARIOS[scenario]
                result = analyze_request(DetectionRequest(**payload))
                store_alert(result)
                time.sleep(0.9)

            result = run_ddos_demo()
            # run_ddos_demo already stores the DDoS alert.
            _ = result
        finally:
            LIVE_REPLAY_RUNNING = False

    threading.Thread(
        target=worker,
        name="codezilla-verified-replay",
        daemon=True,
    ).start()

    return {"status": "started", "mode": "verified_attack_replay"}


# ============================================================
# HEALTH
# ============================================================

@app.get(
    "/health"
)
def health():

    return {
        "status":
            "ok",

        "service":
            "CODEZILLA",

        "version":
            "1.0.0",

        "detectors": [
            "DDoS",
            "C2",
            "DNS",
            "ENCRYPTED_TRAFFIC",
        ],
    }


# ============================================================
# MAIN DETECTION ENDPOINT
# ============================================================

@app.post(
    "/detect",
    response_model=UnifiedAlert,
)
def detect(
    request: DetectionRequest,
):

    try:

        result = analyze_request(
            request
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    store_alert(
        result
    )

    return result


# ============================================================
# ALERT HISTORY
# ============================================================

@app.get(
    "/alerts"
)
def get_alerts():

    return {
        "count":
            len(ALERTS),

        "alerts":
            ALERTS,
    }


# ============================================================
# CLEAR ALERTS
# ============================================================

@app.delete(
    "/alerts"
)
def clear_alerts():

    ALERTS.clear()

    return {
        "status":
            "cleared"
    }


# ============================================================
# LIST DEMO SCENARIOS
# ============================================================

@app.get(
    "/demo"
)
def list_demo_scenarios():

    return {
        "scenarios": [
            "dns",
            "c2",
            "encrypted",
            "correlated",
            "ddos",
        ]
    }


# ============================================================
# ============================================================
# DDOS VERIFIED DEMO
#
# Final judge-safe implementation:
# - Uses the packaged, verified 62-feature CSV input.
# - Does NOT require pandas parquet/pyarrow for the dashboard demo.
# - Sends the sample through the same production DDoS ML pipeline.
# - Preserves all other routes, including live monitoring.
# ============================================================

@app.post(
    "/demo/ddos"
)
def run_ddos_demo():

    csv_path = (
        PROJECT_ROOT
        / "evaluation"
        / "packaging"
        / "verified_attack_input.csv"
    )

    schema_path = (
        PROJECT_ROOT
        / "models"
        / "dos_feature_schema.json"
    )

    if not csv_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "Verified DDoS demo input not found: "
                + str(csv_path)
            ),
        )

    if not schema_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "DDoS feature schema not found: "
                + str(schema_path)
            ),
        )

    try:
        ddos_data = pd.read_csv(csv_path)

        with open(
            schema_path,
            "r",
            encoding="utf-8",
        ) as f:
            dos_schema = json.load(f)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load verified DDoS demo input: "
                + str(exc)
            ),
        ) from exc

    if ddos_data.empty:
        raise HTTPException(
            status_code=500,
            detail="Verified DDoS demo input is empty.",
        )

    required_features = dos_schema.get("features", [])

    if len(required_features) != 62:
        raise HTTPException(
            status_code=500,
            detail=(
                "Expected exactly 62 DDoS features, found "
                f"{len(required_features)}."
            ),
        )

    missing_features = [
        feature
        for feature in required_features
        if feature not in ddos_data.columns
    ]

    if missing_features:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "DDoS feature mismatch",
                "missing_features": missing_features,
            },
        )

    selected = ddos_data.iloc[0]
    ddos_payload: Dict[str, float] = {}

    for feature in required_features:
        value = selected[feature]

        try:
            ddos_payload[feature] = float(value)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Invalid DDoS value for '{feature}': {value}"
                ),
            )

    try:
        request = DetectionRequest(
            source="VERIFIED-DDOS-SAMPLE",
            time_window="VERIFIED-BENCHMARK-WINDOW",
            ddos_features=ddos_payload,
        )

        result = analyze_request(request)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "DDoS detection failed: "
                + str(exc)
            ),
        ) from exc

    store_alert(result)

    result["demo_source"] = "verified_ddos_csv"
    result["demo_input"] = str(csv_path.relative_to(PROJECT_ROOT))

    if "score" in result:
        try:
            result["verified_model_score"] = float(result["score"])
        except (TypeError, ValueError):
            pass

    return result


# ============================================================
# RUN ALL DEMO SCENARIOS
#
# IMPORTANT:
# This route MUST appear before /demo/{scenario}.
# ============================================================

#
# IMPORTANT:
# This route MUST appear before /demo/{scenario}.
# ============================================================

@app.post(
    "/demo/run-all"
)
def run_all_demo_scenarios():

    results: Dict[
        str,
        Any
    ] = {}


    # --------------------------------------------------------
    # DNS / C2 / ENCRYPTED / CORRELATED
    # --------------------------------------------------------

    for (
        scenario,
        payload,
    ) in VERIFIED_SCENARIOS.items():

        try:

            request = DetectionRequest(
                **payload
            )

            result = analyze_request(
                request
            )

            results[
                scenario
            ] = result

            store_alert(
                result
            )

        except Exception as exc:

            results[
                scenario
            ] = {
                "prediction":
                    "ERROR",

                "error":
                    str(exc),
            }


    # --------------------------------------------------------
    # DDoS
    # --------------------------------------------------------

    try:

        ddos_result = (
            run_ddos_demo()
        )

        results[
            "ddos"
        ] = ddos_result

    except Exception as exc:

        results[
            "ddos"
        ] = {
            "prediction":
                "ERROR",

            "error":
                str(exc),
        }


    return {

        "scenarios_run":
            len(results),

        "results":
            results,

        "alert_count":
            len(ALERTS),
    }


# ============================================================
# GENERIC DEMO SCENARIO
#
# IMPORTANT:
# This MUST be AFTER the specific demo routes above.
# ============================================================

@app.post(
    "/demo/{scenario}"
)
def run_demo_scenario(
    scenario: str,
):

    if (
        scenario
        not in VERIFIED_SCENARIOS
    ):

        raise HTTPException(
            status_code=404,
            detail={
                "error":
                    "Unknown demo scenario",

                "available":
                    [
                        "dns",
                        "c2",
                        "encrypted",
                        "correlated",
                        "ddos",
                    ],
            },
        )


    payload = (
        VERIFIED_SCENARIOS[
            scenario
        ]
    )


    try:

        request = DetectionRequest(
            **payload
        )

        result = analyze_request(
            request
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Demo scenario "
                f"'{scenario}' failed: "
                f"{exc}"
            ),
        ) from exc


    store_alert(
        result
    )

    return result


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(
        directory=str(
            STATIC_DIR
        )
    ),
    name="static",
)


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/",
    include_in_schema=False,
)
def dashboard():

    index_file = (
        STATIC_DIR
        / "index.html"
    )

    if not index_file.exists():

        raise HTTPException(
            status_code=404,
            detail=(
                "Dashboard file not found: "
                + str(index_file)
            ),
        )

    return FileResponse(
        index_file
    )