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
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


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

from src.recon_exfil_live import (
    attach_live_monitor,
)


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

ALERTS: List[
    Dict[str, Any]
] = []

MAX_ALERTS = 100


def store_alert(
    result: Dict[str, Any],
) -> None:
    """
    Store only actual threat results.
    """

    if result.get(
        "prediction"
    ) != "THREAT":

        return

    ALERTS.insert(
        0,
        result,
    )

    if len(ALERTS) > MAX_ALERTS:

        del ALERTS[
            MAX_ALERTS:
        ]


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
    """
    Load the real unseen C2 sample saved from the V3 test set.
    """

    c2_path = (
        PROJECT_ROOT
        / "evaluation"
        / "packaging"
        / "c2_verified_attack_input.csv"
    )

    schema_path = (
        PROJECT_ROOT
        / "models"
        / "c2_feature_schema.json"
    )

    if not c2_path.exists():

        raise FileNotFoundError(
            f"C2 verified sample not found: {c2_path}"
        )

    if not schema_path.exists():

        raise FileNotFoundError(
            f"C2 feature schema not found: {schema_path}"
        )

    c2_data = pd.read_csv(
        c2_path
    )

    if c2_data.empty:

        raise ValueError(
            "C2 verified sample is empty."
        )

    with open(
        schema_path,
        "r",
        encoding="utf-8",
    ) as f:

        schema = json.load(
            f
        )

    required_features = (
        schema.get(
            "features",
            [],
        )
    )

    if len(
        required_features
    ) != 62:

        raise ValueError(
            "Expected 62 C2 features, "
            f"found {len(required_features)}."
        )

    missing = [
        feature
        for feature in required_features
        if feature not in c2_data.columns
    ]

    if missing:

        raise ValueError(
            "C2 verified sample is missing "
            "required features: "
            + ", ".join(
                missing[:10]
            )
            + (
                "..."
                if len(missing) > 10
                else ""
            )
        )

    row = c2_data.iloc[0]

    return {
        feature: float(
            row[feature]
        )
        for feature in required_features
    }


VERIFIED_C2_TIME_WINDOW = (
    "2011-08-10T15:13:40"
)


# ============================================================
# VERIFIED DEMO SCENARIOS
# ============================================================

VERIFIED_SCENARIOS: Dict[
    str,
    Dict[str, Any],
] = {

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    "dns": {

        "source":
            "147.32.84.165",

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

VERIFIED_SCENARIOS[
    "correlated"
] = {

    "source":
        "147.32.84.165",

    "time_window":
        VERIFIED_C2_TIME_WINDOW,

    # --------------------------------------------------------
    # C2
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


def _run_live_alert(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run the unified detector pipeline for live features.
    """

    request = DetectionRequest(
        **payload
    )

    result = analyze_request(
        request
    )

    store_alert(
        result
    )

    return result


LIVE_MONITOR = LiveMonitor(
    detect_callback=_run_live_alert,
    default_window_seconds=5,
)


# ============================================================
# EXTENDED LIVE DETECTORS
#
# Adds:
#   - Reconnaissance
#   - Data Exfiltration
#
# without replacing the existing four-detector
# LiveMonitor implementation.
# ============================================================

attach_live_monitor(
    LIVE_MONITOR,
    _run_live_alert,
)


# ============================================================
# LIVE REPLAY STATE
# ============================================================

LIVE_REPLAY_LOCK = (
    threading.Lock()
)

LIVE_REPLAY_RUNNING = False


# ============================================================
# LIVE INTERFACES
# ============================================================


@app.get(
    "/live/interfaces"
)
def live_interfaces():
    """
    Return discoverable packet-capture interfaces.
    """

    interfaces = (
        LIVE_MONITOR.list_interfaces()
    )

    return {
        "interfaces":
            interfaces,

        "capture_backend":
            "Scapy + Npcap",

        "passive_only":
            True,
    }


# ============================================================
# START LIVE CAPTURE
# ============================================================


@app.post(
    "/live/start"
)
def live_start(
    interface: Optional[str] = None,
):
    """
    Start passive live packet capture.
    """

    return LIVE_MONITOR.start(
        interface=interface or None
    )


# ============================================================
# STOP LIVE CAPTURE
# ============================================================


@app.post(
    "/live/stop"
)
def live_stop():
    """
    Stop passive live packet capture.
    """

    return LIVE_MONITOR.stop()


# ============================================================
# LIVE STATUS
# ============================================================


@app.get(
    "/live/status"
)
def live_status():
    """
    Return current live capture telemetry.
    """

    return LIVE_MONITOR.snapshot()


# ============================================================
# VERIFIED LIVE REPLAY
# ============================================================


@app.post(
    "/demo/replay-live"
)
def replay_verified_attacks_live():
    """
    Run verified detector scenarios sequentially for
    a presentation-safe replay.

    No packets are generated or transmitted.
    """

    global LIVE_REPLAY_RUNNING

    with LIVE_REPLAY_LOCK:

        if LIVE_REPLAY_RUNNING:

            return {
                "status":
                    "already_running"
            }

        LIVE_REPLAY_RUNNING = True

    def worker() -> None:

        global LIVE_REPLAY_RUNNING

        try:

            # ------------------------------------------------
            # Existing verified scenarios
            # ------------------------------------------------

            for scenario in (
                "dns",
                "c2",
                "encrypted",
                "correlated",
            ):

                payload = (
                    VERIFIED_SCENARIOS[
                        scenario
                    ]
                )

                result = analyze_request(
                    DetectionRequest(
                        **payload
                    )
                )

                store_alert(
                    result
                )

                time.sleep(
                    0.9
                )

            # ------------------------------------------------
            # Verified DDoS
            # ------------------------------------------------

            result = (
                run_ddos_demo()
            )

            # run_ddos_demo already
            # stores the alert.

            _ = result

        finally:

            LIVE_REPLAY_RUNNING = False

    threading.Thread(
        target=worker,
        name="codezilla-verified-replay",
        daemon=True,
    ).start()

    return {
        "status":
            "started",

        "mode":
            "verified_attack_replay",
    }


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

            "RECONNAISSANCE",

            "DATA_EXFILTRATION",
        ],

        "architecture": {

            "ingestion":
                "passive",

            "payload_decryption":
                False,

            "packet_transmission":
                False,

            "recon_detector":
                "behavioral_policy",

            "exfil_detector":
                "behavioral_policy",
        },
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

            "recon",

            "exfil",
        ]
    }


# ============================================================
# DDOS VERIFIED DEMO
#
# Final judge-safe implementation:
# - Uses the packaged, verified 62-feature CSV input.
# - Does NOT require pandas parquet/pyarrow for the demo.
# - Sends the sample through the production DDoS ML pipeline.
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
                "Verified DDoS demo input "
                "not found: "
                + str(csv_path)
            ),
        )

    if not schema_path.exists():

        raise HTTPException(
            status_code=404,
            detail=(
                "DDoS feature schema "
                "not found: "
                + str(schema_path)
            ),
        )

    try:

        ddos_data = pd.read_csv(
            csv_path
        )

        with open(
            schema_path,
            "r",
            encoding="utf-8",
        ) as f:

            dos_schema = json.load(
                f
            )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to load verified "
                "DDoS demo input: "
                + str(exc)
            ),
        ) from exc

    if ddos_data.empty:

        raise HTTPException(
            status_code=500,
            detail=(
                "Verified DDoS demo "
                "input is empty."
            ),
        )

    required_features = (
        dos_schema.get(
            "features",
            [],
        )
    )

    if len(
        required_features
    ) != 62:

        raise HTTPException(
            status_code=500,
            detail=(
                "Expected exactly 62 "
                "DDoS features, found "
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
                "error":
                    "DDoS feature mismatch",

                "missing_features":
                    missing_features,
            },
        )

    selected = (
        ddos_data.iloc[0]
    )

    ddos_payload: Dict[
        str,
        float,
    ] = {}

    for feature in required_features:

        value = selected[
            feature
        ]

        try:

            ddos_payload[
                feature
            ] = float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Invalid DDoS value "
                    f"for '{feature}': "
                    f"{value}"
                ),
            )

    try:

        request = DetectionRequest(
            source=
                "VERIFIED-DDOS-SAMPLE",

            time_window=
                "VERIFIED-BENCHMARK-WINDOW",

            ddos_features=
                ddos_payload,
        )

        result = analyze_request(
            request
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "DDoS detection failed: "
                + str(exc)
            ),
        ) from exc

    store_alert(
        result
    )

    result[
        "demo_source"
    ] = (
        "verified_ddos_csv"
    )

    result[
        "demo_input"
    ] = str(
        csv_path.relative_to(
            PROJECT_ROOT
        )
    )

    if "score" in result:

        try:

            result[
                "verified_model_score"
            ] = float(
                result[
                    "score"
                ]
            )

        except (
            TypeError,
            ValueError,
        ):

            pass

    return result


# ============================================================
# RECONNAISSANCE DEMO
#
# Synthetic feature replay only.
#
# No network packets are generated.
# No scanning is performed.
# ============================================================


@app.post(
    "/demo/recon"
)
def run_recon_demo():

    payload = {

        "source":
            "VERIFIED-RECON-SYNTHETIC",

        "time_window":
            "RECON-BEHAVIORAL-DEMO",

        "recon_features": {

            "unique_destination_hosts":
                35.0,

            "unique_destination_ports":
                60.0,

            "flow_count":
                80.0,

            "connection_attempts":
                80.0,

            "failed_connection_ratio":
                0.65,

            "short_flow_ratio":
                0.82,

            "port_fanout":
                1.7,

            "host_fanout":
                0.4375,

            "fanout_change":
                8.5,

            "destination_concentration":
                0.10,
        },
    }

    try:

        result = analyze_request(
            DetectionRequest(
                **payload
            )
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Reconnaissance demo "
                "failed: "
                + str(exc)
            ),
        ) from exc

    store_alert(
        result
    )

    result[
        "demo_source"
    ] = (
        "synthetic_recon_feature_replay"
    )

    result[
        "demo_note"
    ] = (
        "Passive behavioral feature replay; "
        "no network probes or packets transmitted."
    )

    return result


# ============================================================
# DATA EXFILTRATION DEMO
#
# Synthetic feature replay only.
#
# It demonstrates suspicious high-volume data-transfer
# behavior using metadata features.
#
# It does NOT claim that actual data was exfiltrated.
# ============================================================


@app.post(
    "/demo/exfil"
)
def run_exfil_demo():

    payload = {

        "source":
            "VERIFIED-EXFIL-SYNTHETIC",

        "time_window":
            "EXFIL-BEHAVIORAL-DEMO",

        "exfil_features": {

            "flow_count":
                5.0,

            "total_bytes":
                2_800_000.0,

            "bytes_per_flow":
                560_000.0,

            "unique_destinations":
                1.0,

            "dominant_destination_bytes_ratio":
                0.98,

            "large_flow_ratio":
                0.80,

            "bytes_rate":
                560_000.0,

            "bytes_rate_change":
                3.5,

            "mean_duration":
                25.0,

            "p95_duration":
                47.0,

            "repeat_destination_ratio":
                0.92,

            "destination_entropy":
                0.05,

            "new_destination_rate":
                0.0,
        },
    }

    try:

        result = analyze_request(
            DetectionRequest(
                **payload
            )
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Data exfiltration demo "
                "failed: "
                + str(exc)
            ),
        ) from exc

    store_alert(
        result
    )

    result[
        "demo_source"
    ] = (
        "synthetic_exfil_feature_replay"
    )

    result[
        "demo_note"
    ] = (
        "Metadata-based suspicious-transfer "
        "demo; not proof of actual exfiltration."
    )

    return result


# ============================================================
# EXTENDED RECON + EXFIL REPLAY
# ============================================================


@app.post(
    "/demo/run-extended"
)
def run_extended_demo():

    results: Dict[
        str,
        Any,
    ] = {}

    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    try:

        results[
            "recon"
        ] = run_recon_demo()

    except Exception as exc:

        results[
            "recon"
        ] = {

            "prediction":
                "ERROR",

            "error":
                str(exc),
        }

    # --------------------------------------------------------
    # Data Exfiltration
    # --------------------------------------------------------

    try:

        results[
            "exfil"
        ] = run_exfil_demo()

    except Exception as exc:

        results[
            "exfil"
        ] = {

            "prediction":
                "ERROR",

            "error":
                str(exc),
        }

    return {

        "scenarios_run":
            2,

        "results":
            results,

        "alert_count":
            len(ALERTS),
    }


# ============================================================
# RUN ALL DEMO SCENARIOS
#
# Existing verified scenarios are preserved.
# The two new behavioral demos are added afterwards.
# ============================================================


@app.post(
    "/demo/run-all"
)
def run_all_demo_scenarios():

    results: Dict[
        str,
        Any,
    ] = {}

    # --------------------------------------------------------
    # Existing verified scenarios
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

    # --------------------------------------------------------
    # Reconnaissance
    # --------------------------------------------------------

    try:

        recon_result = (
            run_recon_demo()
        )

        results[
            "recon"
        ] = recon_result

    except Exception as exc:

        results[
            "recon"
        ] = {

            "prediction":
                "ERROR",

            "error":
                str(exc),
        }

    # --------------------------------------------------------
    # Data Exfiltration
    # --------------------------------------------------------

    try:

        exfil_result = (
            run_exfil_demo()
        )

        results[
            "exfil"
        ] = exfil_result

    except Exception as exc:

        results[
            "exfil"
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
# Specific /demo/recon and /demo/exfil routes above must
# remain before this dynamic route.
# ============================================================


@app.post(
    "/demo/{scenario}"
)
def run_demo_scenario(
    scenario: str,
):

    if scenario == "recon":

        return run_recon_demo()

    if scenario == "exfil":

        return run_exfil_demo()

    if (
        scenario
        not in VERIFIED_SCENARIOS
    ):

        raise HTTPException(
            status_code=404,
            detail={

                "error":
                    "Unknown demo scenario",

                "available": [

                    "dns",

                    "c2",

                    "encrypted",

                    "correlated",

                    "ddos",

                    "recon",

                    "exfil",
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