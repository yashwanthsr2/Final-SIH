from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List

import pandas as pd

from src.detectors.dos_detector import detect as detect_ddos
from src.detectors.c2_detector import detect as detect_c2
from src.detectors.dns_detector import detect as detect_dns
from src.detectors.encrypted_detector import detect as detect_encrypted
from src.detectors.recon_detector import detect as detect_recon
from src.detectors.exfil_detector import detect as detect_exfil


def _single_row(features: Dict[str, Any]) -> pd.DataFrame:
    if not isinstance(features, dict):
        raise TypeError("Detector features must be provided as a dictionary.")
    return pd.DataFrame([features])


def _extract_score(result: Dict[str, Any]) -> float:
    raw_score = result.get("model_score", result.get("score", 0.0))
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        score = 0.0
    return max(0.0, min(1.0, score))


def _extract_supporting_features(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = result.get("supporting_features", result.get("evidence", []))
    return evidence if isinstance(evidence, list) else []


def _normalize_detector_result(
    result: Dict[str, Any],
    detector_name: str,
) -> Dict[str, Any]:
    score = _extract_score(result)
    return {
        "detector": detector_name,
        "prediction": str(result.get("prediction", "BENIGN")),
        "score": score,
        "model_score": score,
        "threat_class": str(result.get("threat_class", detector_name)),
        "severity": str(result.get("severity", "LOW")).upper(),
        "supporting_features": _extract_supporting_features(result),
    }


def run_detector(detector_name: str, features: Dict[str, Any]) -> Dict[str, Any]:
    dataframe = _single_row(features)

    if detector_name == "DDoS":
        results = detect_ddos(dataframe, top_k=5)
    elif detector_name == "C2":
        results = detect_c2(dataframe, top_k=5)
    elif detector_name == "DNS":
        results = detect_dns(dataframe, top_k=5)
    elif detector_name == "ENCRYPTED_TRAFFIC":
        results = detect_encrypted(dataframe, top_k=5)
    elif detector_name == "RECONNAISSANCE":
        results = detect_recon(dataframe, top_k=5)
    elif detector_name == "DATA_EXFILTRATION":
        results = detect_exfil(dataframe, top_k=5)
    else:
        raise ValueError(f"Unsupported detector: {detector_name}")

    if not results:
        return {
            "detector": detector_name,
            "prediction": "BENIGN",
            "score": 0.0,
            "model_score": 0.0,
            "threat_class": detector_name,
            "severity": "LOW",
            "supporting_features": [],
        }

    first_result = results[0]
    if not isinstance(first_result, dict):
        raise TypeError(
            f"{detector_name} detector returned an unexpected result type: {type(first_result)}"
        )
    return _normalize_detector_result(first_result, detector_name)


def _severity_rank(severity: str) -> int:
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(str(severity).upper(), 0)


def _build_alert_identity(
    request: Any,
    active_threats: List[Dict[str, Any]],
) -> tuple[str, str]:
    """Return standardized UTC timestamp and deterministic flow/window identifier."""

    timestamp = getattr(request, "timestamp", None)
    if not timestamp:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    supplied_flow_id = getattr(request, "flow_id", None)
    if supplied_flow_id:
        return str(timestamp), str(supplied_flow_id)

    source = str(getattr(request, "source", "unknown"))
    window = str(getattr(request, "time_window", "unknown"))
    threat_names = ",".join(
        sorted(str(x.get("threat_class", "THREAT")) for x in active_threats)
    )
    raw = f"{source}|{window}|{threat_names}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12].upper()
    return str(timestamp), f"WIN-{digest}"


def _final_alert(
    request: Any,
    active_threats: List[Dict[str, Any]],
) -> Dict[str, Any]:
    timestamp, flow_id = _build_alert_identity(request, active_threats)

    if not active_threats:
        return {
            "timestamp": timestamp,
            "flow_id": flow_id,
            "prediction": "BENIGN",
            "severity": "LOW",
            "score": 0.0,
            "primary_threat": None,
            "source": getattr(request, "source", None),
            "time_window": getattr(request, "time_window", None),
            "detector_count": 0,
            "threats": [],
            "evidence": [],
        }

    strongest = max(active_threats, key=lambda x: float(x.get("score", 0.0)))
    overall_severity = max(
        (x.get("severity", "LOW") for x in active_threats),
        key=_severity_rank,
    )

    evidence: List[Dict[str, Any]] = []
    for result in active_threats:
        for item in result.get("supporting_features", []):
            if isinstance(item, dict):
                evidence.append(item)

    return {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "prediction": "THREAT",
        "severity": overall_severity,
        "score": round(float(strongest.get("score", 0.0)), 4),
        "primary_threat": strongest.get("threat_class"),
        "source": getattr(request, "source", None),
        "time_window": getattr(request, "time_window", None),
        "detector_count": len(active_threats),
        "threats": active_threats,
        "evidence": evidence,
    }


def analyze_request(request: Any) -> Dict[str, Any]:
    detector_inputs = {
        "DDoS": getattr(request, "ddos_features", None),
        "C2": getattr(request, "c2_features", None),
        "DNS": getattr(request, "dns_features", None),
        "ENCRYPTED_TRAFFIC": getattr(request, "encrypted_features", None),
        "RECONNAISSANCE": getattr(request, "recon_features", None),
        "DATA_EXFILTRATION": getattr(request, "exfil_features", None),
    }

    detector_results: List[Dict[str, Any]] = []

    for detector_name, features in detector_inputs.items():
        if features is None:
            continue
        try:
            detector_results.append(run_detector(detector_name, features))
        except Exception as exc:
            detector_results.append(
                {
                    "detector": detector_name,
                    "prediction": "ERROR",
                    "score": 0.0,
                    "model_score": 0.0,
                    "threat_class": detector_name,
                    "severity": "LOW",
                    "supporting_features": [
                        {
                            "feature": "detector_error",
                            "feature_value": str(exc),
                            "evidence_type": "system_error",
                        }
                    ],
                }
            )

    active_threats = [
        x
        for x in detector_results
        if x.get("prediction") not in {"BENIGN", "ERROR"}
    ]

    return _final_alert(request, active_threats)
