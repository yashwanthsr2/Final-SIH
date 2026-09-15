"""
CyberSentinel Unified Detection Service.

Runs all 6 detectors and produces a standardised alert.
Integrates with:
  - Correlation engine
  - Risk scoring
  - Trajectory predictor
  - Digital twin
  - SQLite database
"""

from __future__ import annotations

import math
import time
import uuid
from typing import Any, Dict, List, Optional

import pandas as pd

from backend.app.detectors.ddos.dos_detector import detect as detect_ddos
from backend.app.detectors.beaconing.c2_detector import detect as detect_c2
from backend.app.detectors.dga_dns.dns_detector import detect as detect_dns
from backend.app.detectors.encrypted_malware.encrypted_detector import detect as detect_encrypted
from backend.app.detectors.reconnaissance.recon_detector import detect as detect_recon
from backend.app.detectors.exfiltration.exfil_detector import detect as detect_exfil

from backend.app.core.config import MODEL_VERSION
from backend.app.correlation import get_engine as get_correlation_engine
from backend.app.risk import calculate_risk_score, severity_from_risk
from backend.app.prediction import get_engine as get_trajectory_engine
from backend.app.digital_twin import get_twin
from backend.app.core.baseline_engine import get_baseline_engine
import backend.app.database as db


# ============================================================
# SEVERITY RANK
# ============================================================

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_rank(s: str) -> int:
    return _SEVERITY_RANK.get(str(s).upper(), 0)


# ============================================================
# HELPERS
# ============================================================

def _single_row(features: Dict[str, Any]) -> pd.DataFrame:
    if not isinstance(features, dict):
        raise TypeError("Detector features must be a dict")
    return pd.DataFrame([features])


def _extract_score(result: Dict[str, Any]) -> float:
    raw = result.get("model_score", result.get("score", 0.0))
    try:
        return max(0.0, min(1.0, float(raw)))
    except (TypeError, ValueError):
        return 0.0


def _extract_evidence(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    ev = result.get("supporting_features", result.get("evidence", []))
    if not isinstance(ev, list):
        return []
    clean_ev = []
    for item in ev:
        if isinstance(item, dict):
            clean_item = {}
            for k, v in item.items():
                if isinstance(v, float):
                    clean_item[k] = 0.0 if not math.isfinite(v) else round(v, 4)
                else:
                    clean_item[k] = v
            clean_ev.append(clean_item)
        else:
            clean_ev.append(item)
    return clean_ev


def _normalize(result: Dict[str, Any], detector_name: str) -> Dict[str, Any]:
    raw_pred = str(result.get("prediction", "BENIGN")).upper()
    norm_pred = "BENIGN" if raw_pred in ("BENIGN", "NORMAL", "0", "FALSE", "") else "THREAT"
    return {
        "detector": detector_name,
        "prediction": norm_pred,
        "score": _extract_score(result),
        "model_score": _extract_score(result),
        "threat_class": str(result.get("threat_class", detector_name)),
        "severity": str(result.get("severity", "LOW")).upper(),
        "supporting_features": _extract_evidence(result),
        "detector_type": result.get("detector_type", "ml"),
    }


# ============================================================
# PER-DETECTOR RUNNER
# ============================================================

def run_detector(detector_name: str, features: Dict[str, Any]) -> Dict[str, Any]:
    df = _single_row(features)

    DETECTOR_MAP = {
        "DDoS": detect_ddos,
        "C2": detect_c2,
        "DNS": detect_dns,
        "ENCRYPTED_TRAFFIC": detect_encrypted,
        "RECON": detect_recon,
        "EXFILTRATION": detect_exfil,
    }

    if detector_name not in DETECTOR_MAP:
        raise ValueError(f"Unsupported detector: {detector_name}")

    results = DETECTOR_MAP[detector_name](df, top_k=5)

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

    return _normalize(results[0], detector_name)


# ============================================================
# UNIFIED ANALYSIS — FULL PIPELINE
# ============================================================

def analyze_request(request: Any) -> Dict[str, Any]:
    """
    Run all available detectors and produce a full CyberSentinel alert.

    Integrates:
      - 6 detectors
      - Correlation engine
      - Risk scoring
      - Attack trajectory
      - Digital twin update
      - Database persistence
    """
    t_start = time.time()

    source = getattr(request, "source", None) or "UNKNOWN"
    destination = getattr(request, "destination", None) or getattr(request, "dst_ip", None) or "UNKNOWN"
    protocol = getattr(request, "protocol", None) or getattr(request, "proto", None) or "TCP"
    flow_id = getattr(request, "flow_id", None) or f"flow_{source}_{destination}_{int(time.time())}"
    timestamp = getattr(request, "timestamp", None) or time.time()
    time_window = getattr(request, "time_window", None) or time.strftime("%Y-%m-%dT%H:%M:%S")

    # Detector input mapping
    detector_inputs = {
        "DDoS": getattr(request, "ddos_features", None),
        "C2": getattr(request, "c2_features", None),
        "DNS": getattr(request, "dns_features", None),
        "ENCRYPTED_TRAFFIC": getattr(request, "encrypted_features", None),
        "RECON": getattr(request, "recon_features", None),
        "EXFILTRATION": getattr(request, "exfil_features", None),
    }

    detector_results: List[Dict[str, Any]] = []

    for name, features in detector_inputs.items():
        if features is None:
            continue
        try:
            result = run_detector(name, features)
            detector_results.append(result)
        except Exception as exc:
            detector_results.append({
                "detector": name,
                "prediction": "ERROR",
                "score": 0.0,
                "model_score": 0.0,
                "threat_class": name,
                "severity": "LOW",
                "supporting_features": [{"feature": "error", "value": str(exc)}],
            })

    # Active threats only
    active_threats = [
        r for r in detector_results
        if r["prediction"] not in {"BENIGN", "ERROR"}
    ]

    # Normal Traffic Baseline Calibration (YouTube, Google, normal browsing)
    baseline = get_baseline_engine()
    calibrated_threats = []
    baseline_suppressed = []

    for threat in active_threats:
        t_class = threat.get("threat_class") or threat.get("detector")
        t_feats = detector_inputs.get(t_class) or {}
        cal = baseline.calibrate_detection(threat_class=t_class, score=threat["score"], features=t_feats)
        if cal.get("suppressed"):
            baseline_suppressed.append(f"{t_class} suppressed: {cal.get('reason')}")
        else:
            threat["score"] = cal.get("score", threat["score"])
            calibrated_threats.append(threat)

    active_threats = calibrated_threats

    inference_latency_ms = round((time.time() - t_start) * 1000, 2)

    # --------------------------------------------------------
    # Benign path
    # --------------------------------------------------------
    if not active_threats:
        reason = "; ".join(baseline_suppressed) if baseline_suppressed else "No threats detected"
        benign_id = str(uuid.uuid4())
        return {
            "id": benign_id,
            "alert_id": benign_id,
            "timestamp": timestamp,
            "flow_id": flow_id,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "prediction": "BENIGN",
            "severity": "LOW",
            "score": 0.0,
            "confidence": 0.0,
            "risk_score": 0,
            "primary_threat": None,
            "threat_class": None,
            "time_window": time_window,
            "detector_count": 0,
            "threats": [],
            "evidence": [],
            "contributing_features": [],
            "current_state": "NORMAL",
            "predicted_next_state": "NORMAL",
            "prediction_confidence": 0.0,
            "prediction_reasoning": reason,
            "model_version": MODEL_VERSION,
            "inference_latency_ms": inference_latency_ms,
        }

    # --------------------------------------------------------
    # Strongest detector
    # --------------------------------------------------------
    strongest = max(active_threats, key=lambda r: _severity_rank(r["severity"]) * 10 + r["score"])
    confidence = round(float(strongest["score"]), 4)
    primary_threat = strongest["threat_class"]
    overall_severity = max(
        (r["severity"] for r in active_threats), key=_severity_rank
    )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------
    corr_engine = get_correlation_engine()
    corr_result = None
    for threat in active_threats:
        corr_result = corr_engine.record_alert(
            source=source,
            threat_class=threat["threat_class"],
            confidence=float(threat["score"]),
            timestamp=timestamp,
            destination=destination,
        )
    if corr_result is None:
        corr_result = corr_engine.record_alert(
            source=source,
            threat_class=primary_threat,
            confidence=confidence,
            timestamp=timestamp,
            destination=destination,
        )

    persistence_count = corr_engine.get_persistence_count(source)

    # --------------------------------------------------------
    # Trajectory
    # --------------------------------------------------------
    traj_engine = get_trajectory_engine()
    detected_classes = [r["threat_class"] for r in active_threats]
    trajectory = traj_engine.update_state(source=source, detected_threat_classes=detected_classes)

    # --------------------------------------------------------
    # Anomaly derivation
    # --------------------------------------------------------
    anomaly_score = max((float(r.get("anomaly_score", 0.0)) for r in active_threats), default=0.0)
    if anomaly_score == 0.0:
        anomaly_score = round(min(1.0, confidence * (0.8 if overall_severity in ("HIGH", "CRITICAL") else 0.4)), 3)

    # --------------------------------------------------------
    # Risk scoring (7 Operational Signals)
    # --------------------------------------------------------
    risk_info = calculate_risk_score(
        confidence=confidence,
        severity=overall_severity,
        threat_class=primary_threat,
        correlated_detector_count=max(len(active_threats), corr_result.get("detector_count", 1) if corr_result else 1),
        persistence_count=persistence_count,
        anomaly_score=anomaly_score,
        prediction_confidence=trajectory.get("prediction_confidence", 0.0),
        predicted_next_state=trajectory.get("predicted_next_state"),
        historical_stages=len(trajectory.get("state_history", [])),
    )
    risk_score = risk_info["risk_score"]

    # Elevate severity from composite risk score if higher
    risk_derived_severity = severity_from_risk(risk_score)
    if _severity_rank(risk_derived_severity) > _severity_rank(overall_severity):
        overall_severity = risk_derived_severity

    # --------------------------------------------------------
    # Digital twin update — populate network graph
    # --------------------------------------------------------
    twin = get_twin()
    flow_features = {}
    for features_dict in [
        getattr(request, "ddos_features", None),
        getattr(request, "c2_features", None),
        getattr(request, "recon_features", None),
        getattr(request, "exfil_features", None),
    ]:
        if features_dict:
            flow_features.update(features_dict)

    dst_ip = getattr(request, "destination", None) or flow_features.get("dst_ip") or flow_features.get("destination") or flow_features.get("target_ip")
    domain = getattr(request, "domain", None) or flow_features.get("query") or flow_features.get("domain") or flow_features.get("hostname")
    raw_port = getattr(request, "dst_port", None) or getattr(request, "port", None) or flow_features.get("dst_port") or flow_features.get("port")
    parsed_port = None
    if raw_port is not None:
        try:
            parsed_port = int(raw_port)
        except (ValueError, TypeError):
            pass

    twin.update_from_flow(
        src_ip=source,
        dst_ip=str(dst_ip) if dst_ip else None,
        domain=str(domain) if domain else None,
        dst_port=parsed_port,
        packets=int(flow_features.get("total_packets", 1) or 1),
        bytes_count=int(flow_features.get("total_bytes", 0) or flow_features.get("bytes_out", 0) or 0),
        threat_score=confidence if active_threats else 0.0,
        threat_class=primary_threat if active_threats else None,
    )

    # --------------------------------------------------------
    # Collect all evidence
    # --------------------------------------------------------
    evidence: List[Dict[str, Any]] = []
    from backend.app.explainability.feature_contributions import FEATURE_HUMAN_LABELS
    for threat in active_threats:
        for item in threat["supporting_features"]:
            if isinstance(item, dict):
                item_copy = dict(item)
                item_copy["threat_class"] = threat["threat_class"]
                feat_name = item_copy.get("feature", "")
                if "human_label" not in item_copy:
                    item_copy["human_label"] = FEATURE_HUMAN_LABELS.get(feat_name, feat_name.replace("_", " ").title())
                evidence.append(item_copy)

    # --------------------------------------------------------
    # Build alert
    # --------------------------------------------------------
    alert_id = str(uuid.uuid4())

    alert = {
        "id": alert_id,
        "alert_id": alert_id,
        "timestamp": timestamp,
        "flow_id": flow_id,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "prediction": "THREAT",
        "severity": overall_severity,
        "score": confidence,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_breakdown": risk_info["breakdown"],
        "risk_methodology": risk_info["methodology"],
        "primary_threat": primary_threat,
        "threat_class": primary_threat,
        "time_window": time_window,
        "detector_count": len(active_threats),
        "threats": active_threats,
        "evidence": evidence[:15],
        "contributing_features": evidence[:15],
        "current_state": trajectory["current_state"],
        "predicted_next_state": trajectory["predicted_next_state"],
        "prediction_confidence": trajectory["prediction_confidence"],
        "prediction_reasoning": trajectory.get("prediction_reasoning", ""),
        "state_history": trajectory.get("state_history", []),
        "correlated": corr_result["correlated"],
        "correlated_threats": corr_result["correlated_threats"],
        "correlation_score": corr_result["correlation_score"],
        "correlation_pattern": corr_result["pattern"],
        "model_version": MODEL_VERSION,
        "inference_latency_ms": inference_latency_ms,
    }

    # --------------------------------------------------------
    # Persist to database
    # --------------------------------------------------------
    try:
        db.insert_alert(alert)
    except Exception:
        pass  # Database errors must not crash detection

    return alert