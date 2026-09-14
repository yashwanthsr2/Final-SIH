"""
CODEZILLA RECONNAISSANCE DETECTOR

Passive behavioral detector for reconnaissance / port-scanning activity.

This detector does NOT:
- send probes
- scan hosts
- contact endpoints
- block traffic
- modify network traffic

It only evaluates metadata/features that have already been observed
by the passive monitoring pipeline.

Expected input features:
    unique_destination_hosts
    unique_destination_ports
    flow_count
    connection_attempts
    failed_connection_ratio
    short_flow_ratio
    port_fanout
    host_fanout
    fanout_change
    destination_concentration

The detector uses a transparent behavioral scoring policy rather than
claiming to be a trained ML model.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

import pandas as pd


# ============================================================
# CONSTANTS
# ============================================================

THREAT_CLASS = "RECONNAISSANCE"

# Minimum number of observations before making a strong decision.
MIN_OBSERVATIONS = 5

# Transparent policy threshold.
DECISION_THRESHOLD = 0.70


# ============================================================
# HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Convert a value to a finite float safely."""

    try:
        number = float(value)

        if math.isfinite(number):
            return number

    except (TypeError, ValueError):
        pass

    return default


def _clamp(
    value: float,
    low: float = 0.0,
    high: float = 1.0,
) -> float:
    """Clamp a numeric value into a fixed range."""

    return max(
        low,
        min(
            high,
            value,
        ),
    )


def _severity(
    score: float,
) -> str:
    """Map behavioral score to alert severity."""

    if score >= 0.90:
        return "CRITICAL"

    if score >= 0.80:
        return "HIGH"

    if score >= 0.70:
        return "MEDIUM"

    return "LOW"


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def _build_evidence(
    row: pd.Series,
) -> List[Dict[str, Any]]:
    """
    Return the strongest observable reconnaissance signals.

    These are behavioral feature values, not SHAP values.
    """

    feature_names = [
        "unique_destination_hosts",
        "unique_destination_ports",
        "port_fanout",
        "host_fanout",
        "connection_attempts",
        "failed_connection_ratio",
        "short_flow_ratio",
        "fanout_change",
    ]

    evidence: List[Dict[str, Any]] = []

    for feature in feature_names:

        if feature not in row.index:
            continue

        value = _safe_float(
            row.get(feature)
        )

        evidence.append(
            {
                "feature": feature,
                "feature_value": round(value, 4),
                "evidence_type": "behavioral_feature",
            }
        )

    return evidence[:5]


# ============================================================
# RECON SCORE
# ============================================================

def _recon_score(
    row: pd.Series,
) -> float:
    """
    Calculate a transparent reconnaissance score.

    The score combines several independent observations:

    - destination host fan-out
    - destination port fan-out
    - connection-attempt volume
    - failed/short-flow behavior
    - change in fan-out over time

    This is a behavioral policy score, not a calibrated probability.
    """

    unique_hosts = _safe_float(
        row.get("unique_destination_hosts")
    )

    unique_ports = _safe_float(
        row.get("unique_destination_ports")
    )

    flow_count = _safe_float(
        row.get("flow_count")
    )

    connection_attempts = _safe_float(
        row.get("connection_attempts")
    )

    failed_ratio = _clamp(
        _safe_float(
            row.get("failed_connection_ratio")
        )
    )

    short_ratio = _clamp(
        _safe_float(
            row.get("short_flow_ratio")
        )
    )

    port_fanout = _safe_float(
        row.get("port_fanout")
    )

    host_fanout = _safe_float(
        row.get("host_fanout")
    )

    fanout_change = max(
        0.0,
        _safe_float(
            row.get("fanout_change")
        ),
    )

    # --------------------------------------------------------
    # Normalize observable signals
    # --------------------------------------------------------

    host_signal = _clamp(
        unique_hosts / 20.0
    )

    port_signal = _clamp(
        unique_ports / 30.0
    )

    flow_signal = _clamp(
        flow_count / 50.0
    )

    attempt_signal = _clamp(
        connection_attempts / 50.0
    )

    port_fanout_signal = _clamp(
        port_fanout / 20.0
    )

    host_fanout_signal = _clamp(
        host_fanout / 20.0
    )

    change_signal = _clamp(
        fanout_change / 10.0
    )

    # --------------------------------------------------------
    # Weighted behavioral score
    # --------------------------------------------------------

    score = (
        0.18 * host_signal
        + 0.20 * port_signal
        + 0.10 * flow_signal
        + 0.10 * attempt_signal
        + 0.18 * failed_ratio
        + 0.10 * short_ratio
        + 0.07 * port_fanout_signal
        + 0.04 * host_fanout_signal
        + 0.03 * change_signal
    )

    # Keep score in valid display range.
    return round(
        _clamp(score),
        4,
    )


# ============================================================
# SINGLE-ROW PREDICTION
# ============================================================

def _predict_row(
    row: pd.Series,
) -> Dict[str, Any]:
    """Evaluate one observed feature row."""

    flow_count = _safe_float(
        row.get("flow_count")
    )

    connection_attempts = _safe_float(
        row.get("connection_attempts")
    )

    observations = max(
        flow_count,
        connection_attempts,
    )

    # --------------------------------------------------------
    # Insufficient observations
    # --------------------------------------------------------

    if observations < MIN_OBSERVATIONS:

        return {
            "prediction": "BENIGN",
            "model_score": 0.0,
            "decision_threshold": DECISION_THRESHOLD,
            "threat_class": THREAT_CLASS,
            "severity": "LOW",
            "supporting_features": [],
            "detector_type": "behavioral_policy",
            "status": "insufficient_observations",
        }

    # --------------------------------------------------------
    # Behavioral score
    # --------------------------------------------------------

    score = _recon_score(
        row
    )

    is_threat = (
        score >= DECISION_THRESHOLD
    )

    prediction = (
        "RECONNAISSANCE"
        if is_threat
        else "BENIGN"
    )

    return {
        "prediction": prediction,
        "model_score": score,
        "decision_threshold": DECISION_THRESHOLD,
        "threat_class": THREAT_CLASS,
        "severity": _severity(score),
        "supporting_features": _build_evidence(row),
        "detector_type": "behavioral_policy",
        "status": "evaluated",
    }


# ============================================================
# PUBLIC DETECTOR API
# ============================================================

def detect(
    feature_dataframe: pd.DataFrame,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Run the passive reconnaissance detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame containing reconnaissance feature columns.

    top_k:
        Maximum evidence items returned per result.

    Returns
    -------
    list[dict]
        Standardized CODEZILLA detector results.
    """

    if not isinstance(
        feature_dataframe,
        pd.DataFrame,
    ):
        raise TypeError(
            "feature_dataframe must be a pandas DataFrame"
        )

    if feature_dataframe.empty:
        return []

    results: List[Dict[str, Any]] = []

    for _, row in feature_dataframe.iterrows():

        result = _predict_row(
            row
        )

        result["supporting_features"] = (
            result.get(
                "supporting_features",
                [],
            )[:top_k]
        )

        results.append(
            result
        )

    return results