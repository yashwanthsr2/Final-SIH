"""
CODEZILLA DATA EXFILTRATION DETECTOR

Passive metadata-based detector for suspicious high-volume /
anomalous data-transfer behavior.

Important:
This detector does NOT inspect decrypted payload contents and does
NOT prove that data was actually exfiltrated. It identifies traffic
patterns that are consistent with suspicious data transfer.

The implementation is intentionally transparent and behavioral.
It is NOT presented as a trained ML probability model.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

import pandas as pd


# ============================================================
# CONSTANTS
# ============================================================

THREAT_CLASS = "DATA_EXFILTRATION"

# Policy threshold for the behavioral score.
DECISION_THRESHOLD = 0.72

# Minimum transfer volume required for a strong decision.
MIN_TOTAL_BYTES = 10_000


# ============================================================
# HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Safely convert a value to a finite float."""

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
    """Clamp a value to the requested range."""

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

    if score >= 0.92:
        return "CRITICAL"

    if score >= 0.82:
        return "HIGH"

    if score >= 0.72:
        return "MEDIUM"

    return "LOW"


def _normalized_entropy(
    values: List[Any],
) -> float:
    """
    Calculate normalized Shannon entropy.

    Returns:
        0.0 for completely concentrated traffic.
        1.0 for evenly distributed traffic.
    """

    if not values:
        return 0.0

    counts: Dict[Any, int] = {}

    for value in values:
        counts[value] = counts.get(
            value,
            0,
        ) + 1

    unique_count = len(counts)

    if unique_count <= 1:
        return 0.0

    total = float(
        len(values)
    )

    entropy = 0.0

    for count in counts.values():

        probability = (
            count / total
        )

        if probability > 0:
            entropy -= (
                probability
                * math.log2(probability)
            )

    maximum_entropy = math.log2(
        unique_count
    )

    if maximum_entropy <= 0:
        return 0.0

    return _clamp(
        entropy / maximum_entropy
    )


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def build_features(
    flows: List[Any],
    window_seconds: float = 5.0,
    previous_flows: List[Any] | None = None,
) -> Dict[str, float]:
    """
    Convert observed flow metadata into exfiltration features.

    The function expects flow-like objects containing:

        dst
        bytes
        packets
        first_ts
        last_ts

    It deliberately relies only on already-observed metadata.
    """

    previous_flows = (
        previous_flows
        or []
    )

    flow_count = len(
        flows
    )

    if flow_count == 0:

        return {
            "flow_count": 0.0,
            "total_bytes": 0.0,
            "bytes_per_flow": 0.0,
            "unique_destinations": 0.0,
            "dominant_destination_bytes_ratio": 0.0,
            "large_flow_ratio": 0.0,
            "bytes_rate": 0.0,
            "bytes_rate_change": 0.0,
            "mean_duration": 0.0,
            "p95_duration": 0.0,
            "repeat_destination_ratio": 0.0,
            "destination_entropy": 0.0,
            "new_destination_rate": 0.0,
        }

    durations: List[float] = []
    byte_values: List[float] = []
    destinations: List[str] = []

    destination_bytes: Dict[str, float] = {}

    total_bytes = 0.0

    for flow in flows:

        flow_bytes = max(
            0.0,
            _safe_float(
                getattr(
                    flow,
                    "bytes",
                    0.0,
                )
            ),
        )

        first_ts = _safe_float(
            getattr(
                flow,
                "first_ts",
                0.0,
            )
        )

        last_ts = _safe_float(
            getattr(
                flow,
                "last_ts",
                first_ts,
            )
        )

        duration = max(
            0.0,
            last_ts - first_ts,
        )

        destination = str(
            getattr(
                flow,
                "dst",
                "unknown",
            )
        )

        total_bytes += (
            flow_bytes
        )

        byte_values.append(
            flow_bytes
        )

        durations.append(
            duration
        )

        destinations.append(
            destination
        )

        destination_bytes[
            destination
        ] = (
            destination_bytes.get(
                destination,
                0.0,
            )
            + flow_bytes
        )

    unique_destinations = len(
        set(destinations)
    )

    bytes_per_flow = (
        total_bytes
        / max(
            flow_count,
            1,
        )
    )

    dominant_destination_bytes = (
        max(
            destination_bytes.values()
        )
        if destination_bytes
        else 0.0
    )

    dominant_destination_bytes_ratio = (
        dominant_destination_bytes
        / max(
            total_bytes,
            1.0,
        )
    )

    # --------------------------------------------------------
    # Large-transfer ratio
    # --------------------------------------------------------

    sorted_bytes = sorted(
        byte_values
    )

    median_bytes = sorted_bytes[
        len(sorted_bytes) // 2
    ]

    large_flow_threshold = max(
        1024.0,
        median_bytes * 4.0,
    )

    large_flow_count = sum(
        1
        for value in byte_values
        if value >= large_flow_threshold
    )

    large_flow_ratio = (
        large_flow_count
        / max(
            flow_count,
            1,
        )
    )

    # --------------------------------------------------------
    # Duration statistics
    # --------------------------------------------------------

    sorted_durations = sorted(
        durations
    )

    mean_duration = (
        sum(durations)
        / max(
            len(durations),
            1,
        )
    )

    p95_index = min(
        len(sorted_durations) - 1,
        max(
            0,
            int(
                0.95
                * len(sorted_durations)
            ),
        ),
    )

    p95_duration = (
        sorted_durations[p95_index]
        if sorted_durations
        else 0.0
    )

    # --------------------------------------------------------
    # Byte rate
    # --------------------------------------------------------

    effective_window = max(
        _safe_float(
            window_seconds,
            5.0,
        ),
        0.1,
    )

    bytes_rate = (
        total_bytes
        / effective_window
    )

    previous_total_bytes = 0.0

    for flow in previous_flows:

        previous_total_bytes += max(
            0.0,
            _safe_float(
                getattr(
                    flow,
                    "bytes",
                    0.0,
                )
            ),
        )

    previous_bytes_rate = (
        previous_total_bytes
        / effective_window
    )

    if previous_bytes_rate > 0:

        bytes_rate_change = (
            bytes_rate
            / previous_bytes_rate
        ) - 1.0

    elif bytes_rate > 0:

        bytes_rate_change = 1.0

    else:

        bytes_rate_change = 0.0

    # --------------------------------------------------------
    # Destination repetition
    # --------------------------------------------------------

    destination_counts: Dict[str, int] = {}

    for destination in destinations:

        destination_counts[
            destination
        ] = (
            destination_counts.get(
                destination,
                0,
            )
            + 1
        )

    dominant_destination_count = (
        max(
            destination_counts.values()
        )
        if destination_counts
        else 0
    )

    repeat_destination_ratio = (
        dominant_destination_count
        / max(
            flow_count,
            1,
        )
    )

    # --------------------------------------------------------
    # Novel destination rate
    # --------------------------------------------------------

    previous_destinations = {
        str(
            getattr(
                flow,
                "dst",
                "unknown",
            )
        )
        for flow in previous_flows
    }

    current_destinations = set(
        destinations
    )

    if current_destinations:

        new_destination_count = len(
            current_destinations
            - previous_destinations
        )

        new_destination_rate = (
            new_destination_count
            / len(current_destinations)
        )

    else:

        new_destination_rate = 0.0

    return {
        "flow_count": float(
            flow_count
        ),
        "total_bytes": round(
            total_bytes,
            4,
        ),
        "bytes_per_flow": round(
            bytes_per_flow,
            4,
        ),
        "unique_destinations": float(
            unique_destinations
        ),
        "dominant_destination_bytes_ratio": round(
            _clamp(
                dominant_destination_bytes_ratio
            ),
            4,
        ),
        "large_flow_ratio": round(
            _clamp(
                large_flow_ratio
            ),
            4,
        ),
        "bytes_rate": round(
            bytes_rate,
            4,
        ),
        "bytes_rate_change": round(
            bytes_rate_change,
            4,
        ),
        "mean_duration": round(
            mean_duration,
            4,
        ),
        "p95_duration": round(
            p95_duration,
            4,
        ),
        "repeat_destination_ratio": round(
            _clamp(
                repeat_destination_ratio
            ),
            4,
        ),
        "destination_entropy": round(
            _normalized_entropy(
                destinations
            ),
            4,
        ),
        "new_destination_rate": round(
            _clamp(
                new_destination_rate
            ),
            4,
        ),
    }


# ============================================================
# EVIDENCE
# ============================================================

def _build_evidence(
    row: pd.Series,
) -> List[Dict[str, Any]]:
    """Return the strongest observable transfer indicators."""

    feature_names = [
        "total_bytes",
        "bytes_rate",
        "bytes_per_flow",
        "large_flow_ratio",
        "dominant_destination_bytes_ratio",
        "repeat_destination_ratio",
        "bytes_rate_change",
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
                "feature_value": round(
                    value,
                    4,
                ),
                "evidence_type": "behavioral_feature",
            }
        )

    return evidence[:5]


# ============================================================
# SCORE
# ============================================================

def _exfiltration_score(
    row: pd.Series,
) -> float:
    """
    Calculate suspicious-transfer behavioral score.

    This score is NOT a probability.

    It combines:

        transfer volume
        sustained byte rate
        large-flow concentration
        destination concentration
        repeated transfer behavior
        sudden rate increase
        long-lived flows
    """

    total_bytes = max(
        0.0,
        _safe_float(
            row.get("total_bytes")
        ),
    )

    bytes_rate = max(
        0.0,
        _safe_float(
            row.get("bytes_rate")
        ),
    )

    bytes_per_flow = max(
        0.0,
        _safe_float(
            row.get("bytes_per_flow")
        ),
    )

    large_flow_ratio = _clamp(
        _safe_float(
            row.get("large_flow_ratio")
        )
    )

    dominant_ratio = _clamp(
        _safe_float(
            row.get(
                "dominant_destination_bytes_ratio"
            )
        )
    )

    repeat_ratio = _clamp(
        _safe_float(
            row.get("repeat_destination_ratio")
        )
    )

    bytes_rate_change = max(
        0.0,
        _safe_float(
            row.get("bytes_rate_change")
        ),
    )

    mean_duration = max(
        0.0,
        _safe_float(
            row.get("mean_duration")
        ),
    )

    # --------------------------------------------------------
    # Normalize transfer volume
    # --------------------------------------------------------

    volume_signal = max(
        1.0
        - math.exp(
            -total_bytes / 250_000.0
        ),
        1.0
        - math.exp(
            -bytes_rate / 50_000.0
        ),
    )

    large_flow_signal = _clamp(
        (
            large_flow_ratio
            - 0.15
        )
        / 0.75
    )

    concentration_signal = _clamp(
        (
            dominant_ratio
            - 0.45
        )
        / 0.50
    )

    repetition_signal = _clamp(
        (
            repeat_ratio
            - 0.40
        )
        / 0.60
    )

    rate_change_signal = _clamp(
        (
            bytes_rate_change
            - 0.25
        )
        / 3.0
    )

    duration_signal = _clamp(
        (
            mean_duration
            - 2.0
        )
        / 30.0
    )

    per_flow_signal = _clamp(
        (
            bytes_per_flow
            - 50_000.0
        )
        / 250_000.0
    )

    # --------------------------------------------------------
    # Weighted behavioral score
    # --------------------------------------------------------

    score = (
        0.28 * volume_signal
        + 0.18 * large_flow_signal
        + 0.16 * concentration_signal
        + 0.12 * repetition_signal
        + 0.10 * rate_change_signal
        + 0.08 * duration_signal
        + 0.08 * per_flow_signal
    )

    # --------------------------------------------------------
    # Minimum-volume gate
    # --------------------------------------------------------

    # Very small transfers should not become strong
    # exfiltration alerts merely because another feature is high.

    if total_bytes < MIN_TOTAL_BYTES:

        return 0.0

    # Strong transfer gate.
    strong_transfer = (
        total_bytes >= 250_000.0
        or bytes_rate >= 50_000.0
        or bytes_per_flow >= 100_000.0
    )

    if not strong_transfer:

        score *= 0.25

    return round(
        _clamp(score),
        4,
    )


# ============================================================
# SINGLE ROW
# ============================================================

def _predict_row(
    row: pd.Series,
) -> Dict[str, Any]:
    """Evaluate one observed transfer feature row."""

    total_bytes = max(
        0.0,
        _safe_float(
            row.get("total_bytes")
        ),
    )

    flow_count = max(
        0.0,
        _safe_float(
            row.get("flow_count")
        ),
    )

    if (
        total_bytes < MIN_TOTAL_BYTES
        or flow_count <= 0
    ):

        return {
            "prediction": "BENIGN",
            "model_score": 0.0,
            "decision_threshold": DECISION_THRESHOLD,
            "threat_class": THREAT_CLASS,
            "severity": "LOW",
            "supporting_features": [],
            "detector_type": "behavioral_policy",
            "status": "insufficient_transfer_volume",
        }

    score = _exfiltration_score(
        row
    )

    is_threat = (
        score >= DECISION_THRESHOLD
    )

    prediction = (
        "DATA_EXFILTRATION"
        if is_threat
        else "BENIGN"
    )

    return {
        "prediction": prediction,
        "model_score": score,
        "decision_threshold": DECISION_THRESHOLD,
        "threat_class": THREAT_CLASS,
        "severity": _severity(score),
        "supporting_features": _build_evidence(
            row
        ),
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
    Run the passive data-transfer anomaly detector.

    Parameters
    ----------
    feature_dataframe:
        Pandas DataFrame containing exfiltration features.

    top_k:
        Maximum evidence items returned per row.

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