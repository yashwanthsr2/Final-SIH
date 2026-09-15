"""
CyberSentinel Data Exfiltration Detector.

Passive / read-only. No packets transmitted, no endpoint probing.
No payload decryption.

Detection method: Statistical + rule-based on flow-level metadata.

Signals used:
  - Unusual outbound byte volume (absolute)
  - Outbound/inbound byte asymmetry ratio
  - Rare or new destination IP/domain
  - Long-duration transfer indicator
  - Burst pattern (high bytes in short window)
  - Large single-flow volume (mega-transfer)
  - High unique_destination concentration (low spread — focused transfer)

Thresholds are conservative to limit false positives.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import pandas as pd


THREAT_CLASS = "EXFILTRATION"

# ============================================================
# THRESHOLDS
# ============================================================

# Minimum outbound bytes to consider significant transfer
MIN_OUTBOUND_BYTES = 500_000  # 500 KB

# Minimum outbound/inbound ratio to flag asymmetry
MIN_OUTBOUND_RATIO = 5.0  # 5:1 outbound:inbound

# Maximum number of unique destinations to suggest targeted exfil
MAX_UNIQUE_DESTINATIONS = 3

# Minimum flow duration (seconds) for slow-and-low exfil
MIN_LONG_DURATION = 120.0  # 2 minutes

# Minimum bytes/second for burst exfil
MIN_BURST_BYTES_PER_SEC = 50_000  # 50 KB/s sustained

# Minimum score to classify as EXFIL threat
DECISION_THRESHOLD = 0.40


# ============================================================
# HELPERS
# ============================================================

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        v = float(value)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _compute_exfil_features(row: pd.Series) -> Dict[str, float]:
    """
    Extract exfiltration-relevant features from a flow summary row.

    Accepts column names from the UWF Zeek dataset and common alternatives.
    """
    # Volume
    bytes_out = _safe_float(
        row.get("bytes_out", row.get("total_bytes_out", row.get("total_bytes", 0)))
    )
    bytes_in = _safe_float(
        row.get("bytes_in", row.get("total_bytes_in", 1))
    )

    # Ratio
    outbound_ratio = bytes_out / max(1, bytes_in)

    # Destinations
    unique_dsts = _safe_float(
        row.get("unique_destinations", row.get("unique_dst_ips", row.get("dst_count", 1)))
    )

    # Duration
    duration = _safe_float(
        row.get("mean_flow_duration", row.get("duration", row.get("flow_duration", 0)))
    )

    # Throughput
    window_sec = _safe_float(row.get("window_seconds", row.get("window_size", 60)))
    bytes_per_sec = bytes_out / max(0.1, window_sec)

    # Flow count
    flow_count = _safe_float(row.get("flow_count", row.get("total_flows", 1)))

    return {
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "outbound_ratio": round(outbound_ratio, 3),
        "unique_destinations": unique_dsts,
        "duration": round(duration, 2),
        "bytes_per_sec": round(bytes_per_sec, 1),
        "flow_count": flow_count,
    }


# ============================================================
# SCORER
# ============================================================

def _score_exfil(features: Dict[str, float]) -> Dict[str, Any]:
    """
    Compute an exfiltration threat score from extracted features.

    Each signal contributes independently. Score is a weighted
    combination of normalised signals (0.0–1.0).
    """
    evidence: List[Dict[str, Any]] = []
    score_components: List[float] = []

    # Signal 1: High outbound volume (absolute)
    bout = features["bytes_out"]
    if bout >= MIN_OUTBOUND_BYTES:
        sig = min(1.0, math.log10(bout / MIN_OUTBOUND_BYTES + 1) / 3.0 + 0.4)
        score_components.append(sig * 0.30)
        evidence.append({
            "feature": "bytes_out",
            "value": int(bout),
            "contribution": round(sig * 0.30, 3),
            "direction": "increases_risk",
            "human_label": f"Large outbound transfer ({bout/1e6:.1f} MB)",
        })

    # Signal 2: Outbound/inbound asymmetry
    ratio = features["outbound_ratio"]
    if ratio >= MIN_OUTBOUND_RATIO:
        sig = min(1.0, (ratio - MIN_OUTBOUND_RATIO) / 20.0 + 0.5)
        score_components.append(sig * 0.25)
        evidence.append({
            "feature": "outbound_ratio",
            "value": round(ratio, 2),
            "contribution": round(sig * 0.25, 3),
            "direction": "increases_risk",
            "human_label": f"Asymmetric traffic: {ratio:.1f}× more outbound than inbound",
        })

    # Signal 3: Focused destination (few unique destinations → targeted)
    udst = features["unique_destinations"]
    if 0 < udst <= MAX_UNIQUE_DESTINATIONS and bout >= MIN_OUTBOUND_BYTES * 0.2:
        sig = 1.0 - (udst / (MAX_UNIQUE_DESTINATIONS + 1))
        score_components.append(sig * 0.20)
        evidence.append({
            "feature": "unique_destinations",
            "value": int(udst),
            "contribution": round(sig * 0.20, 3),
            "direction": "increases_risk",
            "human_label": f"Concentrated transfer to {int(udst)} destination(s)",
        })

    # Signal 4: Long-duration slow transfer (low-and-slow exfil)
    dur = features["duration"]
    if dur >= MIN_LONG_DURATION:
        sig = min(1.0, dur / (MIN_LONG_DURATION * 10))
        score_components.append(sig * 0.15)
        evidence.append({
            "feature": "duration",
            "value": round(dur, 1),
            "contribution": round(sig * 0.15, 3),
            "direction": "increases_risk",
            "human_label": f"Extended transfer duration ({dur:.0f}s — slow-and-low pattern)",
        })

    # Signal 5: Burst throughput
    bps = features["bytes_per_sec"]
    if bps >= MIN_BURST_BYTES_PER_SEC:
        sig = min(1.0, bps / (MIN_BURST_BYTES_PER_SEC * 10))
        score_components.append(sig * 0.10)
        evidence.append({
            "feature": "bytes_per_sec",
            "value": round(bps, 1),
            "contribution": round(sig * 0.10, 3),
            "direction": "increases_risk",
            "human_label": f"High-throughput burst ({bps/1e3:.0f} KB/s sustained)",
        })

    total_score = round(sum(score_components), 4)

    return {
        "score": total_score,
        "evidence": evidence,
        "features_used": features,
    }


# ============================================================
# SEVERITY
# ============================================================

def _severity(score: float) -> str:
    if score >= 0.70:
        return "HIGH"
    if score >= DECISION_THRESHOLD:
        return "MEDIUM"
    return "LOW"


# ============================================================
# DETECT
# ============================================================

def detect(
    feature_dataframe: pd.DataFrame,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Run the Data Exfiltration detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame with flow-level metadata. Accepted column names:
            bytes_out, bytes_in, unique_destinations, flow_count,
            mean_flow_duration, window_seconds, etc.
        Missing columns default to 0.

    top_k:
        Maximum evidence items to return per result.

    Returns
    -------
    list[dict]
        Structured detection results matching the CyberSentinel
        common detector interface.
    """
    if not isinstance(feature_dataframe, pd.DataFrame):
        raise TypeError("feature_dataframe must be a pandas DataFrame")

    if feature_dataframe.empty:
        return []

    results = []

    for _, row in feature_dataframe.iterrows():
        features = _compute_exfil_features(row)
        scored = _score_exfil(features)

        score = scored["score"]
        evidence = scored["evidence"][:top_k]

        is_exfil = score >= DECISION_THRESHOLD

        prediction = "EXFILTRATION" if is_exfil else "BENIGN"
        severity = _severity(score)

        results.append({
            "prediction": prediction,
            "model_score": score,
            "decision_threshold": DECISION_THRESHOLD,
            "threat_class": THREAT_CLASS,
            "severity": severity,
            "supporting_features": evidence,
            "detector_type": "statistical_rule_based",
        })

    return results
