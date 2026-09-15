"""
CyberSentinel Reconnaissance / Port Scanning Detector.

Passive / read-only. No packets transmitted, no endpoint probing.

Detection method: Statistical + rule-based on flow-level metadata.

Signals used:
  - Destination port diversity (unique dst ports per src in window)
  - Destination host fan-out (unique dst IPs per src in window)
  - Connection attempt rate (flows per second)
  - SYN-without-ACK ratio (indicates half-open scan)
  - Low bytes-per-flow (common in port scanners)
  - Short flow duration distribution
  - High unique_dst_ports / unique_dst_ips ratio (vertical vs horizontal)

Thresholds are conservative to limit false positives.
All evidence signals are returned in the result.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import pandas as pd


THREAT_CLASS = "RECON"

# ============================================================
# DETECTION THRESHOLDS (tunable via config in future)
# ============================================================

# Minimum unique destination ports to flag port scanning
UNIQUE_DST_PORTS_THRESHOLD = 15

# Minimum unique destination IPs to flag host scanning
UNIQUE_DST_IPS_THRESHOLD = 10

# Minimum connection attempt rate (flows/sec) to flag scanning
MIN_FLOW_RATE = 1.0

# Maximum average bytes/flow for scanner-like traffic
MAX_BYTES_PER_FLOW_SCANNER = 200

# Minimum SYN ratio for SYN scan detection (fraction of SYN-only flows)
MIN_SYN_RATIO = 0.60

# Minimum score to classify as RECON threat
DECISION_THRESHOLD = 0.40


# ============================================================
# FEATURE EXTRACTORS
# ============================================================

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        v = float(value)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _compute_recon_features(row: pd.Series) -> Dict[str, float]:
    """
    Extract recon-relevant features from a flow summary row.

    Supports the UWF Zeek dataset column names and common alternatives.
    Missing columns default to 0.
    """
    # Port/IP diversity
    unique_dst_ports = _safe_float(
        row.get("unique_dst_ports", row.get("dst_port_count", row.get("unique_ports", 0)))
    )
    unique_dst_ips = _safe_float(
        row.get("unique_dst_ips", row.get("unique_destinations", row.get("dst_ip_count", 0)))
    )

    # Flow rate
    flow_count = _safe_float(row.get("flow_count", row.get("total_flows", 1)))
    window_sec = _safe_float(row.get("window_seconds", row.get("duration", 60.0)))
    flow_rate = flow_count / max(0.1, window_sec)

    # Size characteristics
    total_bytes = _safe_float(row.get("total_bytes", row.get("bytes_out", 0)))
    bytes_per_flow = total_bytes / max(1, flow_count)

    # SYN characteristics
    total_packets = _safe_float(row.get("total_packets", 1))
    syn_count = _safe_float(row.get("mean_syn_count", row.get("syn_count", 0))) * flow_count
    syn_ratio = syn_count / max(1, total_packets)

    # Scan type: vertical (many ports / one IP) vs horizontal (one port / many IPs)
    if unique_dst_ips > 0:
        vertical_score = unique_dst_ports / max(1, unique_dst_ips)
    else:
        vertical_score = 0.0

    return {
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_ips": unique_dst_ips,
        "flow_rate": round(flow_rate, 4),
        "bytes_per_flow": round(bytes_per_flow, 2),
        "syn_ratio": round(syn_ratio, 4),
        "vertical_score": round(vertical_score, 3),
        "flow_count": flow_count,
    }


# ============================================================
# SCORER
# ============================================================

def _score_recon(features: Dict[str, float]) -> Dict[str, Any]:
    """
    Compute a recon threat score from extracted features.

    Each signal contributes independently. Score is a weighted
    combination of normalised signals (0.0–1.0).

    Returns the score and evidence list.
    """
    evidence: List[Dict[str, Any]] = []
    score_components: List[float] = []

    # Signal 1: High port diversity → strong recon indicator
    pdiv = features["unique_dst_ports"]
    if pdiv >= UNIQUE_DST_PORTS_THRESHOLD:
        sig = min(1.0, (pdiv - UNIQUE_DST_PORTS_THRESHOLD) / 50.0 + 0.5)
        score_components.append(sig * 0.30)
        evidence.append({
            "feature": "unique_dst_ports",
            "value": pdiv,
            "contribution": round(sig * 0.30, 3),
            "direction": "increases_risk",
            "human_label": f"High destination port diversity ({int(pdiv)} unique ports)",
        })

    # Signal 2: High host fan-out → horizontal scanning
    # Differentiate legitimate CDN fan-out from true horizontal scans:
    # A true scan probes closed/unresponsive hosts (elevated syn_ratio) or sends probe-only payloads (low bytes/flow).
    # Normal CDN multiplexing has high bytes/flow and established TLS handshakes (low syn_ratio).
    idiv = features["unique_dst_ips"]
    pdiv = features.get("unique_dst_ports", 0.0)
    bpf = features.get("bytes_per_flow", 0.0)
    syn = features.get("syn_ratio", 0.0)

    # Legitimate CDN: connecting to multiple IPs on standard web ports with established TLS and high bytes/flow
    is_legitimate_cdn = (pdiv <= 3 and bpf >= 500 and syn < 0.30)

    if idiv >= UNIQUE_DST_IPS_THRESHOLD and not is_legitimate_cdn:
        sig = min(1.0, (idiv - UNIQUE_DST_IPS_THRESHOLD) / 30.0 + 0.4)
        score_components.append(sig * 0.25)
        evidence.append({
            "feature": "unique_dst_ips",
            "value": idiv,
            "contribution": round(sig * 0.25, 3),
            "direction": "increases_risk",
            "human_label": f"High destination IP fan-out ({int(idiv)} unique hosts — horizontal scan)",
        })

    # Signal 3: High flow rate
    fr = features["flow_rate"]
    if fr >= MIN_FLOW_RATE and not is_legitimate_cdn:
        sig = min(1.0, fr / 10.0)
        score_components.append(sig * 0.20)
        evidence.append({
            "feature": "flow_rate",
            "value": round(fr, 3),
            "contribution": round(sig * 0.20, 3),
            "direction": "increases_risk",
            "human_label": f"Elevated connection attempt rate ({fr:.2f} flows/sec)",
        })

    # Signal 4: Low bytes per flow (scanner sends minimal payload)
    bpf = features["bytes_per_flow"]
    if 0 < bpf <= MAX_BYTES_PER_FLOW_SCANNER:
        sig = 1.0 - (bpf / MAX_BYTES_PER_FLOW_SCANNER)
        score_components.append(sig * 0.15)
        evidence.append({
            "feature": "bytes_per_flow",
            "value": round(bpf, 1),
            "contribution": round(sig * 0.15, 3),
            "direction": "increases_risk",
            "human_label": f"Very low bytes/flow ({bpf:.0f} bytes — scanner pattern)",
        })

    # Signal 5: High SYN ratio (SYN scan)
    syn = features["syn_ratio"]
    if syn >= MIN_SYN_RATIO:
        sig = min(1.0, (syn - MIN_SYN_RATIO) / 0.4 + 0.5)
        score_components.append(sig * 0.10)
        evidence.append({
            "feature": "syn_ratio",
            "value": round(syn, 3),
            "contribution": round(sig * 0.10, 3),
            "direction": "increases_risk",
            "human_label": f"High SYN-only packet ratio ({syn:.1%}) — half-open SYN scan",
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
    Run the Reconnaissance / Port Scanning detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame with flow/scan telemetry. Any of the following
        column sets are accepted:
            - unique_dst_ports, unique_dst_ips, flow_count, ...
            - unique_ports, unique_destinations, ...
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
        features = _compute_recon_features(row)
        scored = _score_recon(features)

        score = scored["score"]
        evidence = scored["evidence"][:top_k]

        is_recon = score >= DECISION_THRESHOLD

        prediction = "RECON" if is_recon else "BENIGN"
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
