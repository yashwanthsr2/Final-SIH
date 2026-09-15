"""
CyberSentinel Risk Scoring Engine.

Deterministic, transparent 4-part risk scoring formula (0–100):
  base_score     = model_confidence * 40
  severity_score = severity_rank * 20
  correlation    = min(corr_count * 10, 15)
  persistence    = persistence_bonus (0-5)
"""

from __future__ import annotations
from typing import Any, Dict, Optional

SEVERITY_RANK: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_SCORE: Dict[str, float] = {
    "LOW": 5.0,
    "MEDIUM": 12.0,
    "HIGH": 20.0,
    "CRITICAL": 28.0,
}

THREAT_TYPE_WEIGHT: Dict[str, float] = {
    "DDoS": 1.0,
    "C2": 1.15,
    "DNS": 0.90,
    "ENCRYPTED_TRAFFIC": 0.95,
    "RECON": 0.85,
    "EXFILTRATION": 1.20,
}

CRITICAL_STATES = {"EXFILTRATION", "DISRUPTION", "DATA_COLLECTION", "C2"}

def calculate_risk_score(
    *,
    confidence: float,
    severity: str,
    threat_class: str,
    correlated_detector_count: int = 1,
    persistence_count: int = 0,
    anomaly_score: float = 0.0,
    prediction_confidence: float = 0.0,
    predicted_next_state: Optional[str] = None,
    historical_stages: int = 0,
) -> Dict[str, Any]:
    """
    Calculate a transparent, non-black-box risk score (0-100) combining 7 operational signals:
      1. confidence            (0-30 pts): ML model probability
      2. severity              (5-28 pts): threat severity rank (LOW=5, MED=12, HIGH=20, CRIT=28)
      3. correlation           (0-15 pts): multi-detector cross-verification
      4. persistence           (0-10 pts): historical repeat alert count for the source
      5. anomaly_score         (0-10 pts): statistical deviation from normal traffic baseline
      6. prediction_confidence (0-10 pts): trajectory Markov transition toward critical states
      7. historical_behavior   (0-5 pts):  number of kill-chain stages traversed
      8. threat_type_weight    (0.85-1.20 multiplier): inherent impact of the threat class
    """
    severity_upper = severity.upper()
    threat_upper = threat_class.upper()

    # 1. Model Confidence (0-30 pts)
    base_confidence = min(30.0, max(0.0, float(confidence) * 30.0))

    # 2. Threat Severity (5-28 pts)
    severity_pts = SEVERITY_SCORE.get(severity_upper, 5.0)

    # 3. Multi-detector Correlation (0-15 pts)
    correlation_pts = min(15.0, max(0, correlated_detector_count - 1) * 7.5)

    # 4. Historical Persistence / Repeat Offender (0-10 pts)
    persistence_pts = min(10.0, max(0, persistence_count) * 2.0)

    # 5. Baseline Anomaly Magnitude (0-10 pts)
    anomaly_pts = min(10.0, max(0.0, float(anomaly_score)) * 10.0)

    # 6. Trajectory Predictive Escalation (0-10 pts)
    is_critical_next = bool(predicted_next_state and str(predicted_next_state).upper() in CRITICAL_STATES)
    pred_scale = 10.0 if is_critical_next else 5.0
    prediction_pts = min(10.0, max(0.0, float(prediction_confidence)) * pred_scale)

    # 7. Historical Multi-Stage Progression (0-5 pts)
    historical_pts = min(5.0, max(0, historical_stages - 1) * 2.5)

    # 8. Inherent Threat Multiplier
    weight = THREAT_TYPE_WEIGHT.get(threat_upper, 1.0)

    raw_sum = (
        base_confidence
        + severity_pts
        + correlation_pts
        + persistence_pts
        + anomaly_pts
        + prediction_pts
        + historical_pts
    )
    raw_score = raw_sum * weight
    risk_score = int(min(100, max(0, round(raw_score))))

    return {
        "risk_score": risk_score,
        "breakdown": {
            "base_confidence": round(base_confidence, 1),
            "severity_component": round(severity_pts, 1),
            "correlation_bonus": round(correlation_pts, 1),
            "persistence_bonus": round(persistence_pts, 1),
            "anomaly_component": round(anomaly_pts, 1),
            "prediction_component": round(prediction_pts, 1),
            "historical_component": round(historical_pts, 1),
            "threat_type_weight": weight,
            "raw_sum": round(raw_sum, 1),
        },
        "methodology": (
            f"risk = (confidence({base_confidence:.1f}) + severity({severity_pts:.1f}) + "
            f"correlation({correlation_pts:.1f}) + persistence({persistence_pts:.1f}) + "
            f"anomaly({anomaly_pts:.1f}) + prediction({prediction_pts:.1f}) + "
            f"history({historical_pts:.1f})) × weight({weight}) = {risk_score}/100"
        ),
    }

def severity_from_risk(risk_score: int) -> str:
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 35:
        return "MEDIUM"
    return "LOW"
