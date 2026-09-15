"""
CyberSentinel Detector Base & Normalizer.
Normalizes outputs from all 6 detector families into one standardized format.
"""

from __future__ import annotations
from typing import Any, Dict, List

def normalize_detector_result(result: Dict[str, Any], detector_name: str) -> Dict[str, Any]:
    raw_pred = str(result.get("prediction", "BENIGN")).upper()
    is_threat = raw_pred not in {"BENIGN", "NORMAL", "SAFE", "NO_THREAT", "0", "FALSE", ""}
    
    score = float(result.get("model_score", result.get("score", 0.0)))
    score = max(0.0, min(1.0, score))
    
    threat_class = str(result.get("threat_class") or detector_name)
    severity = str(result.get("severity", "LOW")).upper()
    evidence = result.get("supporting_features", result.get("evidence", []))
    if not isinstance(evidence, list):
        evidence = []

    return {
        "detector": detector_name,
        "prediction": "THREAT" if is_threat else "BENIGN",
        "score": score,
        "model_score": score,
        "threat_class": threat_class,
        "severity": severity,
        "supporting_features": evidence,
        "detector_type": result.get("detector_type", "ml"),
    }
