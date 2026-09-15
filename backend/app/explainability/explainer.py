"""
CyberSentinel Threat Explainer.
Generates analyst-friendly narrative explanations of detected threats.
"""

from __future__ import annotations
from typing import Any, Dict, List
from backend.app.explainability.feature_contributions import format_evidence_item

def explain_alert(threat_class: str, confidence: float, evidence: List[Dict[str, Any]]) -> str:
    top_feats = [e.get("feature", "") for e in evidence[:3] if e.get("feature")]
    feat_str = ", ".join(top_feats) if top_feats else "network flow metadata"
    return f"{threat_class} detected with confidence {confidence:.2f} driven by {feat_str}."
