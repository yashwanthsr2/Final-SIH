"""
CyberSentinel Alert & Evidence Schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class EvidenceItem(BaseModel):
    feature: str
    value: Optional[Any] = None
    contribution: Optional[float] = None
    direction: Optional[str] = None
    human_label: Optional[str] = None
    threat_class: Optional[str] = None

class DetectorResult(BaseModel):
    detector: str
    prediction: str
    score: float = Field(ge=0.0, le=1.0)
    model_score: float = Field(ge=0.0, le=1.0)
    threat_class: str
    severity: str
    supporting_features: List[Dict[str, Any]] = []
    detector_type: Optional[str] = None

class UnifiedAlert(BaseModel):
    alert_id: Optional[str] = None
    prediction: str
    severity: str
    score: float
    confidence: float = 0.0
    risk_score: int = 0
    risk_breakdown: Optional[Dict[str, Any]] = None
    primary_threat: Optional[str] = None
    threat_class: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    protocol: Optional[str] = None
    time_window: Optional[str] = None
    timestamp: Optional[float] = None
    detector_count: int = 0
    threats: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    current_state: Optional[str] = None
    predicted_next_state: Optional[str] = None
    prediction_confidence: float = 0.0
    prediction_reasoning: Optional[str] = None
    correlated: bool = False
    correlated_threats: List[str] = []
    correlation_score: float = 0.0
    correlation_pattern: Optional[str] = None
    model_version: Optional[str] = None
    inference_latency_ms: Optional[float] = None
