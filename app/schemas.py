"""
CyberSentinel Pydantic schemas.

All API request/response models use these types.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================
# REQUEST
# ============================================================

class DetectionRequest(BaseModel):
    """
    Unified detection request. Supply feature dicts for
    whichever detectors should run. Detectors with None input are skipped.
    """
    source: Optional[str] = None
    time_window: Optional[str] = None
    destination: Optional[str] = None
    domain: Optional[str] = None
    protocol: Optional[str] = None

    # Per-detector feature dicts
    ddos_features: Optional[Dict[str, float]] = None
    c2_features: Optional[Dict[str, float]] = None
    dns_features: Optional[Dict[str, float]] = None
    encrypted_features: Optional[Dict[str, float]] = None
    recon_features: Optional[Dict[str, float]] = None
    exfil_features: Optional[Dict[str, float]] = None


# ============================================================
# EVIDENCE ITEM
# ============================================================

class EvidenceItem(BaseModel):
    feature: str
    value: Optional[Any] = None
    contribution: Optional[float] = None
    direction: Optional[str] = None
    human_label: Optional[str] = None
    threat_class: Optional[str] = None


# ============================================================
# DETECTOR RESULT
# ============================================================

class DetectorResult(BaseModel):
    detector: str
    prediction: str
    score: float = Field(ge=0.0, le=1.0)
    model_score: float = Field(ge=0.0, le=1.0)
    threat_class: str
    severity: str
    supporting_features: List[Dict[str, Any]] = []
    detector_type: Optional[str] = None


# ============================================================
# UNIFIED ALERT  (matches SIH required schema)
# ============================================================

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


# ============================================================
# REPLAY
# ============================================================

class ReplaySpeedRequest(BaseModel):
    speed: float = Field(gt=0, le=100, description="Replay speed multiplier (1x, 5x, 10x, 50x)")


# ============================================================
# SYSTEM METRICS
# ============================================================

class SystemMetrics(BaseModel):
    flows_total: int
    alerts_total: int
    ingestion_rate: float
    inference_latency_ms: float
    memory_mb: Optional[float] = None
    uptime_seconds: float