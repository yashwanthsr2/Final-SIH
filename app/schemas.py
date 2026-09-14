from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DetectionRequest(BaseModel):
    """Unified request model for all CODEZILLA detectors."""

    source: Optional[str] = None
    time_window: Optional[str] = None
    timestamp: Optional[str] = None
    flow_id: Optional[str] = None

    ddos_features: Optional[Dict[str, float]] = None
    c2_features: Optional[Dict[str, float]] = None
    dns_features: Optional[Dict[str, float]] = None
    encrypted_features: Optional[Dict[str, float]] = None
    recon_features: Optional[Dict[str, float]] = None
    exfil_features: Optional[Dict[str, float]] = None


class DetectorResult(BaseModel):
    detector: str
    prediction: str
    score: float = Field(ge=0.0, le=1.0)
    threat_class: str
    severity: str
    supporting_features: List[Dict[str, Any]] = Field(default_factory=list)


class UnifiedAlert(BaseModel):
    """Standard CODEZILLA alert record."""

    timestamp: str
    flow_id: str
    prediction: str
    severity: str
    score: float = Field(ge=0.0, le=1.0)
    primary_threat: Optional[str] = None
    source: Optional[str] = None
    time_window: Optional[str] = None
    detector_count: int
    threats: List[DetectorResult]
    evidence: List[Dict[str, Any]]
