from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DetectionRequest(BaseModel):
    """
    Generic CODEZILLA detection request.

    The client may send feature dictionaries for any
    supported detector.
    """

    source: Optional[str] = None

    time_window: Optional[str] = None

    ddos_features: Optional[Dict[str, float]] = None

    c2_features: Optional[Dict[str, float]] = None

    dns_features: Optional[Dict[str, float]] = None

    encrypted_features: Optional[Dict[str, float]] = None


class DetectorResult(BaseModel):

    detector: str

    prediction: str

    score: float = Field(
        ge=0.0,
        le=1.0
    )

    threat_class: str

    severity: str

    supporting_features: List[
        Dict[str, Any]
    ] = []


class UnifiedAlert(BaseModel):

    prediction: str

    severity: str

    score: float

    primary_threat: Optional[str] = None

    source: Optional[str] = None

    time_window: Optional[str] = None

    detector_count: int

    threats: List[
        DetectorResult
    ]

    evidence: List[
        Dict[str, Any]
    ]