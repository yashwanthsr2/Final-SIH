"""
CyberSentinel Threat Schemas & Requests.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class DetectionRequest(BaseModel):
    """
    Unified detection request.
    Supply feature dicts for whichever detectors should run.
    """
    flow_id: Optional[str] = None
    timestamp: Optional[float] = None
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

class ThreatSummary(BaseModel):
    total_alerts: int
    recent_24h: int
    by_threat_class: List[Dict[str, Any]]
    by_severity: List[Dict[str, Any]]

class ReplaySpeedRequest(BaseModel):
    speed: float = Field(gt=0, le=100, description="Replay speed multiplier")

class SystemMetrics(BaseModel):
    flows_total: int
    alerts_total: int
    ingestion_rate: float
    inference_latency_ms: float
    memory_mb: Optional[float] = None
    uptime_seconds: float
