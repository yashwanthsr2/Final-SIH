"""
CyberSentinel Digital Twin & Network Graph Schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class GraphNode(BaseModel):
    id: str
    label: str
    ip: str
    role: str = "host"
    threat_level: str = "NONE"
    risk_score: int = 0
    flow_count: int = 0
    bytes_total: int = 0
    last_seen: float = 0.0

class GraphEdge(BaseModel):
    source: str
    target: str
    protocol: str = "TCP"
    flow_count: int = 1
    bytes_total: int = 0
    has_threat: bool = False
    threat_classes: List[str] = []

class DigitalTwinGraph(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
