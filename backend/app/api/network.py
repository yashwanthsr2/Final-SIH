"""
CyberSentinel Digital Twin & Network Topology API Router.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from backend.app.digital_twin import get_twin

router = APIRouter(tags=["Network"])

@router.get("/api/network")
@router.get("/api/twin/graph")
def get_network_graph(
    include_ports: bool = False,
    min_threat_score: float = Query(default=0.0, ge=0.0, le=1.0),
    limit_nodes: int = Query(default=150, le=500),
):
    twin = get_twin()
    return twin.get_graph(
        include_ports=include_ports,
        min_threat_score=min_threat_score,
        limit_nodes=limit_nodes,
    )
