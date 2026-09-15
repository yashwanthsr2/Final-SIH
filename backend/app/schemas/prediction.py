"""
CyberSentinel Attack Trajectory & State Schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class TrajectoryTransition(BaseModel):
    next_state: str
    probability: float
    description: str

class TrajectoryResponse(BaseModel):
    source: str
    current_state: str
    predicted_next_state: str
    prediction_confidence: float
    reasoning: str
    possible_transitions: List[TrajectoryTransition] = []
    recommended_action: str
    mitre_techniques: List[str] = []
