"""
CyberSentinel Threat State Tracker.
Maintains state machine per observed IP.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
import time

class ThreatState:
    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.current_state = "NORMAL"
        self.last_updated = time.time()
        self.history: List[Dict[str, Any]] = []

    def transition_to(self, new_state: str, confidence: float, threat_class: str):
        self.history.append({
            "from_state": self.current_state,
            "to_state": new_state,
            "threat_class": threat_class,
            "confidence": confidence,
            "timestamp": time.time(),
        })
        self.current_state = new_state
        self.last_updated = time.time()
