"""
CyberSentinel Digital Twin Edge Model.
"""

from __future__ import annotations
import time
from typing import Any, Dict

def create_edge() -> Dict[str, Any]:
    return {
        "packets": 0,
        "bytes": 0,
        "flow_count": 0,
        "last_seen": time.time(),
        "threat_score": 0.0,
    }
