"""
CyberSentinel Digital Twin Node Model.
"""

from __future__ import annotations
import time
from typing import Any, Dict, List, Optional

NODE_TYPE_IP = "ip"
NODE_TYPE_DOMAIN = "domain"
NODE_TYPE_PORT = "port"

def create_node(node_id: str, node_type: str) -> Dict[str, Any]:
    return {
        "id": node_id,
        "node_type": node_type,
        "first_seen": time.time(),
        "last_seen": time.time(),
        "packets": 0,
        "bytes": 0,
        "flow_count": 0,
        "threat_score": 0.0,
        "threat_classes": [],
        "anomaly_score": 0.0,
        "tags": [],
    }
