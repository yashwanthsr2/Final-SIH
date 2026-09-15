"""
CyberSentinel Flow Ingestion & Buffer Service.
Handles ingestion, buffering, and query of NormalizedFlow objects.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, Dict, List, Optional
from backend.app.schemas.flow import NormalizedFlow
from backend.app.digital_twin import get_twin
import backend.app.database as db

class FlowService:
    def __init__(self, max_buffer_size: int = 1000):
        self._buffer: deque[NormalizedFlow] = deque(maxlen=max_buffer_size)
        self._lock = threading.RLock()
        self._twin = get_twin()

    def process_flow(self, flow: NormalizedFlow) -> Dict[str, Any]:
        with self._lock:
            self._buffer.append(flow)
            
            # Update digital twin topology
            self._twin.update_from_flow(
                src_ip=flow.source_ip,
                dst_ip=flow.destination_ip,
                domain=flow.tls_sni or flow.dns_query,
                dst_port=flow.destination_port,
                packets=flow.total_packets,
                bytes_count=flow.total_bytes,
            )
            
            # Persist to database
            flow_dict = flow.to_dict()
            flow_id = db.insert_flow(flow_dict)
            flow_dict["id"] = flow_id
            return flow_dict

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [f.to_dict() for f in list(self._buffer)[-limit:]]

_flow_service: Optional[FlowService] = None
_flow_service_lock = threading.Lock()

def get_flow_service() -> FlowService:
    global _flow_service
    if _flow_service is None:
        with _flow_service_lock:
            if _flow_service is None:
                _flow_service = FlowService()
    return _flow_service
