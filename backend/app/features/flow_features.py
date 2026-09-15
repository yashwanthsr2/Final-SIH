"""
CyberSentinel L3/L4 Core Flow Feature Extraction.
Extracts volume, port, and protocol features from NormalizedFlow.
"""

from __future__ import annotations
from typing import Any, Dict

def extract_flow_features(flow_dict: Dict[str, Any]) -> Dict[str, float]:
    orig_bytes = float(flow_dict.get("orig_bytes") or flow_dict.get("bytes_out") or 0.0)
    resp_bytes = float(flow_dict.get("resp_bytes") or flow_dict.get("bytes_in") or 0.0)
    orig_pkts = float(flow_dict.get("orig_pkts") or flow_dict.get("packets_out") or 0.0)
    resp_pkts = float(flow_dict.get("resp_pkts") or flow_dict.get("packets_in") or 0.0)
    
    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts
    
    byte_ratio = (orig_bytes / (resp_bytes + 1.0)) if orig_bytes > 0 else 0.0
    pkt_ratio = (orig_pkts / (resp_pkts + 1.0)) if orig_pkts > 0 else 0.0

    return {
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "total_bytes": total_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "total_pkts": total_pkts,
        "byte_ratio": byte_ratio,
        "pkt_ratio": pkt_ratio,
    }
