"""
CyberSentinel Flow Timing & Temporal Feature Extraction.
"""

from __future__ import annotations
from typing import Any, Dict

def extract_timing_features(flow_dict: Dict[str, Any]) -> Dict[str, float]:
    duration = float(flow_dict.get("duration") or 0.0)
    mean_iat = float(flow_dict.get("mean_iat") or 0.0)
    total_pkts = float(flow_dict.get("orig_pkts") or 0.0) + float(flow_dict.get("resp_pkts") or 0.0)
    
    pkt_rate = (total_pkts / duration) if duration > 0.001 else total_pkts
    
    return {
        "duration": duration,
        "mean_iat": mean_iat,
        "pkt_rate": pkt_rate,
    }
