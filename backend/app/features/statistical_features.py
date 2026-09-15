"""
CyberSentinel Statistical Feature Extraction.
Computes port entropy, fan-out, and byte asymmetry.
"""

from __future__ import annotations
import math
from typing import Any, Dict, List

def compute_entropy(values: List[Any]) -> float:
    if not values:
        return 0.0
    freqs = {}
    for v in values:
        freqs[v] = freqs.get(v, 0) + 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in freqs.values())

def extract_statistical_features(flow_dict: Dict[str, Any]) -> Dict[str, float]:
    bytes_out = float(flow_dict.get("orig_bytes") or flow_dict.get("bytes_out") or 0.0)
    bytes_in = float(flow_dict.get("resp_bytes") or flow_dict.get("bytes_in") or 0.0)
    total_bytes = bytes_out + bytes_in
    
    asymmetry_ratio = (bytes_out / (total_bytes + 1.0))
    return {
        "asymmetry_ratio": asymmetry_ratio,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
    }
