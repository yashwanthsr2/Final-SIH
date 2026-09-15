"""
CyberSentinel TLS / Encrypted Traffic Feature Extraction.
"""

from __future__ import annotations
from typing import Any, Dict, List
import pandas as pd

ENCRYPTED_FEATURES = [
    "encrypted_flow_count",
    "encrypted_total_packets",
    "encrypted_total_bytes",
    "encrypted_unique_destinations",
    "encrypted_unique_ports",
    "encrypted_mean_duration",
    "bytes_per_flow",
    "packets_per_flow",
    "flow_count_change",
    "bytes_change",
    "destination_change",
]

def route_encrypted(df: pd.DataFrame) -> pd.DataFrame:
    missing = [f for f in ENCRYPTED_FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"Encrypted features missing: {', '.join(missing)}")
    return df[ENCRYPTED_FEATURES].copy()
