"""
CyberSentinel DNS Feature Extraction & Routing.
"""

from __future__ import annotations
from typing import Any, Dict, List
import pandas as pd

DNS_FEATURES = [
    "dns_query_rate",
    "dns_unique_destinations",
    "dns_packet_concentration",
    "dns_byte_concentration",
    "dns_iat_cv",
    "query_rate_prev",
    "query_rate_roll3",
    "query_rate_roll6",
    "query_rate_std6",
    "query_rate_change",
    "query_rate_z6",
    "destination_change",
    "bytes_per_query",
    "packets_per_query",
]

def route_dns(df: pd.DataFrame) -> pd.DataFrame:
    missing = [f for f in DNS_FEATURES if f not in df.columns]
    if missing:
        raise ValueError(f"DNS features missing: {', '.join(missing)}")
    return df[DNS_FEATURES].copy()
