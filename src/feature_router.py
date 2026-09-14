"""
CODEZILLA FEATURE ROUTER

Central feature-routing utilities for the six supported
threat categories:

    1. DDoS
    2. C2
    3. DNS
    4. ENCRYPTED_TRAFFIC
    5. RECONNAISSANCE
    6. DATA_EXFILTRATION

The router does not perform packet capture and does not
modify traffic. It only selects/normalizes already-observed
feature columns for the relevant detector.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd


# ============================================================
# DNS FEATURES
# ============================================================

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


# ============================================================
# ENCRYPTED TRAFFIC FEATURES
# ============================================================

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


# ============================================================
# RECONNAISSANCE FEATURES
# ============================================================

RECON_FEATURES = [
    "unique_destination_hosts",
    "unique_destination_ports",
    "flow_count",
    "connection_attempts",
    "failed_connection_ratio",
    "short_flow_ratio",
    "port_fanout",
    "host_fanout",
    "fanout_change",
    "destination_concentration",
]


# ============================================================
# DATA EXFILTRATION FEATURES
# ============================================================

EXFIL_FEATURES = [
    "flow_count",
    "total_bytes",
    "bytes_per_flow",
    "unique_destinations",
    "dominant_destination_bytes_ratio",
    "large_flow_ratio",
    "bytes_rate",
    "bytes_rate_change",
    "mean_duration",
    "p95_duration",
    "repeat_destination_ratio",
    "destination_entropy",
    "new_destination_rate",
]


# ============================================================
# INTERNAL HELPERS
# ============================================================


def _ensure_dataframe(
    data: Any,
) -> pd.DataFrame:
    """
    Normalize input into a DataFrame.

    Accepted inputs:
        - pandas DataFrame
        - dictionary representing one feature row
    """

    if isinstance(
        data,
        pd.DataFrame,
    ):

        return data.copy()

    if isinstance(
        data,
        dict,
    ):

        return pd.DataFrame(
            [data]
        )

    raise TypeError(
        "Expected pandas DataFrame or feature dictionary."
    )


def _select_features(
    data: Any,
    features: List[str],
) -> pd.DataFrame:
    """
    Select known detector features while preserving
    row count.

    Missing feature columns are filled with zeros.
    """

    dataframe = _ensure_dataframe(
        data
    )

    selected = dataframe.copy()

    for feature in features:

        if feature not in selected.columns:

            selected[feature] = 0.0

    return selected[
        features
    ].copy()


# ============================================================
# DNS ROUTER
# ============================================================


def route_dns(
    data: Any,
) -> pd.DataFrame:
    """
    Prepare DNS features for the DNS detector.
    """

    return _select_features(
        data,
        DNS_FEATURES,
    )


# ============================================================
# ENCRYPTED TRAFFIC ROUTER
# ============================================================


def route_encrypted(
    data: Any,
) -> pd.DataFrame:
    """
    Prepare encrypted-traffic metadata features.
    """

    return _select_features(
        data,
        ENCRYPTED_FEATURES,
    )


# ============================================================
# RECONNAISSANCE ROUTER
# ============================================================


def route_recon(
    data: Any,
) -> pd.DataFrame:
    """
    Prepare reconnaissance behavioral features.
    """

    return _select_features(
        data,
        RECON_FEATURES,
    )


# ============================================================
# DATA EXFILTRATION ROUTER
# ============================================================


def route_exfil(
    data: Any,
) -> pd.DataFrame:
    """
    Prepare suspicious data-transfer features.
    """

    return _select_features(
        data,
        EXFIL_FEATURES,
    )


# ============================================================
# FEATURE DESCRIPTION
# ============================================================


def describe_features() -> Dict[str, List[str]]:
    """
    Return the feature schema exposed by each routed
    detector family.
    """

    return {
        "DNS": list(
            DNS_FEATURES
        ),

        "ENCRYPTED_TRAFFIC": list(
            ENCRYPTED_FEATURES
        ),

        "RECONNAISSANCE": list(
            RECON_FEATURES
        ),

        "DATA_EXFILTRATION": list(
            EXFIL_FEATURES
        ),
    }