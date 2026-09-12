"""
CODEZILLA FEATURE ROUTER

Routes a unified traffic/window DataFrame to the feature
schemas required by individual detectors.

This module does not perform detection itself.
"""

from __future__ import annotations

from typing import Dict, List
import pandas as pd


# ============================================================
# FEATURE SCHEMAS
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


def get_available_features(
    dataframe: pd.DataFrame,
    required_features: List[str],
) -> List[str]:
    """
    Return the required features that actually exist.
    """

    return [
        feature
        for feature in required_features
        if feature in dataframe.columns
    ]


def has_features(
    dataframe: pd.DataFrame,
    required_features: List[str],
) -> bool:
    """
    Check whether all required features are available.
    """

    return all(
        feature in dataframe.columns
        for feature in required_features
    )


def route_dns(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """
    Return DNS model features if available.
    """

    missing = [
        feature
        for feature in DNS_FEATURES
        if feature not in dataframe.columns
    ]

    if missing:
        raise ValueError(
            "DNS features missing: "
            + ", ".join(missing)
        )

    return dataframe[DNS_FEATURES].copy()


def route_encrypted(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    """
    Return encrypted-traffic model features if available.
    """

    missing = [
        feature
        for feature in ENCRYPTED_FEATURES
        if feature not in dataframe.columns
    ]

    if missing:
        raise ValueError(
            "Encrypted features missing: "
            + ", ".join(missing)
        )

    return dataframe[
        ENCRYPTED_FEATURES
    ].copy()


def describe_features(
    dataframe: pd.DataFrame,
) -> Dict[str, List[str]]:
    """
    Describe which detector schemas can be satisfied.
    """

    return {
        "DNS": get_available_features(
            dataframe,
            DNS_FEATURES,
        ),

        "ENCRYPTED_TRAFFIC": get_available_features(
            dataframe,
            ENCRYPTED_FEATURES,
        ),
    }