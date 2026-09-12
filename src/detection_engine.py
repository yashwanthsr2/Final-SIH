"""
CODEZILLA UNIFIED DETECTION ENGINE

Runs DDoS, C2, DNS, and encrypted-traffic detectors
and combines their outputs at event level.

Event identity:
    SrcAddr + time_window

Passive / read-only.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import pandas as pd

from src.detectors import dos_detector
from src.detectors import c2_detector
from src.detectors import dns_detector
from src.detectors import encrypted_detector

from src.feature_router import (
    route_dns,
    route_encrypted,
)

from src.detector_adapter import (
    normalize_result,
)

from src.threat_fusion import (
    fuse_results,
)


# ============================================================
# HELPER — ADD CONTEXT
# ============================================================

def _attach_context(
    source_dataframe: pd.DataFrame,
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Attach source/time information to detector results.
    """

    output = []

    for index, result in enumerate(results):

        result = dict(result)

        if "SrcAddr" in source_dataframe.columns:

            result["SrcAddr"] = (
                source_dataframe.iloc[index]["SrcAddr"]
            )

        if "time_window" in source_dataframe.columns:

            result["time_window"] = (
                source_dataframe.iloc[index]["time_window"]
            )

        output.append(result)

    return output


# ============================================================
# HELPER — ADD RESULTS TO EVENT BUCKET
# ============================================================

def _add_results(
    events: dict,
    results: list[dict[str, Any]],
) -> None:

    for result in results:

        source = result.get(
            "SrcAddr",
            "UNKNOWN"
        )

        time_window = result.get(
            "time_window",
            "UNKNOWN"
        )

        key = (
            source,
            time_window
        )

        events.setdefault(
            key,
            []
        ).append(result)


# ============================================================
# MAIN ENGINE
# ============================================================

def analyze_events(
    *,
    ddos_data: Optional[pd.DataFrame] = None,
    c2_data: Optional[pd.DataFrame] = None,
    dns_data: Optional[pd.DataFrame] = None,
    encrypted_data: Optional[pd.DataFrame] = None,
    top_k: int = 5,
) -> pd.DataFrame:
    """
    Run all available detectors.

    Each detector can receive its own feature dataframe.
    This is necessary because the detectors use different
    feature schemas.
    """

    events: dict[
        tuple,
        list[dict[str, Any]]
    ] = {}

    # ========================================================
    # DDoS
    # ========================================================

    if ddos_data is not None:

        ddos_results = dos_detector.detect(
            ddos_data,
            top_k=top_k
        )

        ddos_results = _attach_context(
            ddos_data,
            ddos_results
        )

        normalized_ddos = []

        for result in ddos_results:

            normalized_ddos.append(
                normalize_result(
                    result,
                    "DDoS"
                )
                | {
                    "SrcAddr": result.get(
                        "SrcAddr"
                    ),
                    "time_window": result.get(
                        "time_window"
                    )
                }
            )

        _add_results(
            events,
            normalized_ddos
        )

    # ========================================================
    # C2
    # ========================================================

    if c2_data is not None:

        c2_results = c2_detector.detect(
            c2_data,
            top_k=top_k
        )

        c2_results = _attach_context(
            c2_data,
            c2_results
        )

        normalized_c2 = []

        for result in c2_results:

            normalized_c2.append(
                normalize_result(
                    result,
                    "C2"
                )
                | {
                    "SrcAddr": result.get(
                        "SrcAddr"
                    ),
                    "time_window": result.get(
                        "time_window"
                    )
                }
            )

        _add_results(
            events,
            normalized_c2
        )

    # ========================================================
    # DNS
    # ========================================================

    if dns_data is not None:

        dns_features = route_dns(
            dns_data
        )

        dns_results = dns_detector.detect(
            dns_features,
            top_k=top_k
        )

        dns_results = _attach_context(
            dns_data,
            dns_results
        )

        normalized_dns = []

        for result in dns_results:

            normalized_dns.append(
                normalize_result(
                    result,
                    "DNS"
                )
                | {
                    "SrcAddr": result.get(
                        "SrcAddr"
                    ),
                    "time_window": result.get(
                        "time_window"
                    )
                }
            )

        _add_results(
            events,
            normalized_dns
        )

    # ========================================================
    # ENCRYPTED TRAFFIC
    # ========================================================

    if encrypted_data is not None:

        encrypted_features = route_encrypted(
            encrypted_data
        )

        encrypted_results = (
            encrypted_detector.detect(
                encrypted_features,
                top_k=top_k
            )
        )

        encrypted_results = _attach_context(
            encrypted_data,
            encrypted_results
        )

        normalized_encrypted = []

        for result in encrypted_results:

            normalized_encrypted.append(
                normalize_result(
                    result,
                    "ENCRYPTED_TRAFFIC"
                )
                | {
                    "SrcAddr": result.get(
                        "SrcAddr"
                    ),
                    "time_window": result.get(
                        "time_window"
                    )
                }
            )

        _add_results(
            events,
            normalized_encrypted
        )

    # ========================================================
    # FUSION
    # ========================================================

    final_rows = []

    for (
        source,
        time_window
    ), detector_results in events.items():

        fusion = fuse_results(
            detector_results
        )

        final_rows.append({

            "SrcAddr": source,

            "time_window": time_window,

            "prediction": fusion[
                "prediction"
            ],

            "severity": fusion[
                "severity"
            ],

            "score": fusion[
                "score"
            ],

            "primary_threat": fusion[
                "primary_threat"
            ],

            "detector_count": len(
                fusion.get(
                    "threats",
                    []
                )
            ),

            "threats": fusion.get(
                "threats",
                []
            ),

            "evidence": fusion.get(
                "evidence",
                []
            ),
        })

    if not final_rows:

        return pd.DataFrame(
            columns=[
                "SrcAddr",
                "time_window",
                "prediction",
                "severity",
                "score",
                "primary_threat",
                "detector_count",
                "threats",
                "evidence",
            ]
        )

    return (
        pd.DataFrame(final_rows)
        .sort_values(
            [
                "time_window",
                "score"
            ],
            ascending=[
                True,
                False
            ]
        )
        .reset_index(drop=True)
    )