from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd

from src.detectors.dos_detector import detect as detect_ddos
from src.detectors.c2_detector import detect as detect_c2
from src.detectors.dns_detector import detect as detect_dns
from src.detectors.encrypted_detector import detect as detect_encrypted


# ============================================================
# CODEZILLA DETECTOR SERVICE
# ============================================================


def _single_row(features: Dict[str, Any]) -> pd.DataFrame:
    """
    Convert one feature dictionary into a one-row DataFrame.
    """

    if not isinstance(features, dict):
        raise TypeError(
            "Detector features must be provided as a dictionary."
        )

    return pd.DataFrame([features])


def _extract_score(result: Dict[str, Any]) -> float:
    """
    Normalize score field.

    Existing detectors may use either:
        model_score
    or:
        score
    """

    raw_score = result.get(
        "model_score",
        result.get("score", 0.0),
    )

    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        score = 0.0

    # Keep score inside the valid probability range.
    return max(0.0, min(1.0, score))


def _extract_supporting_features(
    result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Normalize supporting evidence from detector outputs.
    """

    evidence = result.get(
        "supporting_features",
        result.get("evidence", []),
    )

    if evidence is None:
        return []

    if not isinstance(evidence, list):
        return []

    return evidence


def _normalize_detector_result(
    result: Dict[str, Any],
    detector_name: str,
) -> Dict[str, Any]:
    """
    Convert any detector output into CODEZILLA's
    common detector-result format.
    """

    score = _extract_score(result)

    prediction = str(
        result.get(
            "prediction",
            "BENIGN",
        )
    )

    threat_class = str(
        result.get(
            "threat_class",
            detector_name,
        )
    )

    severity = str(
        result.get(
            "severity",
            "LOW",
        )
    ).upper()

    supporting_features = (
        _extract_supporting_features(result)
    )

    normalized = {
        "detector": detector_name,
        "prediction": prediction,
        "score": score,
        "model_score": score,
        "threat_class": threat_class,
        "severity": severity,
        "supporting_features": supporting_features,
    }

    return normalized


def run_detector(
    detector_name: str,
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run one CODEZILLA detector.

    Supported detectors:
        DDoS
        C2
        DNS
        ENCRYPTED_TRAFFIC
    """

    dataframe = _single_row(features)

    # --------------------------------------------------------
    # Run selected detector
    # --------------------------------------------------------

    if detector_name == "DDoS":

        results = detect_ddos(
            dataframe,
            top_k=5,
        )

    elif detector_name == "C2":

        results = detect_c2(
            dataframe,
            top_k=5,
        )

    elif detector_name == "DNS":

        results = detect_dns(
            dataframe,
            top_k=5,
        )

    elif detector_name == "ENCRYPTED_TRAFFIC":

        results = detect_encrypted(
            dataframe,
            top_k=5,
        )

    else:

        raise ValueError(
            f"Unsupported detector: {detector_name}"
        )

    # --------------------------------------------------------
    # Empty result
    # --------------------------------------------------------

    if not results:

        return {
            "detector": detector_name,
            "prediction": "BENIGN",
            "score": 0.0,
            "model_score": 0.0,
            "threat_class": detector_name,
            "severity": "LOW",
            "supporting_features": [],
        }

    # --------------------------------------------------------
    # Normalize first result
    # --------------------------------------------------------

    first_result = results[0]

    if not isinstance(first_result, dict):

        raise TypeError(
            f"{detector_name} detector returned "
            f"an unexpected result type: "
            f"{type(first_result)}"
        )

    return _normalize_detector_result(
        first_result,
        detector_name,
    )


def _severity_rank(severity: str) -> int:
    """
    Convert severity to sortable numeric rank.
    """

    ranking = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return ranking.get(
        str(severity).upper(),
        0,
    )


def analyze_request(
    request: Any,
) -> Dict[str, Any]:
    """
    Run all detectors supplied in the request and
    create one unified CODEZILLA alert.
    """

    detector_results: List[
        Dict[str, Any]
    ] = []

    # --------------------------------------------------------
    # Detector input mapping
    # --------------------------------------------------------

    detector_inputs = {
        "DDoS": getattr(
            request,
            "ddos_features",
            None,
        ),

        "C2": getattr(
            request,
            "c2_features",
            None,
        ),

        "DNS": getattr(
            request,
            "dns_features",
            None,
        ),

        "ENCRYPTED_TRAFFIC": getattr(
            request,
            "encrypted_features",
            None,
        ),
    }

    # --------------------------------------------------------
    # Run supplied detectors
    # --------------------------------------------------------

    for detector_name, features in detector_inputs.items():

        if features is None:
            continue

        try:

            result = run_detector(
                detector_name,
                features,
            )

            detector_results.append(
                result
            )

        except Exception as exc:

            # Keep the API alive if one optional detector fails.
            # The error is represented in the response rather
            # than crashing the complete request.

            detector_results.append({
                "detector": detector_name,
                "prediction": "ERROR",
                "score": 0.0,
                "model_score": 0.0,
                "threat_class": detector_name,
                "severity": "LOW",
                "supporting_features": [
                    {
                        "feature": "detector_error",
                        "feature_value": str(exc),
                    }
                ],
            })

    # --------------------------------------------------------
    # Active threats only
    # --------------------------------------------------------

    active_threats = [
        result
        for result in detector_results
        if result["prediction"] not in {
            "BENIGN",
            "ERROR",
        }
    ]

    # --------------------------------------------------------
    # No threat
    # --------------------------------------------------------

    if not active_threats:

        return {
            "prediction": "BENIGN",
            "severity": "LOW",
            "score": 0.0,
            "primary_threat": None,
            "source": getattr(
                request,
                "source",
                None,
            ),
            "time_window": getattr(
                request,
                "time_window",
                None,
            ),
            "detector_count": 0,
            "threats": [],
            "evidence": [],
        }

    # --------------------------------------------------------
    # Strongest detector
    # --------------------------------------------------------

    strongest = max(
        active_threats,
        key=lambda result: float(
            result.get("score", 0.0)
        ),
    )

    # --------------------------------------------------------
    # Overall severity
    # --------------------------------------------------------

    overall_severity = max(
        (
            result.get(
                "severity",
                "LOW",
            )
            for result in active_threats
        ),
        key=_severity_rank,
    )

    # --------------------------------------------------------
    # Combined evidence
    # --------------------------------------------------------

    evidence: List[
        Dict[str, Any]
    ] = []

    for result in active_threats:

        supporting_features = result.get(
            "supporting_features",
            [],
        )

        if isinstance(
            supporting_features,
            list,
        ):

            for item in supporting_features:

                if isinstance(
                    item,
                    dict,
                ):

                    evidence.append(
                        item
                    )

    # --------------------------------------------------------
    # Final unified alert
    # --------------------------------------------------------

    final_alert = {
        "prediction": "THREAT",

        "severity": overall_severity,

        "score": round(
            float(
                strongest.get(
                    "score",
                    0.0,
                )
            ),
            4,
        ),

        "primary_threat": strongest.get(
            "threat_class"
        ),

        "source": getattr(
            request,
            "source",
            None,
        ),

        "time_window": getattr(
            request,
            "time_window",
            None,
        ),

        "detector_count": len(
            active_threats
        ),

        "threats": active_threats,

        "evidence": evidence,
    }

    return final_alert