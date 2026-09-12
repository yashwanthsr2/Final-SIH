"""
CODEZILLA DETECTOR ADAPTER

Normalizes outputs from different detector families into
one common structure for the fusion engine.
"""

from __future__ import annotations

from typing import Any, Dict


def normalize_result(
    result: Dict[str, Any],
    detector_name: str,
) -> Dict[str, Any]:
    """
    Convert a detector-specific result into the common
    CODEZILLA result schema.
    """

    prediction = str(
        result.get(
            "prediction",
            "BENIGN"
        )
    ).upper()

    # --------------------------------------------------------
    # Normalize benign / malicious state
    # --------------------------------------------------------

    is_threat = prediction not in {
        "BENIGN",
        "NORMAL",
        "SAFE",
        "NO_THREAT",
    }

    # --------------------------------------------------------
    # Threat class
    # --------------------------------------------------------

    threat_class = result.get(
        "threat_class"
    )

    if threat_class is None:
        threat_class = detector_name

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    try:
        score = float(
            result.get(
                "model_score",
                0.0
            )
        )
    except (
        TypeError,
        ValueError
    ):
        score = 0.0

    score = max(
        0.0,
        min(
            1.0,
            score
        )
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = str(
        result.get(
            "severity",
            "LOW"
        )
    ).upper()

    if is_threat and severity == "LOW":

        if score >= 0.95:
            severity = "HIGH"

        elif score >= 0.75:
            severity = "MEDIUM"

    # --------------------------------------------------------
    # Common structure
    # --------------------------------------------------------

    return {
        "detector": detector_name,
        "prediction": (
            prediction
            if is_threat
            else "BENIGN"
        ),
        "model_score": round(
            score,
            4
        ),
        "threat_class": str(
            threat_class
        ),
        "severity": severity,
        "supporting_features": result.get(
            "supporting_features",
            []
        ),
    }