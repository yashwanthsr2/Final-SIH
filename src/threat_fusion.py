from __future__ import annotations

from typing import Any, Dict, List


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(
        str(severity).upper(),
        1
    )


def fuse_results(
    detector_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Combine detector outputs into one unified alert.

    Important:
    Individual detector scores are treated as detector-local
    confidence/evidence scores. They are not assumed to be
    calibrated probabilities across detector families.
    """

    if not detector_results:
        return {
            "prediction": "BENIGN",
            "severity": "LOW",
            "score": 0.0,
            "primary_threat": None,
            "threats": [],
            "evidence": [],
        }

    active_threats = []

    for result in detector_results:

        prediction = str(
            result.get(
                "prediction",
                "BENIGN"
            )
        ).upper()

        if prediction == "BENIGN":
            continue

        score = float(
            result.get(
                "model_score",
                0.0
            )
        )

        threat_class = str(
            result.get(
                "threat_class",
                "UNKNOWN"
            )
        )

        severity = str(
            result.get(
                "severity",
                "LOW"
            )
        ).upper()

        active_threats.append({
            "threat_class": threat_class,
            "prediction": prediction,
            "score": round(score, 4),
            "severity": severity,
            "supporting_features": result.get(
                "supporting_features",
                []
            ),
        })

    # No detector fired.
    if not active_threats:
        return {
            "prediction": "BENIGN",
            "severity": "LOW",
            "score": 0.0,
            "primary_threat": None,
            "threats": [],
            "evidence": [],
        }

    # --------------------------------------------------------
    # Choose primary threat
    # --------------------------------------------------------
    #
    # Prefer:
    #   1. Severity
    #   2. Detector-local score
    #
    # We intentionally do NOT claim scores are comparable
    # calibrated probabilities.
    # --------------------------------------------------------

    active_threats.sort(
        key=lambda item: (
            _severity_rank(
                item["severity"]
            ),
            item["score"]
        ),
        reverse=True
    )

    primary = active_threats[0]

    # --------------------------------------------------------
    # Final severity
    # --------------------------------------------------------

    final_severity = max(
        (
            item["severity"]
            for item in active_threats
        ),
        key=_severity_rank
    )

    # --------------------------------------------------------
    # Evidence strength
    # --------------------------------------------------------

    # Start with the strongest local detector score.
    strongest_score = max(
        item["score"]
        for item in active_threats
    )

    # Independent detector agreement increases confidence.
    detector_count = len(
        active_threats
    )

    agreement_bonus = min(
        0.10,
        max(0, detector_count - 1) * 0.05
    )

    final_score = min(
        1.0,
        strongest_score + agreement_bonus
    )

    # --------------------------------------------------------
    # Collect evidence
    # --------------------------------------------------------

    evidence = []

    for threat in active_threats:

        for item in threat[
            "supporting_features"
        ]:

            evidence.append({
                "threat_class": (
                    threat["threat_class"]
                ),
                **item,
            })

    return {
        "prediction": "THREAT",
        "severity": final_severity,
        "score": round(
            final_score,
            4
        ),
        "primary_threat": (
            primary["threat_class"]
        ),
        "threats": active_threats,
        "evidence": evidence[:15],
    }