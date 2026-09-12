"""
CODEZILLA DNS DETECTOR

Production DNS detector using the validated HistGradientBoosting model.

Passive / read-only:
- No DNS queries are sent.
- No endpoint probing.
- No mitigation actions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import math

import joblib
import pandas as pd


# ============================================================
# CONSTANTS
# ============================================================

THREAT_CLASS = "DNS"

# Project root:
# CODEZILLA-SIH26145/
#     src/
#         detectors/
#             dns_detector.py
ROOT_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    ROOT_DIR
    / "models"
    / "dns_hgb.joblib"
)


# ============================================================
# LOAD TRAINED DNS MODEL
# ============================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"DNS model file not found:\n{MODEL_PATH}"
    )

MODEL_BUNDLE = joblib.load(MODEL_PATH)

MODEL = MODEL_BUNDLE["model"]

THRESHOLD = float(
    MODEL_BUNDLE["threshold"]
)

FEATURES = list(
    MODEL_BUNDLE["features"]
)


# ============================================================
# HELPER
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0
) -> float:
    """Safely convert a value to a finite float."""

    try:
        value = float(value)

        if math.isfinite(value):
            return value

    except (TypeError, ValueError):
        pass

    return default


# ============================================================
# MAIN DETECTOR
# ============================================================

def detect(
    feature_dataframe: pd.DataFrame,
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Run the trained DNS detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame containing the exact 14 DNS features used
        during model training.

    top_k:
        Number of supporting features returned.

    Returns
    -------
    list[dict]
        Structured DNS detection results.
    """

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if not isinstance(
        feature_dataframe,
        pd.DataFrame
    ):
        raise TypeError(
            "feature_dataframe must be a pandas DataFrame"
        )

    if feature_dataframe.empty:
        return []

    # --------------------------------------------------------
    # Check required features
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURES
        if feature not in feature_dataframe.columns
    ]

    if missing_features:

        raise ValueError(
            "Missing DNS features:\n"
            + "\n".join(
                f"- {feature}"
                for feature in missing_features
            )
        )

    # --------------------------------------------------------
    # Prepare model input
    # --------------------------------------------------------

    X = (
        feature_dataframe[FEATURES]
        .copy()
        .replace(
            [float("inf"), -float("inf")],
            float("nan")
        )
        .fillna(0.0)
    )

    # --------------------------------------------------------
    # Predict probabilities
    # --------------------------------------------------------

    probabilities = (
        MODEL
        .predict_proba(X)[:, 1]
    )

    results = []

    # --------------------------------------------------------
    # Build structured results
    # --------------------------------------------------------

    for row_number, probability in enumerate(
        probabilities
    ):

        probability = _safe_float(
            probability
        )

        # Threshold selected on validation data
        is_dns_threat = (
            probability >= THRESHOLD
        )

        if is_dns_threat:

            prediction = "DNS_THREAT"

            if probability >= 0.95:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        else:

            prediction = "BENIGN"
            severity = "LOW"

        # ----------------------------------------------------
        # Evidence
        # ----------------------------------------------------

        row = X.iloc[row_number]

        supporting_features = []

        for feature in FEATURES:

            supporting_features.append({
                "feature": feature,
                "feature_value": _safe_float(
                    row[feature]
                )
            })

        # Show strongest numerical feature values first.
        supporting_features.sort(
            key=lambda item:
            abs(item["feature_value"]),
            reverse=True
        )

        results.append({

            "prediction": prediction,

            "model_score": round(
                probability,
                4
            ),

            "decision_threshold": THRESHOLD,

            "threat_class": THREAT_CLASS,

            "severity": severity,

            "supporting_features": (
                supporting_features[:top_k]
            )
        })

    return results