"""
CODEZILLA ENCRYPTED TRAFFIC DETECTOR

Production detector using the validated encrypted-traffic
HistGradientBoosting model.

Passive / read-only:
- does not contact remote hosts
- does not decrypt traffic
- does not modify network state
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

THREAT_CLASS = "ENCRYPTED_TRAFFIC"

ROOT_DIR = Path(
    __file__
).resolve().parents[2]

MODEL_PATH = (
    ROOT_DIR
    / "models"
    / "encrypted_hgb.joblib"
)


# ============================================================
# LOAD MODEL
# ============================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Encrypted model not found:\n{MODEL_PATH}"
    )

MODEL_BUNDLE = joblib.load(
    MODEL_PATH
)

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

    try:
        value = float(value)

        if math.isfinite(value):
            return value

    except (TypeError, ValueError):
        pass

    return default


# ============================================================
# DETECTOR
# ============================================================

def detect(
    feature_dataframe: pd.DataFrame,
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Detect suspicious encrypted-traffic behaviour.

    feature_dataframe must contain the exact features used
    during model training.
    """

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
    # Check schema
    # --------------------------------------------------------

    missing = [
        feature
        for feature in FEATURES
        if feature not in feature_dataframe.columns
    ]

    if missing:
        raise ValueError(
            "Missing encrypted features:\n"
            + "\n".join(
                f"- {feature}"
                for feature in missing
            )
        )

    # --------------------------------------------------------
    # Prepare input
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
    # Model prediction
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

        is_threat = (
            probability >= THRESHOLD
        )

        if is_threat:

            prediction = "ENCRYPTED_THREAT"

            if probability >= 0.95:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        else:

            prediction = "BENIGN"
            severity = "LOW"

        row = X.iloc[row_number]

        supporting_features = []

        for feature in FEATURES:

            supporting_features.append({
                "feature": feature,
                "feature_value": _safe_float(
                    row[feature]
                )
            })

        # Strongest numerical values first.
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
            ),
        })

    return results