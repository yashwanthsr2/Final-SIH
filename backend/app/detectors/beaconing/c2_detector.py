"""
CODEZILLA C2 ML detector.

Passive / read-only detector.

Uses the trained CODEZILLA C2 HistGradientBoosting model.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import json
import math

import joblib
import pandas as pd


THREAT_CLASS = "C2"

# ------------------------------------------------------------
# Project paths
# ------------------------------------------------------------

from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, MODELS_CLASSIFIER_DIR, MODELS_PREPROCESSING_DIR

MODEL_PATH = (MODELS_CLASSIFIER_DIR / "c2_hgb.joblib") if (MODELS_CLASSIFIER_DIR / "c2_hgb.joblib").exists() else (MODELS_DIR / "c2_hgb.joblib")

SCHEMA_PATH = (MODELS_PREPROCESSING_DIR / "c2_feature_schema.json") if (MODELS_PREPROCESSING_DIR / "c2_feature_schema.json").exists() else (MODELS_DIR / "c2_feature_schema.json")


# ------------------------------------------------------------
# Load model + schema once
# ------------------------------------------------------------

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"C2 model not found: {MODEL_PATH}"
    )

if not SCHEMA_PATH.exists():
    raise FileNotFoundError(
        f"C2 feature schema not found: {SCHEMA_PATH}"
    )


MODEL = joblib.load(MODEL_PATH)

with open(
    SCHEMA_PATH,
    "r",
    encoding="utf-8"
) as f:
    SCHEMA = json.load(f)


FEATURES: List[str] = SCHEMA["features"]

DECISION_THRESHOLD = float(
    SCHEMA["decision_threshold"]
)


# ------------------------------------------------------------
# Basic validation
# ------------------------------------------------------------

if len(FEATURES) == 0:
    raise ValueError("C2 feature schema has no features defined.")


def _safe_float(
    value: Any,
    default: float = 0.0
) -> float:
    """Convert value to finite float."""
    try:
        value = float(value)

        if math.isfinite(value):
            return value

    except (TypeError, ValueError):
        pass

    return default


def _severity(
    score: float
) -> str:

    if score >= 0.75:
        return "HIGH"

    if score >= DECISION_THRESHOLD:
        return "MEDIUM"

    return "LOW"


def _build_evidence(
    row: pd.Series
) -> List[Dict[str, Any]]:
    """
    Return behavioral feature evidence.

    These are the strongest C2 features identified during
    model analysis. They are evidence signals, not SHAP values.
    """

    important_features = [
        "mean_bytes",
        "total_bytes",
        "mean_packets",
        "mean_duration",
        "max_pair_seen",
    ]

    evidence = []

    for feature in important_features:

        if feature not in row.index:
            continue

        value = _safe_float(
            row.get(feature)
        )

        evidence.append({
            "feature": feature,
            "feature_value": value,
            "evidence_type": "behavioral_feature"
        })

    return evidence[:5]


def _predict_row(
    row: pd.Series
) -> Dict[str, Any]:
    """Run the trained C2 model on one row."""

    missing = [
        feature
        for feature in FEATURES
        if feature not in row.index
    ]

    if missing:
        raise ValueError(
            "C2 ML input is missing required features: "
            + ", ".join(missing[:10])
            + (
                "..."
                if len(missing) > 10
                else ""
            )
        )

    X = pd.DataFrame(
        [[
            _safe_float(row[feature])
            for feature in FEATURES
        ]],
        columns=FEATURES
    )

    probability = float(
        MODEL.predict_proba(X)[0, 1]
    )

    prediction = (
        "C2"
        if probability >= DECISION_THRESHOLD
        else "BENIGN"
    )

    severity = _severity(
        probability
    )

    return {
        "prediction": prediction,
        "model_score": round(
            probability,
            4
        ),
        "decision_threshold": DECISION_THRESHOLD,
        "threat_class": THREAT_CLASS,
        "severity": severity,
        "supporting_features": _build_evidence(row)
    }


def detect(
    feature_dataframe: pd.DataFrame,
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Run the trained C2 ML detector.

    Parameters
    ----------
    feature_dataframe:
        DataFrame containing all 62 trained C2 features.

    top_k:
        Maximum number of evidence features returned.
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

    results = []

    for _, row in feature_dataframe.iterrows():

        result = _predict_row(row)

        result["supporting_features"] = (
            result["supporting_features"][:top_k]
        )

        results.append(result)

    return results