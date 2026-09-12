from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import sys
import joblib
import numpy as np
import pandas as pd


# ============================================================
# CODEZILLA SHARED ML PREDICTOR
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ============================================================
# COMPATIBILITY SHIM
#
# Some previously serialized sklearn models may reference
# the private module "_loss" during pickle loading.
#
# Modern sklearn exposes this functionality as
# "sklearn._loss".
# ============================================================

try:
    import sklearn._loss as sklearn_loss

    # Make old pickle references to "_loss" resolve to the
    # currently installed sklearn._loss module.
    sys.modules.setdefault(
        "_loss",
        sklearn_loss
    )

except ImportError as exc:
    raise RuntimeError(
        "Installed scikit-learn does not provide sklearn._loss. "
        "Check the scikit-learn installation."
    ) from exc


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "dos_hgb.joblib"
)


# ============================================================
# LOAD MODEL
# ============================================================

try:

    model = joblib.load(
        MODEL_PATH
    )

except Exception as exc:

    raise RuntimeError(
        f"Could not load CODEZILLA DDoS model: "
        f"{MODEL_PATH}\n"
        f"Original error: {exc}"
    ) from exc


# ============================================================
# PREDICTION FUNCTION
# ============================================================

def predict(
    feature_dataframe: pd.DataFrame,
    *,
    include_evidence: bool = True,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Run the packaged DDoS model.

    Parameters
    ----------
    feature_dataframe:
        DataFrame containing the exact model features.

    include_evidence:
        Whether to include feature-evidence information.

    top_k:
        Number of evidence features to return.

    Returns
    -------
    list[dict]
        Structured DDoS predictions.
    """

    if not isinstance(
        feature_dataframe,
        pd.DataFrame
    ):
        raise TypeError(
            "feature_dataframe must be a pandas DataFrame."
        )

    if feature_dataframe.empty:
        return []

    # --------------------------------------------------------
    # Extract expected model features
    # --------------------------------------------------------

    if hasattr(
        model,
        "feature_names_in_"
    ):

        expected_features = list(
            model.feature_names_in_
        )

        missing = [
            feature
            for feature in expected_features
            if feature not in feature_dataframe.columns
        ]

        if missing:

            raise ValueError(
                "Missing model features: "
                + ", ".join(missing)
            )

        X = feature_dataframe[
            expected_features
        ].copy()

    else:

        X = feature_dataframe.copy()

    # --------------------------------------------------------
    # Clean numeric data
    # --------------------------------------------------------

    X = (
        X
        .replace(
            [np.inf, -np.inf],
            np.nan
        )
        .fillna(0)
    )

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    if not hasattr(
        model,
        "predict_proba"
    ):
        raise TypeError(
            "Loaded model does not support predict_proba()."
        )

    probabilities = (
        model
        .predict_proba(X)[:, 1]
    )

    # --------------------------------------------------------
    # Decision threshold
    #
    # DDoS model metadata specifies 0.80.
    # --------------------------------------------------------

    decision_threshold = 0.80

    predictions = (
        probabilities >= decision_threshold
    ).astype(int)

    # --------------------------------------------------------
    # Build results
    # --------------------------------------------------------

    results = []

    for index, probability in enumerate(
        probabilities
    ):

        probability = float(
            probability
        )

        prediction = int(
            predictions[index]
        )

        if prediction == 1:

            label = "ATTACK"

            if probability >= 0.95:
                severity = "HIGH"

            else:
                severity = "MEDIUM"

        else:

            label = "BENIGN"
            severity = "LOW"

        supporting_features = []

        # ----------------------------------------------------
        # Basic evidence
        # ----------------------------------------------------

        if include_evidence:

            row = X.iloc[index]

            # Try model feature importance
            if hasattr(
                model,
                "feature_importances_"
            ):

                importance_values = np.asarray(
                    model.feature_importances_
                )

                ranked_indices = np.argsort(
                    np.abs(
                        importance_values
                    )
                )[::-1]

                selected = ranked_indices[
                    :max(
                        1,
                        top_k
                    )
                ]

                for feature_index in selected:

                    if feature_index >= len(
                        X.columns
                    ):
                        continue

                    feature_name = X.columns[
                        feature_index
                    ]

                    value = row[
                        feature_name
                    ]

                    try:
                        value = float(value)
                    except (
                        TypeError,
                        ValueError
                    ):
                        pass

                    supporting_features.append({
                        "feature": feature_name,
                        "feature_value": value,
                        "importance": float(
                            importance_values[
                                feature_index
                            ]
                        ),
                    })

        results.append({
            "prediction": label,
            "model_score": probability,
            "decision_threshold": decision_threshold,
            "threat_class": "DDoS",
            "severity": severity,
            "supporting_features":
                supporting_features,
        })

    return results


# ============================================================
# LOAD CONFIRMATION
# ============================================================

print(
    f"CODEZILLA DDoS model loaded: {MODEL_PATH}"
)

print(
    f"Model type: {type(model).__name__}"
)