"""
CyberSentinel ML Inference Engine.
Standardized prediction and evidence extraction for all models.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from backend.app.ml.model_loader import get_model
from backend.app.ml.preprocessing import align_features

def _compute_tree_contributions(model: Any, x_row: np.ndarray, expected_cols: List[str]) -> np.ndarray:
    """
    Compute exact sample-level tree-path attribution (Saabas decomposition)
    for HistGradientBoostingClassifier decision trees.
    """
    n_features = len(expected_cols)
    contributions = np.zeros(n_features, dtype=float)
    predictors = getattr(model, "_predictors", [])
    for tree_ensemble in predictors:
        tree = tree_ensemble[0] if isinstance(tree_ensemble, (list, tuple, np.ndarray)) else tree_ensemble
        nodes = getattr(tree, "nodes", None)
        if nodes is None:
            continue
        node_idx = 0
        while not nodes[node_idx]["is_leaf"]:
            node = nodes[node_idx]
            f_idx = node["feature_idx"]
            val = x_row[f_idx]
            curr_val = float(node["value"])

            if np.isnan(val):
                next_idx = node["left"] if node["missing_go_to_left"] else node["right"]
            elif val <= node["num_threshold"]:
                next_idx = node["left"]
            else:
                next_idx = node["right"]

            next_val = float(nodes[next_idx]["value"])
            contributions[f_idx] += (next_val - curr_val)
            node_idx = next_idx

    return contributions


def run_inference(
    model_name: str,
    df: pd.DataFrame,
    threshold: float = 0.5,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    model_obj = get_model(model_name)
    if isinstance(model_obj, dict) and "model" in model_obj:
        model = model_obj["model"]
        expected_cols = getattr(model, "feature_names_in_", None)
        if expected_cols is None and "features" in model_obj:
            expected_cols = list(model_obj["features"])
    else:
        model = model_obj
        expected_cols = getattr(model, "feature_names_in_", None)

    # Check if model has feature names
    if expected_cols is not None:
        aligned_df = align_features(df, list(expected_cols))
    else:
        aligned_df = df.copy()

    X = aligned_df.to_numpy(dtype=np.float32)
    eval_input = aligned_df if expected_cols is not None else X

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(eval_input)
        scores = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
    elif hasattr(model, "decision_function"):
        raw = model.decision_function(eval_input)
        scores = 1.0 / (1.0 + np.exp(-raw))
    else:
        preds = model.predict(eval_input)
        scores = preds.astype(float)


    results = []
    for idx, score in enumerate(scores):
        score_val = float(score)
        prediction = "THREAT" if score_val >= threshold else "BENIGN"

        # Evidence extraction directly from model decision paths
        evidence = []
        if hasattr(model, "_predictors") and expected_cols is not None:
            contribs = _compute_tree_contributions(model, X[idx], list(expected_cols))
            row_vals = X[idx]
            ranked_idx = np.argsort(np.abs(contribs))[::-1][:top_k]
            for r_idx in ranked_idx:
                feat = str(expected_cols[r_idx])
                val = float(row_vals[r_idx])
                c_val = float(contribs[r_idx])
                direction = "increases_risk" if c_val > 0 else "decreases_risk"
                evidence.append({
                    "feature": feat,
                    "value": val,
                    "feature_value": val,
                    "contribution": round(c_val, 4),
                    "importance": round(abs(c_val), 4),
                    "direction": direction,
                })
        elif hasattr(model, "feature_importances_") and expected_cols is not None:
            importances = model.feature_importances_
            row_vals = X[idx]
            ranked_idx = np.argsort(importances)[::-1][:top_k]
            for r_idx in ranked_idx:
                feat = str(expected_cols[r_idx])
                val = float(row_vals[r_idx])
                imp = float(importances[r_idx])
                evidence.append({
                    "feature": feat,
                    "value": val,
                    "feature_value": val,
                    "contribution": round(imp, 4),
                    "importance": round(imp, 4),
                    "direction": "increases_risk",
                })
        elif expected_cols is not None:
            # Fallback signal ranking
            row_vals = X[idx]
            ranked_idx = np.argsort(np.abs(row_vals))[::-1][:top_k]
            for r_idx in ranked_idx:
                feat = str(expected_cols[r_idx])
                val = float(row_vals[r_idx])
                evidence.append({
                    "feature": feat,
                    "value": val,
                    "feature_value": val,
                    "contribution": round(abs(val), 4),
                    "importance": round(abs(val), 4),
                    "direction": "increases_risk",
                })

        results.append({
            "prediction": prediction,
            "score": score_val,
            "model_score": score_val,
            "threshold": threshold,
            "supporting_features": evidence,
        })

    return results
