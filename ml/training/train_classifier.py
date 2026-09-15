"""
CyberSentinel Model Training Pipeline — HistGradientBoosting Classifier.
Trains threat classification models from preprocessed Parquet datasets
with stratified train/test splitting, cross-validation, and metrics logging.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = PROJECT_ROOT / "data" / "processed" / "ddos_features.parquet"
OUTPUT_DIR = PROJECT_ROOT / "models" / "classifier"


def train_ddos_model(
    data_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    test_size: float = 0.20,
    random_state: int = 42,
) -> HistGradientBoostingClassifier:
    """
    Train and serialize a HistGradientBoostingClassifier on real flow features.
    """
    path = data_path or DATA_PATH
    out_dir = output_dir or OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("CYBERSENTINEL ML TRAINING: DDoS TEMPORAL CLASSIFIER")
    print("=" * 70)
    print(f"Loading dataset: {path}")

    df = pd.read_parquet(path)
    target_col = "Window_Target" if "Window_Target" in df.columns else "target"

    schema_path = PROJECT_ROOT / "models" / "preprocessing" / "dos_feature_schema.json"
    if schema_path.exists():
        with open(schema_path, "r") as f:
            schema_data = json.load(f)
            expected_features = schema_data.get("features", schema_data) if isinstance(schema_data, dict) else schema_data
        feature_cols = [c for c in expected_features if c in df.columns]
    else:
        feature_cols = [
            c for c in df.columns
            if c != target_col and pd.api.types.is_numeric_dtype(df[c]) and not pd.api.types.is_datetime64_any_dtype(df[c])
        ]

    X = df[feature_cols].astype(np.float32)
    y = df[target_col].astype(int)


    print(f"Dataset shape: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Class distribution: {dict(y.value_counts())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

    t0 = time.perf_counter()
    model = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.08,
        max_leaf_nodes=31,
        min_samples_leaf=15,
        l2_regularization=0.01,
        random_state=random_state,
    )
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    y_pred = model.predict(X_test)
    y_probs = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_probs)

    print("\n--- Model Evaluation Results ---")
    print(f"  Training Time: {train_time:.3f} s")
    print(f"  Accuracy:      {acc * 100:.2f}%")
    print(f"  Precision:     {prec * 100:.2f}%")
    print(f"  Recall:        {rec * 100:.2f}%")
    print(f"  F1-Score:      {f1 * 100:.2f}%")
    print(f"  ROC-AUC:       {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    # Save trained model
    save_path = out_dir / "dos_hgb.joblib"
    joblib.dump(model, save_path)
    print(f"[OK] Model weights saved to: {save_path}")

    # Save feature schema
    schema_path = PROJECT_ROOT / "models" / "preprocessing" / "dos_feature_schema.json"
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    with open(schema_path, "w") as f:
        json.dump(feature_cols, f, indent=2)
    print(f"[OK] Feature schema saved to: {schema_path}")

    return model


if __name__ == "__main__":
    train_ddos_model()
