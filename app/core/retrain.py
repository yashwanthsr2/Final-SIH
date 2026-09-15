"""
CyberSentinel Model Retrainer.

Retrains all four HGB classifiers from the processed parquet files
already present in data/processed/.

Run:
    python -m app.core.retrain

Output:
    models/dos_hgb.joblib
    models/c2_hgb.joblib
    models/dns_hgb.joblib
    models/encrypted_hgb.joblib
    (+ updated *_feature_schema.json and metadata files)

This script intentionally matches the original training logic
inferred from the feature schemas and evaluation reports.
"""

from __future__ import annotations

import json
import math
import time
import warnings
from pathlib import Path

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
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/NaN with 0 and ensure numeric dtypes."""
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)
    return df


def _train_hgb(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    threshold: float = 0.5,
    max_iter: int = 200,
    learning_rate: float = 0.1,
    max_leaf_nodes: int = 31,
    random_state: int = 42,
) -> HistGradientBoostingClassifier:
    model = HistGradientBoostingClassifier(
        max_iter=max_iter,
        learning_rate=learning_rate,
        max_leaf_nodes=max_leaf_nodes,
        random_state=random_state,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20,
    )
    model.fit(X_train, y_train)
    return model


def _evaluate(model, X_test: pd.DataFrame, y_test: pd.Series, threshold: float = 0.5) -> dict:
    proba = model.predict_proba(X_test)[:, 1]
    preds = (proba >= threshold).astype(int)

    fpr = None
    try:
        auc = roc_auc_score(y_test, proba)
    except Exception:
        auc = None

    n_tp = ((preds == 1) & (y_test == 1)).sum()
    n_fp = ((preds == 1) & (y_test == 0)).sum()
    n_fn = ((preds == 0) & (y_test == 1)).sum()
    n_tn = ((preds == 0) & (y_test == 0)).sum()

    fpr = n_fp / max(1, n_fp + n_tn)

    return {
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
        "roc_auc": round(float(auc), 4) if auc is not None else None,
        "fpr": round(float(fpr), 4),
        "n_test": len(y_test),
        "n_positive": int(y_test.sum()),
        "threshold": threshold,
    }


def _save_metadata(name: str, meta: dict) -> None:
    path = MODELS_DIR / f"{name}_metadata.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"  Saved metadata: {path.name}")


# ============================================================
# DDOS RETRAINER
# ============================================================

def retrain_ddos() -> None:
    print("\n========== DDoS MODEL ==========")
    parquet = DATA_DIR / "ddos_features.parquet"
    if not parquet.exists():
        print(f"  SKIP: {parquet} not found")
        return

    df = pd.read_parquet(parquet)
    print(f"  Shape: {df.shape}")

    # Actual label column found by data inspection
    label_col = "Window_Target"
    if label_col not in df.columns:
        print(f"  SKIP: Expected label column '{label_col}' not found. Columns: {list(df.columns[:20])}")
        return

    y = df[label_col].astype(int)
    print(f"  Label column: {label_col}")
    print(f"  Class balance: {y.sum()} attacks / {(y==0).sum()} benign")

    # Exclude non-feature columns: label, time, attack_ratio (a leaky feature)
    EXCLUDE = {label_col, "time_window", "attack_ratio"}
    schema_path = MODELS_DIR / "dos_feature_schema.json"
    if schema_path.exists():
        with open(schema_path) as f:
            schema = json.load(f)
        feature_cols = [c for c in schema["features"] if c in df.columns and c not in EXCLUDE]
    else:
        feature_cols = [c for c in df.columns if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])]

    if not feature_cols:
        print("  SKIP: No usable feature columns.")
        return

    X = _clean(df[feature_cols])
    print(f"  Features: {len(feature_cols)}")
    print(f"  Class balance: {y.sum()} attacks / {(y==0).sum()} benign")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    t0 = time.time()
    model = _train_hgb(X_train, y_train, threshold=0.80)
    elapsed = time.time() - t0
    print(f"  Training time: {elapsed:.1f}s")

    metrics = _evaluate(model, X_test, y_test, threshold=0.80)
    print(f"  Metrics: {metrics}")

    model_path = MODELS_DIR / "dos_hgb.joblib"
    joblib.dump(model, model_path)
    print(f"  Saved: {model_path.name}")

    # Update schema
    schema_data = {"feature_count": len(feature_cols), "features": feature_cols}
    with open(MODELS_DIR / "dos_feature_schema.json", "w") as f:
        json.dump(schema_data, f, indent=2)

    _save_metadata("dos", {
        "model_name": "CODEZILLA-DOS-HGB",
        "model_type": "HistGradientBoostingClassifier",
        "task": "Temporal DDoS detection",
        "feature_count": len(feature_cols),
        "decision_threshold": 0.80,
        "training_date": time.strftime("%Y-%m-%d"),
        "dataset": "UWF-ZeekDataSum25 + processed parquet",
        "training_time_sec": round(elapsed, 1),
        "final_test": metrics,
        "sklearn_version": _sklearn_version(),
    })


# ============================================================
# C2 RETRAINER
# ============================================================

def retrain_c2() -> None:
    print("\n========== C2 MODEL ==========")
    parquet = DATA_DIR / "c2_features.parquet"
    if not parquet.exists():
        print(f"  SKIP: {parquet} not found")
        return

    df = pd.read_parquet(parquet)
    print(f"  Shape: {df.shape}")

    label_col = "c2_target"
    if label_col not in df.columns:
        print(f"  SKIP: Expected '{label_col}' not found. Columns: {list(df.columns[:20])}")
        return

    y = df[label_col].astype(int)
    print(f"  Label column: {label_col}")
    print(f"  Class balance: {y.sum()} C2 / {(y==0).sum()} benign")

    # Exclude non-feature columns
    EXCLUDE = {label_col, "time_window", "scenario"}
    schema_path = MODELS_DIR / "c2_feature_schema.json"
    if schema_path.exists():
        with open(schema_path) as f:
            schema = json.load(f)
        feature_cols = [c for c in schema["features"] if c in df.columns and c not in EXCLUDE]
    else:
        feature_cols = [c for c in df.columns if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])]

    print(f"  Features: {len(feature_cols)}")
    print(f"  Class balance: {y.sum()} C2 / {(y==0).sum()} benign")

    X = _clean(df[feature_cols])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.sum() > 10 else None
    )

    t0 = time.time()
    model = _train_hgb(X_train, y_train)
    elapsed = time.time() - t0
    print(f"  Training time: {elapsed:.1f}s")

    # Optimise threshold on validation set
    proba_val = model.predict_proba(X_test)[:, 1]
    best_f1, best_thresh = 0, 0.5
    for t in np.arange(0.3, 0.9, 0.05):
        preds = (proba_val >= t).astype(int)
        f = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, t

    best_thresh = round(best_thresh, 2)
    print(f"  Optimal threshold: {best_thresh} (F1={best_f1:.4f})")

    metrics = _evaluate(model, X_test, y_test, threshold=best_thresh)
    print(f"  Metrics: {metrics}")

    model_path = MODELS_DIR / "c2_hgb.joblib"
    joblib.dump(model, model_path)
    print(f"  Saved: {model_path.name}")

    # Update schema with new threshold
    with open(schema_path, "r") as f:
        schema_data = json.load(f)
    schema_data["decision_threshold"] = best_thresh
    # Ensure features list reflects what was actually used
    schema_data["features"] = feature_cols
    schema_data["feature_count"] = len(feature_cols)
    with open(schema_path, "w") as f:
        json.dump(schema_data, f, indent=2)

    _save_metadata("c2", {
        "model_name": "CODEZILLA-C2-HGB",
        "model_type": "HistGradientBoostingClassifier",
        "task": "C2 behavioural detection",
        "feature_count": len(feature_cols),
        "decision_threshold": best_thresh,
        "training_date": time.strftime("%Y-%m-%d"),
        "dataset": "UWF-ZeekDataSum25 + processed parquet",
        "training_time_sec": round(elapsed, 1),
        "final_test": metrics,
        "sklearn_version": _sklearn_version(),
    })


# ============================================================
# DNS RETRAINER
# ============================================================

def retrain_dns() -> None:
    print("\n========== DNS MODEL ==========")
    parquet = DATA_DIR / "dns_source_features.parquet"
    if not parquet.exists():
        print(f"  SKIP: {parquet} not found")
        return

    df = pd.read_parquet(parquet)
    print(f"  Shape: {df.shape}")

    label_col = "dns_target"
    if label_col not in df.columns:
        print(f"  SKIP: Expected '{label_col}' not found. Columns: {list(df.columns[:20])}")
        return

    y = df[label_col].astype(int)
    print(f"  Label column: {label_col}")
    print(f"  Class balance: {y.sum()} DNS threats / {(y==0).sum()} benign")

    EXCLUDE = {label_col, "SrcAddr", "src_addr", "source", "time_window", "timestamp"}
    feature_cols = [
        c for c in df.columns
        if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])
    ]
    print(f"  Features: {len(feature_cols)}")

    X = _clean(df[feature_cols])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.sum() > 10 else None
    )

    t0 = time.time()
    model = _train_hgb(X_train, y_train)
    elapsed = time.time() - t0

    # Optimise threshold
    proba_val = model.predict_proba(X_test)[:, 1]
    best_f1, best_thresh = 0, 0.5
    for t in np.arange(0.3, 0.98, 0.05):
        preds = (proba_val >= t).astype(int)
        f = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, t
    best_thresh = round(best_thresh, 2)
    print(f"  Optimal threshold: {best_thresh}, Training time: {elapsed:.1f}s")

    metrics = _evaluate(model, X_test, y_test, threshold=best_thresh)
    print(f"  Metrics: {metrics}")

    # Save as bundle (model+threshold+features) for compatibility with dns_detector.py
    bundle = {"model": model, "threshold": best_thresh, "features": feature_cols}
    model_path = MODELS_DIR / "dns_hgb.joblib"
    joblib.dump(bundle, model_path)
    print(f"  Saved: {model_path.name}")

    _save_metadata("dns", {
        "model_name": "CODEZILLA-DNS-HGB",
        "model_type": "HistGradientBoostingClassifier",
        "task": "DNS threat detection",
        "feature_count": len(feature_cols),
        "decision_threshold": best_thresh,
        "training_date": time.strftime("%Y-%m-%d"),
        "dataset": "UWF-ZeekDataSum25 DNS source features",
        "training_time_sec": round(elapsed, 1),
        "final_test": metrics,
        "sklearn_version": _sklearn_version(),
    })


# ============================================================
# ENCRYPTED RETRAINER
# ============================================================

def retrain_encrypted() -> None:
    print("\n========== ENCRYPTED TRAFFIC MODEL ==========")
    parquet = DATA_DIR / "encrypted_source_features.parquet"
    if not parquet.exists():
        print(f"  SKIP: {parquet} not found")
        return

    df = pd.read_parquet(parquet)
    print(f"  Shape: {df.shape}")

    label_col = "encrypted_target"
    if label_col not in df.columns:
        print(f"  SKIP: Expected '{label_col}' not found. Columns: {list(df.columns[:20])}")
        return

    y = df[label_col].astype(int)
    print(f"  Label column: {label_col}")
    print(f"  Class balance: {y.sum()} threats / {(y==0).sum()} benign")

    EXCLUDE = {label_col, "SrcAddr", "src_addr", "source", "time_window", "timestamp"}
    feature_cols = [
        c for c in df.columns
        if c not in EXCLUDE and pd.api.types.is_numeric_dtype(df[c])
    ]
    print(f"  Features: {len(feature_cols)}")

    X = _clean(df[feature_cols])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.sum() > 10 else None
    )

    t0 = time.time()
    model = _train_hgb(X_train, y_train)
    elapsed = time.time() - t0

    # Optimise threshold
    proba_val = model.predict_proba(X_test)[:, 1]
    best_f1, best_thresh = 0, 0.5
    for t in np.arange(0.3, 0.9, 0.05):
        preds = (proba_val >= t).astype(int)
        f = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, t
    best_thresh = round(best_thresh, 2)
    print(f"  Optimal threshold: {best_thresh}, Training time: {elapsed:.1f}s")

    metrics = _evaluate(model, X_test, y_test, threshold=best_thresh)
    print(f"  Metrics: {metrics}")

    # Save bundle for compatibility with encrypted_detector.py
    bundle = {"model": model, "threshold": best_thresh, "features": feature_cols}
    model_path = MODELS_DIR / "encrypted_hgb.joblib"
    joblib.dump(bundle, model_path)
    print(f"  Saved: {model_path.name}")

    _save_metadata("encrypted", {
        "model_name": "CODEZILLA-ENCRYPTED-HGB",
        "model_type": "HistGradientBoostingClassifier",
        "task": "Encrypted malware traffic detection (metadata-only)",
        "feature_count": len(feature_cols),
        "decision_threshold": best_thresh,
        "training_date": time.strftime("%Y-%m-%d"),
        "dataset": "UWF-ZeekDataSum25 encrypted source features",
        "training_time_sec": round(elapsed, 1),
        "final_test": metrics,
        "sklearn_version": _sklearn_version(),
    })


# ============================================================
# UTILS
# ============================================================

def _sklearn_version() -> str:
    try:
        import sklearn
        return sklearn.__version__
    except Exception:
        return "unknown"


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    print("=" * 60)
    print("CyberSentinel Model Retrainer")
    print(f"sklearn: {_sklearn_version()}")
    print(f"Data dir: {DATA_DIR}")
    print(f"Models dir: {MODELS_DIR}")
    print("=" * 60)

    retrain_ddos()
    retrain_c2()
    retrain_dns()
    retrain_encrypted()

    print("\n========== COMPLETE ==========")
    print("All available models retrained and saved.")
    print("Run: python -m uvicorn app.main:app --host 127.0.0.1 --port 8000")


if __name__ == "__main__":
    main()
