"""
CyberSentinel Machine Learning Models Evaluation Suite.
Evaluates accuracy, precision, recall, F1, ROC-AUC, confusion matrix, and latency.
"""

import time
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data" / "processed"

MODEL_CONFIGS = [
    {
        "name": "DDoS",
        "file": "dos_hgb.joblib",
        "metadata": "dos_metadata.json",
        "schema": "dos_feature_schema.json",
        "data_file": "ddos_features.parquet",
        "target_col": "Window_Target",
        "drop_cols": ["time_window", "Window_Target", "attack_ratio"],
        "subdirs": ["classifier", ""],
    },
    {
        "name": "C2 Beaconing",
        "file": "c2_hgb.joblib",
        "metadata": "c2_metadata.json",
        "schema": "c2_feature_schema.json",
        "data_file": "c2_features.parquet",
        "target_col": "c2_target",
        "drop_cols": ["time_window", "c2_target", "scenario"],
        "subdirs": ["classifier", ""],
    },
    {
        "name": "DNS Threat",
        "file": "dns_hgb.joblib",
        "metadata": "dns_metadata.json",
        "data_file": "dns_source_features.parquet",
        "target_col": "dns_target",
        "drop_cols": ["SrcAddr", "time_window", "dns_target"],
        "subdirs": ["classifier", ""],
    },
    {
        "name": "Encrypted Session",
        "file": "encrypted_hgb.joblib",
        "metadata": "encrypted_metadata.json",
        "data_file": "encrypted_source_features.parquet",
        "target_col": "encrypted_target",
        "drop_cols": ["SrcAddr", "time_window", "encrypted_target"],
        "subdirs": ["anomaly", ""],
    },
]

def find_model_file(filename, subdirs):
    for sub in subdirs:
        p = (MODELS_DIR / sub / filename) if sub else (MODELS_DIR / filename)
        if p.exists():
            return p
    return None

def evaluate_model(cfg):
    print("=" * 70)
    print(f"EVALUATING MODEL: {cfg['name']}")
    print("=" * 70)

    model_path = find_model_file(cfg["file"], cfg["subdirs"])
    if not model_path:
        print(f"Model file not found: {cfg['file']}")
        return None

    import warnings
    warnings.filterwarnings("ignore")

    raw_loaded = joblib.load(model_path)
    bundle_features = None
    if isinstance(raw_loaded, dict):
        if "features" in raw_loaded:
            bundle_features = list(raw_loaded["features"])
        model = raw_loaded.get("model", raw_loaded)
    else:
        model = raw_loaded

    data_path = DATA_DIR / cfg["data_file"]
    if not data_path.exists():
        print(f"Data file not found: {data_path}")
        return None

    df = pd.read_parquet(data_path)
    print(f"Data Loaded: {len(df):,} rows x {len(df.columns)} columns")

    y = df[cfg["target_col"]].values
    feature_cols = [c for c in df.columns if c not in cfg["drop_cols"]]
    
    if bundle_features:
        for ef in bundle_features:
            if ef not in df.columns:
                df[ef] = 0.0
        X = df[bundle_features].values
    elif hasattr(model, "feature_names_in_"):
        expected_features = list(model.feature_names_in_)
        for ef in expected_features:
            if ef not in df.columns:
                df[ef] = 0.0
        X = df[expected_features].values
    else:
        X = df[feature_cols].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
    )

    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    eval_latency = (time.perf_counter() - t0) * 1000

    y_proba = None
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test)
        y_proba = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_proba) if (y_proba is not None and len(np.unique(y_test)) > 1) else 0.0

    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"Latency:   {eval_latency:.2f} ms")

    return {
        "model": cfg["name"],
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "latency_ms": eval_latency,
    }

def main():
    print("CYBERSENTINEL ML PIPELINE EVALUATION")
    results = []
    for cfg in MODEL_CONFIGS:
        res = evaluate_model(cfg)
        if res:
            results.append(res)

if __name__ == "__main__":
    main()
