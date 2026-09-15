"""
Phase 6: Machine Learning Models Validation & Metrics Generator.
Loads each joblib model, reads the corresponding parquet dataset, splits train/test or evaluates on held-out data,
computes real metrics (Accuracy, Precision, Recall, F1, Macro/Weighted F1, Confusion Matrix, FP, FN, latency).
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

MODELS_DIR = Path("models")
DATA_DIR = Path("data/processed")

MODEL_CONFIGS = [
    {
        "name": "DDoS",
        "file": "dos_hgb.joblib",
        "metadata": "dos_metadata.json",
        "schema": "dos_feature_schema.json",
        "data_file": "ddos_features.parquet",
        "target_col": "Window_Target",
        "drop_cols": ["time_window", "Window_Target", "attack_ratio"],
    },
    {
        "name": "C2 Beaconing",
        "file": "c2_hgb.joblib",
        "metadata": "c2_metadata.json",
        "schema": "c2_feature_schema.json",
        "data_file": "c2_features.parquet",
        "target_col": "c2_target",
        "drop_cols": ["time_window", "c2_target", "scenario"],
    },
    {
        "name": "DNS Threat",
        "file": "dns_hgb.joblib",
        "metadata": "dns_metadata.json",
        "data_file": "dns_source_features.parquet",
        "target_col": "dns_target",
        "drop_cols": ["SrcAddr", "time_window", "dns_target"],
    },
    {
        "name": "Encrypted Session",
        "file": "encrypted_hgb.joblib",
        "metadata": "encrypted_metadata.json",
        "data_file": "encrypted_source_features.parquet",
        "target_col": "encrypted_target",
        "drop_cols": ["SrcAddr", "time_window", "encrypted_target"],
    },
]

def evaluate_model(cfg):
    print("=" * 70)
    print(f"EVALUATING MODEL: {cfg['name']}")
    print("=" * 70)
    model_path = MODELS_DIR / cfg["file"]
    assert model_path.exists(), f"Model file missing: {model_path}"
    
    loaded = joblib.load(model_path)
    print(f"  Model Type: {type(loaded).__name__}")
    
    # Check if bundle or raw estimator
    if isinstance(loaded, dict):
        estimator = loaded.get("model") or loaded.get("estimator") or loaded.get("classifier")
        features = loaded.get("features") or loaded.get("feature_names")
        threshold = loaded.get("threshold", 0.5)
        print(f"  Container: dict bundle (estimator={type(estimator).__name__}, threshold={threshold})")
    else:
        estimator = loaded
        features = getattr(estimator, "feature_names_in_", None)
        threshold = 0.5
        print(f"  Container: direct estimator (threshold={threshold})")
        
    data_path = DATA_DIR / cfg["data_file"]
    assert data_path.exists(), f"Data file missing: {data_path}"
    df = pd.read_parquet(data_path)
    
    # Split features and target
    y = df[cfg["target_col"]].values
    
    if features is not None and len(features) > 0:
        used_features = [f for f in features if f in df.columns]
        X = df[used_features].copy()
    else:
        used_features = [c for c in df.columns if c not in cfg["drop_cols"]]
        X = df[used_features].copy()
        
    print(f"  Feature count: {len(used_features)}")
    
    # 80/20 train/test split to evaluate real generalization
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    print(f"  Test set size: {len(X_test):,} samples (Class 0: {(y_test==0).sum():,}, Class 1: {(y_test==1).sum():,})")
    
    # Inference Latency Benchmark
    t0 = time.perf_counter()
    if hasattr(estimator, "predict_proba"):
        probs = estimator.predict_proba(X_test)[:, 1]
    else:
        probs = estimator.decision_function(X_test)
        
    total_time = time.perf_counter() - t0
    latency_per_sample_us = (total_time / len(X_test)) * 1_000_000
    
    preds = (probs >= threshold).astype(int)
    
    # Metrics
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    macro_f1 = f1_score(y_test, preds, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, preds, average="weighted", zero_division=0)
    try:
        auc = roc_auc_score(y_test, probs)
    except:
        auc = 0.5
        
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    
    print("\n  ACTUAL METRICS (Test Set):")
    print(f"    • Accuracy:       {acc*100:.2f}%")
    print(f"    • Precision:      {prec*100:.2f}%")
    print(f"    • Recall:         {rec*100:.2f}%")
    print(f"    • F1 Score:       {f1*100:.2f}%")
    print(f"    • Macro F1:       {macro_f1*100:.2f}%")
    print(f"    • Weighted F1:    {weighted_f1*100:.2f}%")
    print(f"    • ROC-AUC:        {auc:.4f}")
    print(f"    • Decision Thresh:{threshold}")
    print(f"    • Mean Latency:   {latency_per_sample_us:.2f} microseconds/sample")
    print(f"\n  CONFUSION MATRIX:")
    print(f"    [TN: {tn:5d} | FP: {fp:5d}]")
    print(f"    [FN: {fn:5d} | TP: {tp:5d}]")
    print(f"    False Positive Rate: {fp / (fp + tn) * 100:.2f}%")
    print(f"    False Negative Rate: {fn / (fn + tp) * 100:.2f}%")
    
    return {
        "name": cfg["name"],
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "roc_auc": auc,
        "latency_us": latency_per_sample_us,
        "cm": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }

if __name__ == "__main__":
    results = []
    for cfg in MODEL_CONFIGS:
        results.append(evaluate_model(cfg))
    
    print("\n" + "=" * 70)
    print("PHASE 6 SUMMARY TABLE")
    print("=" * 70)
    print(f"{'Model':20s} | {'F1':7s} | {'ROC-AUC':7s} | {'Precision':9s} | {'Recall':7s} | {'Latency':12s}")
    print("-" * 70)
    for r in results:
        print(f"{r['name']:20s} | {r['f1']*100:6.1f}% | {r['roc_auc']:7.4f} | {r['precision']*100:8.1f}% | {r['recall']*100:6.1f}% | {r['latency_us']:8.2f} us")
    print("=" * 70)
