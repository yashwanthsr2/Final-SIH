"""
CyberSentinel Model Training Pipeline — Encrypted Traffic Anomaly Detector.
Trains an anomaly scoring classifier on encrypted flow metadata
and packages it as a production bundle: {model, threshold, features}.
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
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "models" / "anomaly"

FEATURES = [
    "encrypted_flow_count",
    "encrypted_total_packets",
    "encrypted_total_bytes",
    "encrypted_unique_destinations",
    "encrypted_unique_ports",
    "encrypted_mean_duration",
    "bytes_per_flow",
    "packets_per_flow",
    "flow_count_prev",
    "flow_count_change",
    "bytes_prev",
    "bytes_change",
    "destination_change",
]


def train_encrypted_anomaly_model(
    output_dir: Optional[Path] = None,
    random_state: int = 42,
) -> HistGradientBoostingClassifier:
    """
    Train and bundle the encrypted traffic anomaly model.
    """
    out_dir = output_dir or OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("CYBERSENTINEL ML TRAINING: ENCRYPTED TRAFFIC ANOMALY MODEL")
    print("=" * 70)

    # Synthetic baseline generation for demonstration and reproducibility
    np.random.seed(random_state)
    n_benign = 1000
    n_anomaly = 200

    benign_data = {
        "encrypted_flow_count": np.random.poisson(lam=10, size=n_benign),
        "encrypted_total_packets": np.random.poisson(lam=150, size=n_benign),
        "encrypted_total_bytes": np.random.normal(loc=50000, scale=10000, size=n_benign).clip(1000),
        "encrypted_unique_destinations": np.random.randint(1, 5, size=n_benign),
        "encrypted_unique_ports": np.random.randint(1, 3, size=n_benign),
        "encrypted_mean_duration": np.random.exponential(scale=15.0, size=n_benign),
        "bytes_per_flow": np.random.normal(loc=5000, scale=1000, size=n_benign).clip(500),
        "packets_per_flow": np.random.normal(loc=15, scale=5, size=n_benign).clip(1),
        "flow_count_prev": np.random.poisson(lam=10, size=n_benign),
        "flow_count_change": np.random.normal(loc=0, scale=2, size=n_benign),
        "bytes_prev": np.random.normal(loc=50000, scale=10000, size=n_benign).clip(1000),
        "bytes_change": np.random.normal(loc=0, scale=5000, size=n_benign),
        "destination_change": np.random.choice([-1, 0, 1], size=n_benign),
        "label": np.zeros(n_benign, dtype=int),
    }

    # Anomalies: massive bursts, high destination diversity, extreme byte shifts
    anomaly_data = {
        "encrypted_flow_count": np.random.poisson(lam=80, size=n_anomaly),
        "encrypted_total_packets": np.random.poisson(lam=2500, size=n_anomaly),
        "encrypted_total_bytes": np.random.normal(loc=800000, scale=150000, size=n_anomaly).clip(50000),
        "encrypted_unique_destinations": np.random.randint(15, 60, size=n_anomaly),
        "encrypted_unique_ports": np.random.randint(10, 30, size=n_anomaly),
        "encrypted_mean_duration": np.random.exponential(scale=1.5, size=n_anomaly),
        "bytes_per_flow": np.random.normal(loc=10000, scale=2000, size=n_anomaly).clip(1000),
        "packets_per_flow": np.random.normal(loc=35, scale=10, size=n_anomaly).clip(5),
        "flow_count_prev": np.random.poisson(lam=10, size=n_anomaly),
        "flow_count_change": np.random.normal(loc=70, scale=15, size=n_anomaly),
        "bytes_prev": np.random.normal(loc=50000, scale=10000, size=n_anomaly).clip(1000),
        "bytes_change": np.random.normal(loc=750000, scale=150000, size=n_anomaly),
        "destination_change": np.random.randint(10, 50, size=n_anomaly),
        "label": np.ones(n_anomaly, dtype=int),
    }

    df_benign = pd.DataFrame(benign_data)
    df_anomaly = pd.DataFrame(anomaly_data)
    df = pd.concat([df_benign, df_anomaly], ignore_index=True)

    X = df[FEATURES].astype(np.float32)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )

    t0 = time.perf_counter()
    model = HistGradientBoostingClassifier(
        max_iter=100,
        learning_rate=0.08,
        random_state=random_state,
    )
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    y_pred = model.predict(X_test)
    y_probs = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_probs)

    print(f"Training time: {train_time:.3f}s | Test ROC-AUC: {auc:.4f}")
    print(classification_report(y_test, y_pred, digits=4))

    bundle = {
        "model": model,
        "threshold": 0.50,
        "features": FEATURES,
    }

    save_path = out_dir / "encrypted_hgb.joblib"
    joblib.dump(bundle, save_path)
    print(f"[OK] Anomaly bundle saved to: {save_path}")

    schema_path = PROJECT_ROOT / "models" / "preprocessing" / "encrypted_metadata.json"
    schema_path.parent.mkdir(parents=True, exist_ok=True)
    with open(schema_path, "w") as f:
        json.dump({"features": FEATURES, "threshold": 0.50, "roc_auc": round(auc, 4)}, f, indent=2)
    print(f"[OK] Metadata saved to: {schema_path}")

    return model


if __name__ == "__main__":
    train_encrypted_anomaly_model()
