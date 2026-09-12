#!/usr/bin/env python
"""CODEZILLA strict modern-2025 UWF Zeek validation.

Default evaluation is leakage-resistant group/file holdout:
- attack traffic is held out by tactic folder (all rows from that tactic stay in test)
- benign traffic is partitioned into matching folds and never overlaps train/test
- predictions from every held-out fold are aggregated into one honest OOF test set

A legacy random split is still available with --mode random for comparison only.
This is an auxiliary modern benchmark and does not replace production detectors.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder

NUMERIC = [
    "duration", "missed_bytes", "orig_bytes", "orig_ip_bytes",
    "orig_pkts", "resp_bytes", "resp_ip_bytes", "resp_pkts",
]
CATEGORICAL = [
    "conn_state", "history", "service", "proto", "local_orig", "local_resp",
]
LABEL_CANDIDATES = [
    "label_tactic_binary", "label_tactic", "label", "tactic", "attack", "class",
]
BENIGN_NAMES = {"benign", "normal", "background"}


def discover_files(root: Path) -> list[Path]:
    files = sorted(list(root.rglob("*.csv")) + list(root.rglob("*.parquet")))
    if not files and root.is_file() and root.suffix.lower() in {".csv", ".parquet"}:
        files = [root]
    return files


def read_one(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def choose_label(df: pd.DataFrame) -> str:
    lower = {str(c).lower(): c for c in df.columns}
    for name in LABEL_CANDIDATES:
        if name in lower:
            return lower[name]
    raise ValueError("No supported label column found. Expected: " + ", ".join(LABEL_CANDIDATES))


def binary_target(series: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().mean() > 0.95:
        return (numeric.fillna(0) != 0).astype(int)
    text = series.astype(str).str.strip().str.lower()
    return (~text.isin({"benign", "normal", "background", "none", "0", "false"})).astype(int)


def build_pipeline(num_cols: list[str], cat_cols: list[str]) -> Pipeline:
    pre = ColumnTransformer(
        transformers=[
            ("num", Pipeline([("imputer", SimpleImputer(strategy="median"))]), num_cols),
            ("cat", Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("encoder", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)),
            ]), cat_cols),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )
    model = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.05,
        max_leaf_nodes=31,
        min_samples_leaf=25,
        l2_regularization=1.0,
        random_state=42,
    )
    return Pipeline([("preprocess", pre), ("model", model)])


def metric_bundle(y_true: pd.Series, prob: np.ndarray, threshold: float = 0.50) -> dict:
    pred = (prob >= threshold).astype(int)
    out = {
        "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, pred).tolist(),
        "classification_report": classification_report(y_true, pred, output_dict=True, zero_division=0),
    }
    out["roc_auc"] = float(roc_auc_score(y_true, prob)) if y_true.nunique() == 2 else None
    return out


def prepare(root: Path, max_rows: int) -> tuple[pd.DataFrame, str, list[str], list[str]]:
    files = discover_files(root)
    if not files:
        raise SystemExit(f"No CSV/Parquet files found under {root}")

    print(f"[1/7] Reading {len(files)} files from {root}")
    frames: list[pd.DataFrame] = []
    for path in files:
        try:
            part = read_one(path)
            if len(part):
                part = part.copy()
                # First directory below dataset root is the traffic/tactic group.
                try:
                    rel = path.relative_to(root)
                    group = rel.parts[0] if len(rel.parts) > 1 else path.stem
                except ValueError:
                    group = path.parent.name or path.stem
                part["_source_group"] = str(group)
                frames.append(part)
        except Exception as exc:
            print(f"WARN: skipped {path.name}: {exc}")
    if not frames:
        raise SystemExit("No readable dataset files were found.")

    df = pd.concat(frames, ignore_index=True, sort=False)
    print(f"Loaded rows: {len(df):,}; columns: {len(df.columns)}")
    label_col = choose_label(df)
    df["_target"] = binary_target(df[label_col])

    num_cols = [c for c in NUMERIC if c in df.columns]
    cat_cols = [c for c in CATEGORICAL if c in df.columns]
    if len(num_cols) + len(cat_cols) < 4:
        raise SystemExit(f"Too few recognized behavioural features. Columns: {sorted(map(str, df.columns))}")

    keep = num_cols + cat_cols + ["_target", "_source_group"]
    work = df[keep].copy()
    for c in num_cols:
        work[c] = pd.to_numeric(work[c], errors="coerce")
    for c in cat_cols:
        work[c] = work[c].astype(str).replace({"nan": "<MISSING>"})
    work["_source_group"] = work["_source_group"].astype(str)

    if max_rows and len(work) > max_rows:
        # Stratified cap while retaining source-group information.
        sampled, _ = train_test_split(work, train_size=max_rows, stratify=work["_target"], random_state=42)
        work = sampled.reset_index(drop=True)
        print(f"Applied stratified row cap: {len(work):,}")

    return work, str(label_col), num_cols, cat_cols


def strict_group_eval(work: pd.DataFrame, num_cols: list[str], cat_cols: list[str]) -> tuple[dict, dict]:
    groups = sorted(work["_source_group"].unique())
    benign_group = next((g for g in groups if g.strip().lower() in BENIGN_NAMES), None)
    attack_groups = [g for g in groups if g != benign_group and (work.loc[work["_source_group"] == g, "_target"].mean() > 0.5)]
    if benign_group is None or not attack_groups:
        raise SystemExit(f"Could not identify benign + attack groups. Found groups: {groups}")

    benign = work[work["_source_group"] == benign_group].copy().reset_index(drop=True)
    attack_by_group = {g: work[work["_source_group"] == g].copy() for g in attack_groups}
    benign_parts = np.array_split(benign.index.to_numpy(), len(attack_groups))

    all_truth: list[int] = []
    all_prob: list[float] = []
    fold_rows = []

    for fold_id, attack_group in enumerate(attack_groups):
        test_benign_idx = set(benign_parts[fold_id].tolist())
        test_benign = benign.loc[sorted(test_benign_idx)].copy()
        test_attack = attack_by_group[attack_group].copy()
        test = pd.concat([test_benign, test_attack], ignore_index=True)

        train_benign = benign.drop(index=sorted(test_benign_idx))
        train_attack = work[~work["_source_group"].isin([benign_group, attack_group])]
        train = pd.concat([train_benign, train_attack], ignore_index=True)

        X_train = train[num_cols + cat_cols]
        y_train = train["_target"]
        X_test = test[num_cols + cat_cols]
        y_test = test["_target"]

        pipe = build_pipeline(num_cols, cat_cols)
        pipe.fit(X_train, y_train)
        prob = pipe.predict_proba(X_test)[:, 1]
        all_truth.extend(y_test.astype(int).tolist())
        all_prob.extend(prob.astype(float).tolist())

        fm = metric_bundle(y_test, prob)
        fold_rows.append({
            "fold": fold_id + 1,
            "held_out_attack_group": attack_group,
            "train_rows": len(train),
            "test_rows": len(test),
            "test_benign_rows": len(test_benign),
            "test_attack_rows": len(test_attack),
            "accuracy": fm["accuracy"],
            "precision": fm["precision"],
            "recall": fm["recall"],
            "f1": fm["f1"],
            "roc_auc": fm["roc_auc"],
        })
        print(f"  Fold {fold_id+1}/{len(attack_groups)}: hold out {attack_group:20s} | F1={fm['f1']:.4f} Recall={fm['recall']:.4f}")

    y_all = pd.Series(all_truth, name="target")
    prob_all = np.asarray(all_prob, dtype=float)
    overall = metric_bundle(y_all, prob_all)
    details = {
        "evaluation_method": "grouped_out_of_group_cross_validation",
        "group_column": "_source_group",
        "benign_group": benign_group,
        "attack_groups": attack_groups,
        "folds": fold_rows,
        "overall": overall,
        "test_rows_total": int(len(y_all)),
    }
    return overall, details


def random_eval(work: pd.DataFrame, num_cols: list[str], cat_cols: list[str]) -> tuple[dict, dict]:
    X = work[num_cols + cat_cols]
    y = work["_target"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
    pipe = build_pipeline(num_cols, cat_cols)
    pipe.fit(X_train, y_train)
    prob = pipe.predict_proba(X_test)[:, 1]
    m = metric_bundle(y_test, prob)
    return m, {"evaluation_method": "random_stratified_split", "train_rows": len(X_train), "test_rows": len(X_test)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV/Parquet file or dataset directory")
    ap.add_argument("--dataset-name", default="UWF-ZeekDataSum2025-1")
    ap.add_argument("--max-rows", type=int, default=0, help="Safety cap; 0 = no cap")
    ap.add_argument("--mode", choices=["strict", "random"], default="strict")
    ap.add_argument("--threshold", type=float, default=0.50)
    args = ap.parse_args()

    root = Path(args.data).resolve()
    work, label_col, num_cols, cat_cols = prepare(root, args.max_rows)

    print(f"[2/7] Target distribution: benign={(work['_target']==0).sum():,}, threat={(work['_target']==1).sum():,}")
    print(f"Recognized features: numeric={len(num_cols)}, categorical={len(cat_cols)}")

    if args.mode == "strict":
        print("[3/7] Using leakage-resistant file/tactic holdout evaluation")
        metrics, details = strict_group_eval(work, num_cols, cat_cols)
    else:
        print("[3/7] WARNING: using random stratified split for comparison only")
        metrics, details = random_eval(work, num_cols, cat_cols)

    # Retrain a final auxiliary benchmark model on ALL rows for artifact/demo use.
    print("[4/7] Training final auxiliary 2025 model on all available rows")
    final_pipe = build_pipeline(num_cols, cat_cols)
    final_pipe.fit(work[num_cols + cat_cols], work["_target"])

    out = Path(__file__).resolve().parents[1] / "evaluation" / "modern_2025" / "output"
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_pipe, out / "uwf_2025_hgb.joblib")

    result = {
        "dataset": args.dataset_name,
        "label_column": label_col,
        "rows_used": int(len(work)),
        "features_numeric": num_cols,
        "features_categorical": cat_cols,
        "evaluation": details,
        "metrics": metrics,
        "warning": "Do not use random-split 1.0000 results as headline evidence; strict grouped evaluation is the defensible result.",
        "production_status": "auxiliary_validation_only",
    }
    (out / "uwf_2025_metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    schema = {
        "model_name": "CODEZILLA-UWF-2025-HGB",
        "dataset": args.dataset_name,
        "feature_count": len(num_cols) + len(cat_cols),
        "numeric_features": num_cols,
        "categorical_features": cat_cols,
        "decision_threshold": args.threshold,
        "task": "binary benign vs threat on modern UWF Zeek data",
        "evaluation_method": details.get("evaluation_method"),
        "note": "Auxiliary modern benchmark; does not replace DDoS/C2/DNS/encrypted production detectors.",
    }
    (out / "uwf_2025_feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    print("[5/7] Saved artifacts:")
    for p in sorted(out.iterdir()):
        print(" -", p)

    print("[6/7] FINAL 2025 RESULTS")
    for key in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        value = metrics.get(key)
        print(f"{key.upper():9s}: {value if value is None else f'{value:.4f}'}")
    print("CONFUSION:", metrics["confusion_matrix"])
    print(f"TEST ROWS: {details.get('test_rows_total', details.get('test_rows'))}")
    print(f"METHOD: {details['evaluation_method']}")
    print("[7/7] Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
