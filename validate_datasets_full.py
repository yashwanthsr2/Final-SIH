"""
Phase 5: Exhaustive Dataset Validation Script.
Inspects processed parquets and modern 2025 raw Zeek data without fabricating statistics.
"""
import os
import glob
from pathlib import Path
import pandas as pd
import numpy as np

DATA_DIR = Path("data")

def inspect_parquet(path):
    print(f"\n--- Parquet File: {path.name} ---")
    df = pd.read_parquet(path)
    print(f"  Rows: {len(df):,}")
    print(f"  Columns ({len(df.columns)}): {list(df.columns)}")
    print(f"  Memory: {df.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB")
    print(f"  Missing values total: {df.isna().sum().sum()}")
    print(f"  Duplicate rows: {df.duplicated().sum()}")
    
    # Class / label distribution
    label_cols = [c for c in df.columns if c.lower() in ('label', 'target', 'threat', 'is_threat', 'class')]
    if label_cols:
        for lc in label_cols:
            print(f"  Label column '{lc}' distribution:")
            vc = df[lc].value_counts(dropna=False)
            for k, v in vc.items():
                print(f"    {k}: {v:,} ({v/len(df)*100:.2f}%)")
    else:
        print("  No explicit single binary label column. Feature table schema.")
    
    # Check numeric stats
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = np.isinf(df[numeric_cols]).sum().sum() if len(numeric_cols) > 0 else 0
    print(f"  Infinite values: {inf_count}")

def inspect_raw_modern():
    raw_dir = DATA_DIR / "modern_2025" / "UWF-ZeekDataSum25-1"
    print(f"\n=======================================================")
    print(f"RAW 2025 DATASET: UWF-ZeekDataSum25-1")
    print(f"=======================================================")
    if not raw_dir.exists():
        print("  Raw directory not found.")
        return
    
    categories = [d for d in raw_dir.iterdir() if d.is_dir()]
    total_files = 0
    total_rows = 0
    category_summary = {}

    for cat in sorted(categories):
        csvs = list(cat.glob("*.csv"))
        file_count = len(csvs)
        total_files += file_count
        # sample first file to check schema & count total rows across category
        cat_rows = 0
        sample_cols = []
        for f in csvs:
            # count lines quickly
            with open(f, 'rb') as fp:
                lines = sum(1 for _ in fp) - 1 # minus header
                cat_rows += max(0, lines)
        
        if csvs:
            sample_df = pd.read_csv(csvs[0], nrows=2)
            sample_cols = list(sample_df.columns)
            
        category_summary[cat.name] = {
            "files": file_count,
            "rows": cat_rows,
            "sample_columns": sample_cols
        }
        total_rows += cat_rows
        print(f"  • {cat.name:22s}: {file_count:3d} CSV files | {cat_rows:10,d} records")

    print(f"\n  TOTAL RAW 2025 RECORDS: {total_rows:,} across {total_files} partition files.")
    if categories:
        first_cat = sorted(categories)[0]
        first_csv = list(first_cat.glob("*.csv"))[0]
        df_sample = pd.read_csv(first_csv, nrows=5)
        print(f"\n  Raw Zeek CSV Schema ({len(df_sample.columns)} fields):")
        print(f"  {list(df_sample.columns)}")

if __name__ == "__main__":
    print("=======================================================")
    print("PHASE 5: DATASET INSPECTION & VALIDATION")
    print("=======================================================")
    processed_files = sorted(list((DATA_DIR / "processed").glob("*.parquet")))
    print(f"Processed Feature Stores: {len(processed_files)} files found.")
    for p in processed_files:
        inspect_parquet(p)
    
    inspect_raw_modern()
