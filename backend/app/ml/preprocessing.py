"""
CyberSentinel Real-Time Feature Aligner & Preprocessor.
"""

from __future__ import annotations
from typing import Any, Dict, List
import pandas as pd
import numpy as np

def align_features(df: pd.DataFrame, expected_features: List[str]) -> pd.DataFrame:
    """Ensure dataframe has all expected features, filling missing with 0.0."""
    out = df.copy()
    for col in expected_features:
        if col not in out.columns:
            out[col] = 0.0
    return out[expected_features].astype(np.float32)
