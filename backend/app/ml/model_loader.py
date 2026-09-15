"""
CyberSentinel Model Loader.
Loads trained scikit-learn models from models/ directories with caching.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional
import joblib

from backend.app.core.config import (
    MODELS_DIR,
    MODELS_CLASSIFIER_DIR,
    MODELS_ANOMALY_DIR,
)

# Compatibility shim for legacy sklearn pickles
try:
    import sklearn._loss as sklearn_loss
    sys.modules.setdefault("_loss", sklearn_loss)
except ImportError:
    pass

_MODEL_CACHE: Dict[str, Any] = {}

def get_model(model_name: str) -> Any:
    """
    Retrieve or load a model by filename or identifier.
    Searches models/classifier, models/anomaly, and models/ root.
    """
    if model_name in _MODEL_CACHE:
        return _MODEL_CACHE[model_name]

    filename = model_name if model_name.endswith(".joblib") else f"{model_name}.joblib"
    
    candidate_paths = [
        MODELS_CLASSIFIER_DIR / filename,
        MODELS_ANOMALY_DIR / filename,
        MODELS_DIR / filename,
    ]

    for p in candidate_paths:
        if p.exists():
            try:
                m = joblib.load(p)
                _MODEL_CACHE[model_name] = m
                return m
            except Exception as e:
                raise RuntimeError(f"Failed loading model from {p}: {e}")

    raise FileNotFoundError(f"Model {model_name} not found in candidate paths: {candidate_paths}")

def reload_models() -> None:
    """Clear model cache to force reload from disk."""
    _MODEL_CACHE.clear()

def get_all_models() -> Dict[str, Any]:
    """Retrieve and load all known standard classifier models."""
    models = {}
    for name in ["dos_hgb", "c2_hgb", "dns_hgb", "encrypted_hgb"]:
        try:
            models[name] = get_model(name)
        except Exception:
            pass
    return models
