"""
CyberSentinel Model Registry & Metadata API Router.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from fastapi import APIRouter
from backend.app.core.config import MODELS_DIR, MODELS_CLASSIFIER_DIR, MODELS_ANOMALY_DIR, MODELS_PREPROCESSING_DIR
from backend.app.ml import reload_models
import backend.app.database as db

router = APIRouter(tags=["Models"])

def load_model_metadata_list() -> List[Dict[str, Any]]:
    # Search preprocessing dir or models dir (exclude duplicate _model_metadata)
    metadata_files = [mf for mf in MODELS_PREPROCESSING_DIR.glob("*_metadata.json") if not mf.name.endswith("_model_metadata.json")]
    if not metadata_files:
        metadata_files = [mf for mf in MODELS_DIR.glob("*_metadata.json") if not mf.name.endswith("_model_metadata.json")]

    results = []
    for mf in metadata_files:
        try:
            with open(mf, encoding="utf-8") as f:
                meta = json.load(f)
            joblib_name = mf.stem.replace("_metadata", "_hgb") + ".joblib"
            p1 = MODELS_CLASSIFIER_DIR / joblib_name
            p2 = MODELS_ANOMALY_DIR / joblib_name
            p3 = MODELS_DIR / joblib_name
            actual_p = p1 if p1.exists() else (p2 if p2.exists() else (p3 if p3.exists() else None))
            meta["model_file"] = joblib_name
            meta["loaded"] = actual_p is not None
            meta["file_size_kb"] = round(actual_p.stat().st_size / 1024, 1) if actual_p else 0
            if "final_test" in meta and not meta.get("metrics"):
                meta["metrics"] = meta["final_test"]
            elif "metrics" in meta and not meta.get("final_test"):
                meta["final_test"] = meta["metrics"]
            results.append(meta)
            db.upsert_model_metadata(meta)
        except Exception:
            pass
    return results

@router.get("/api/models")
def get_models():
    models = db.get_all_models()
    if not models or any((not m.get("metrics") and not m.get("final_test")) or not m.get("loaded") for m in models):
        models = load_model_metadata_list()
    return {"count": len(models), "models": models}

@router.post("/api/reload-model")
def reload_model_registry():
    reload_models()
    models = load_model_metadata_list()
    return {"status": "reloaded", "count": len(models)}
