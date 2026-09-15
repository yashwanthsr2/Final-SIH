"""
CyberSentinel Unified Detection Service.
Re-exports and delegates to the canonical backend.app.services.alert_service.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import pandas as pd

from backend.app.services.alert_service import (
    analyze_request,
    run_detector,
    _normalize,
    _extract_score,
    _extract_evidence,
    _single_row,
    _severity_rank,
)

__all__ = [
    "analyze_request",
    "run_detector",
    "_normalize",
    "_extract_score",
    "_extract_evidence",
    "_single_row",
    "_severity_rank",
]