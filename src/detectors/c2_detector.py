"""
CyberSentinel C2 Beaconing Detector.
Re-exports the canonical implementation from backend.app.detectors.beaconing.c2_detector.
"""
from backend.app.detectors.beaconing.c2_detector import (
    THREAT_CLASS,
    MODEL,
    SCHEMA,
    FEATURES,
    detect,
)

__all__ = ["THREAT_CLASS", "MODEL", "SCHEMA", "FEATURES", "detect"]