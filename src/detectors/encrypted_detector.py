"""
CyberSentinel Encrypted Session Malware Detector.
Re-exports the canonical implementation from backend.app.detectors.encrypted_malware.encrypted_detector.
"""
from backend.app.detectors.encrypted_malware.encrypted_detector import (
    THREAT_CLASS,
    MODEL,
    THRESHOLD,
    FEATURES,
    detect,
)

__all__ = ["THREAT_CLASS", "MODEL", "THRESHOLD", "FEATURES", "detect"]