"""
CyberSentinel Data Exfiltration Detector.
Re-exports the canonical implementation from backend.app.detectors.exfiltration.exfil_detector.
"""
from backend.app.detectors.exfiltration.exfil_detector import (
    THREAT_CLASS,
    detect,
)

detect_exfil = detect

__all__ = ["THREAT_CLASS", "detect", "detect_exfil"]
