"""
CyberSentinel DDoS Detector.
Re-exports the canonical implementation from backend.app.detectors.ddos.dos_detector.
"""
from backend.app.detectors.ddos.dos_detector import (
    THREAT_CLASS,
    detect,
)

__all__ = ["THREAT_CLASS", "detect"]