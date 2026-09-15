"""
CyberSentinel Reconnaissance / Port Scanning Detector.
Re-exports the canonical implementation from backend.app.detectors.reconnaissance.recon_detector.
"""
from backend.app.detectors.reconnaissance.recon_detector import (
    THREAT_CLASS,
    detect,
)

detect_recon = detect

__all__ = ["THREAT_CLASS", "detect", "detect_recon"]
