"""
CyberSentinel DNS Threat / DGA / Tunneling Detector.
Re-exports the canonical implementation from backend.app.detectors.dga_dns.dns_detector.
"""
from backend.app.detectors.dga_dns.dns_detector import (
    THREAT_CLASS,
    MODEL_BUNDLE,
    MODEL,
    THRESHOLD,
    FEATURES,
    detect,
)

__all__ = ["THREAT_CLASS", "MODEL_BUNDLE", "MODEL", "THRESHOLD", "FEATURES", "detect"]