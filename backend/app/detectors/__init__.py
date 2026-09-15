"""
CyberSentinel Threat Detectors Package.
Unified interface for all 6 detection engines.
"""

from backend.app.detectors.ddos.dos_detector import detect as detect_ddos
from backend.app.detectors.beaconing.c2_detector import detect as detect_c2
from backend.app.detectors.dga_dns.dns_detector import detect as detect_dns
from backend.app.detectors.encrypted_malware.encrypted_detector import detect as detect_encrypted
from backend.app.detectors.reconnaissance.recon_detector import detect as detect_recon
from backend.app.detectors.exfiltration.exfil_detector import detect as detect_exfil
from backend.app.detectors.base import normalize_detector_result

DETECTOR_REGISTRY = {
    "DDoS": detect_ddos,
    "C2": detect_c2,
    "DNS": detect_dns,
    "ENCRYPTED_TRAFFIC": detect_encrypted,
    "RECON": detect_recon,
    "EXFILTRATION": detect_exfil,
}

__all__ = [
    "detect_ddos",
    "detect_c2",
    "detect_dns",
    "detect_encrypted",
    "detect_recon",
    "detect_exfil",
    "normalize_detector_result",
    "DETECTOR_REGISTRY",
]
