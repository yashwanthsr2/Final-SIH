"""
CyberSentinel State Definitions, Transition Matrix & Mitigation Playbooks.
Aligned with MITRE ATT&CK kill chain.
"""

from __future__ import annotations
from typing import Dict, List

STATES = [
    "NORMAL",
    "RECON",
    "SCANNING",
    "C2",
    "SUSPICIOUS_ACTIVITY",
    "DATA_COLLECTION",
    "EXFILTRATION",
    "DISRUPTION",
]

THREAT_TO_STATE: Dict[str, str] = {
    "RECON": "RECON",
    "DDoS": "DISRUPTION",
    "C2": "C2",
    "DNS": "C2",
    "ENCRYPTED_TRAFFIC": "SUSPICIOUS_ACTIVITY",
    "EXFILTRATION": "EXFILTRATION",
}

TRANSITIONS: Dict[str, Dict[str, float]] = {
    "NORMAL": {
        "NORMAL": 0.70, "RECON": 0.15, "SUSPICIOUS_ACTIVITY": 0.10,
        "SCANNING": 0.03, "C2": 0.01, "DATA_COLLECTION": 0.005,
        "EXFILTRATION": 0.004, "DISRUPTION": 0.001,
    },
    "RECON": {
        "NORMAL": 0.10, "RECON": 0.30, "SCANNING": 0.35,
        "C2": 0.10, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.03,
        "EXFILTRATION": 0.02, "DISRUPTION": 0.01,
    },
    "SCANNING": {
        "NORMAL": 0.05, "RECON": 0.10, "SCANNING": 0.25,
        "C2": 0.30, "SUSPICIOUS_ACTIVITY": 0.15, "DATA_COLLECTION": 0.10,
        "EXFILTRATION": 0.04, "DISRUPTION": 0.01,
    },
    "C2": {
        "NORMAL": 0.03, "RECON": 0.05, "SCANNING": 0.05,
        "C2": 0.35, "SUSPICIOUS_ACTIVITY": 0.15, "DATA_COLLECTION": 0.25,
        "EXFILTRATION": 0.10, "DISRUPTION": 0.02,
    },
    "SUSPICIOUS_ACTIVITY": {
        "NORMAL": 0.10, "RECON": 0.10, "SCANNING": 0.10,
        "C2": 0.20, "SUSPICIOUS_ACTIVITY": 0.25, "DATA_COLLECTION": 0.15,
        "EXFILTRATION": 0.08, "DISRUPTION": 0.02,
    },
    "DATA_COLLECTION": {
        "NORMAL": 0.02, "RECON": 0.03, "SCANNING": 0.03,
        "C2": 0.20, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.20,
        "EXFILTRATION": 0.40, "DISRUPTION": 0.02,
    },
    "EXFILTRATION": {
        "NORMAL": 0.05, "RECON": 0.02, "SCANNING": 0.02,
        "C2": 0.20, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.10,
        "EXFILTRATION": 0.45, "DISRUPTION": 0.06,
    },
    "DISRUPTION": {
        "NORMAL": 0.15, "RECON": 0.05, "SCANNING": 0.05,
        "C2": 0.15, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.05,
        "EXFILTRATION": 0.05, "DISRUPTION": 0.40,
    },
}

MITRE_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "RECON": {
        "mitre_id": "T1595",
        "name": "Active Scanning",
        "action": "Isolate source host; review perimeter firewall ACLs; verify no unauthorized port mapping.",
        "techniques": ["T1595.001", "T1595.002"],
    },
    "SCANNING": {
        "mitre_id": "T1046",
        "name": "Network Service Discovery",
        "action": "Enable rate limiting on targeted ports; alert SOC; correlate with internal host logs.",
        "techniques": ["T1046"],
    },
    "C2": {
        "mitre_id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "action": "Block C2 destination IP/domain on DNS resolver; isolate host from internal subnets.",
        "techniques": ["T1071.001", "T1071.004", "T1568.002"],
    },
    "SUSPICIOUS_ACTIVITY": {
        "mitre_id": "T1036",
        "name": "Masquerading / Anomaly",
        "action": "Increase telemetry sampling rate; monitor outbound byte ratios; inspect TLS SNI headers.",
        "techniques": ["T1036"],
    },
    "DATA_COLLECTION": {
        "mitre_id": "T1005",
        "name": "Data from Local System",
        "action": "Restrict outbound data transfer quotas; alert compliance officer; preserve memory artifacts.",
        "techniques": ["T1005", "T1074"],
    },
    "EXFILTRATION": {
        "mitre_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "action": "Immediately sever external connection; review data loss prevention (DLP) alerts; initiate incident response.",
        "techniques": ["T1048.003", "T1041"],
    },
    "DISRUPTION": {
        "mitre_id": "T1498",
        "name": "Network Denial of Service",
        "action": "Activate BGP blackholing / upstream scrubber; engage DDoS mitigation provider; preserve PCAP sample.",
        "techniques": ["T1498.001", "T1499"],
    },
    "NORMAL": {
        "mitre_id": "N/A",
        "name": "Normal Traffic",
        "action": "No mitigation required. Baseline passive monitoring active.",
        "techniques": [],
    },
}
