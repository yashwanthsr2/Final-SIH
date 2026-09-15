"""
CyberSentinel Feature Contribution Analyzer.
Ranks and interprets contributing features for alert explainability.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

FEATURE_HUMAN_LABELS = {
    "orig_bytes": "Outbound Byte Volume",
    "resp_bytes": "Inbound Byte Volume",
    "duration": "Flow Duration",
    "mean_iat": "Mean Inter-Arrival Time",
    "dns_query_rate": "DNS Query Frequency",
    "dns_packet_concentration": "DNS Packet Concentration",
    "encrypted_flow_count": "Encrypted Connection Count",
    "unique_dst_ports": "Distinct Destination Ports Targeted",
    "mean_syn_count": "Unacknowledged TCP SYN Ratio",
    "byte_ratio": "Upload-to-Download Asymmetry Ratio",
    "total_packets": "Total Packet Volume",
    "total_bytes": "Total Transferred Byte Volume",
    "max_bytes_per_second": "Peak Bandwidth Consumption (Bytes/s)",
    "mean_bytes_per_second": "Average Bandwidth Consumption (Bytes/s)",
    "mean_iat_lag1": "Prior Window Mean Packet Inter-Arrival Time",
    "mean_packet_size_rolling3": "Rolling Packet Size Distribution (3-Window)",
    "flow_count": "Concurrent Flow Aggregation Count",
    "mean_ack_count": "TCP ACK Packet Volume",
    "mean_fin_count": "TCP FIN Teardown Volume",
    "mean_rst_count": "TCP RST Abort Volume",
    "destination_concentration": "Target IP Concentration Ratio",
    "communication_periodicity": "Beaconing Periodicity Regularity",
    "entropy": "Payload Byte Entropy",
    "sni_entropy": "TLS SNI Randomness Entropy",
}

def format_evidence_item(feature_name: str, value: Any, importance: float = 0.0, direction: Optional[str] = None) -> Dict[str, Any]:
    human_label = FEATURE_HUMAN_LABELS.get(feature_name, feature_name.replace("_", " ").title())
    if direction is None:
        direction = "increases_risk" if importance > 0 else "decreases_risk"
    return {
        "feature": feature_name,
        "value": value,
        "feature_value": value,
        "contribution": round(importance, 4),
        "importance": round(abs(importance), 4),
        "direction": direction,
        "human_label": human_label,
    }
