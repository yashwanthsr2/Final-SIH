"""
CyberSentinel Normalized Flow Schema.

Vendor-neutral, structured representation of observed network flows.
Can be instantiated from:
- Zeek conn/dns/ssl log events
- Scapy packet streams
- Live socket connection telemetry

Strictly passive: contains only metadata; zero decrypted payloads or private content.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedFlow:
    flow_id: str
    timestamp: float = field(default_factory=time.time)
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    duration: float = 0.0

    # Volume metrics
    orig_bytes: int = 0
    resp_bytes: int = 0
    total_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    total_packets: int = 0

    # Connection state & history
    conn_state: Optional[str] = None  # e.g. S0, SF, REJ, RSTO (Zeek standard)
    history: Optional[str] = None     # e.g. ShADdFfa (TCP flags sequence)
    service: Optional[str] = None     # e.g. dns, ssl, http

    # Directionality
    direction: str = "outbound"       # outbound, inbound, internal

    # DNS metadata (if observed on port 53/853 or from dns.log)
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_answers: List[str] = field(default_factory=list)

    # TLS metadata (if observed from ssl.log / SNI handshake)
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None

    # Timing / inter-arrival
    mean_iat: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_zeek_conn(cls, row: Dict[str, Any]) -> NormalizedFlow:
        """Construct NormalizedFlow from a Zeek conn.log record."""
        orig_b = _safe_int(row.get("orig_bytes") or row.get("orig_ip_bytes", 0))
        resp_b = _safe_int(row.get("resp_bytes") or row.get("resp_ip_bytes", 0))
        orig_p = _safe_int(row.get("orig_pkts", 0))
        resp_p = _safe_int(row.get("resp_pkts", 0))
        duration = _safe_float(row.get("duration", 0.0))

        flow_id = str(row.get("uid") or row.get("community_id") or f"{row.get('src_ip_zeek')}:{row.get('dest_ip_zeek')}:{time.time()}")
        ts = _safe_float(row.get("ts", time.time()))

        return cls(
            flow_id=flow_id,
            timestamp=ts,
            source_ip=str(row.get("src_ip_zeek") or row.get("id.orig_h") or "0.0.0.0"),
            destination_ip=str(row.get("dest_ip_zeek") or row.get("id.resp_h") or "0.0.0.0"),
            source_port=_safe_int(row.get("src_port_zeek") or row.get("id.orig_p", 0)),
            destination_port=_safe_int(row.get("dest_port_zeek") or row.get("id.resp_p", 0)),
            protocol=str(row.get("proto", "TCP")).upper(),
            duration=duration,
            orig_bytes=orig_b,
            resp_bytes=resp_b,
            total_bytes=orig_b + resp_b,
            orig_pkts=orig_p,
            resp_pkts=resp_p,
            total_packets=orig_p + resp_p,
            conn_state=str(row.get("conn_state", "")) if row.get("conn_state") else None,
            history=str(row.get("history", "")) if row.get("history") else None,
            service=str(row.get("service", "")) if row.get("service") else None,
            direction=_infer_direction(str(row.get("src_ip_zeek") or ""), str(row.get("dest_ip_zeek") or "")),
        )


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "" or v == "-":
            return default
        return int(float(v))
    except (ValueError, TypeError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "" or v == "-":
            return default
        return float(v)
    except (ValueError, TypeError):
        return default


def _infer_direction(src: str, dst: str) -> str:
    def is_private(ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.20.")
            or ip.startswith("172.21.")
            or ip.startswith("172.22.")
            or ip.startswith("172.23.")
            or ip.startswith("172.24.")
            or ip.startswith("172.25.")
            or ip.startswith("172.26.")
            or ip.startswith("172.27.")
            or ip.startswith("172.28.")
            or ip.startswith("172.29.")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
            or ip.startswith("127.")
        )
    src_priv = is_private(src)
    dst_priv = is_private(dst)
    if src_priv and dst_priv:
        return "internal"
    if src_priv and not dst_priv:
        return "outbound"
    return "inbound"
