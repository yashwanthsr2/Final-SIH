"""
CyberSentinel Flow Schemas.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


@dataclass
class NormalizedFlow:
    """Canonical vendor-neutral normalized flow representation."""
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
    conn_state: Optional[str] = None
    history: Optional[str] = None
    service: Optional[str] = None

    # Directionality
    direction: str = "outbound"

    # DNS metadata
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_answers: List[str] = field(default_factory=list)

    # TLS metadata
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None

    # Timing & duration bounds
    first_ts: float = 0.0
    last_ts: float = 0.0
    mean_iat: float = 0.0

    # TCP flags
    syn: int = 0
    ack: int = 0
    rst: int = 0

    @property
    def src(self) -> str:
        return self.source_ip

    @property
    def dst(self) -> str:
        return self.destination_ip

    @property
    def sport(self) -> int:
        return self.source_port

    @property
    def dport(self) -> int:
        return self.destination_port

    @property
    def proto(self) -> str:
        return self.protocol

    @property
    def bytes(self) -> int:
        return self.total_bytes

    @property
    def packets(self) -> int:
        return self.total_packets

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_zeek_conn(cls, row: Dict[str, Any]) -> "NormalizedFlow":
        import uuid
        uid = str(row.get("uid") or uuid.uuid4())
        orig_bytes = _safe_int(row.get("orig_bytes") or row.get("orig_ip_bytes") or 0)
        resp_bytes = _safe_int(row.get("resp_bytes") or row.get("resp_ip_bytes") or 0)
        orig_pkts = _safe_int(row.get("orig_pkts") or 0)
        resp_pkts = _safe_int(row.get("resp_pkts") or 0)
        ts = _safe_float(row.get("ts") or time.time())
        dur = _safe_float(row.get("duration") or row.get("duration_zeek") or 0.0)
        hist = str(row.get("history", "")) if row.get("history") else ""
        
        return cls(
            flow_id=uid,
            timestamp=ts,
            first_ts=ts,
            last_ts=ts + dur,
            source_ip=str(row.get("id.orig_h") or row.get("src_ip_zeek") or "0.0.0.0"),
            destination_ip=str(row.get("id.resp_h") or row.get("dest_ip_zeek") or "0.0.0.0"),
            source_port=_safe_int(row.get("id.orig_p") or row.get("src_port_zeek") or 0),
            destination_port=_safe_int(row.get("id.resp_p") or row.get("dest_port_zeek") or 0),
            protocol=str(row.get("proto") or row.get("proto_zeek") or "TCP").upper(),
            duration=dur,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            total_bytes=orig_bytes + resp_bytes,
            orig_pkts=orig_pkts,
            resp_pkts=resp_pkts,
            total_packets=orig_pkts + resp_pkts,
            conn_state=str(row.get("conn_state", "")) if row.get("conn_state") else None,
            history=hist if hist else None,
            service=str(row.get("service", "")) if row.get("service") else None,
            syn=int("S" in hist or "s" in hist),
            ack=int("A" in hist or "a" in hist),
            rst=int("R" in hist or "r" in hist),
        )


import math

def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "" or v == "-":
            return default
        val = float(v)
        if not math.isfinite(val):
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "" or v == "-":
            return default
        val = float(v)
        return val if math.isfinite(val) else default
    except (ValueError, TypeError):
        return default


class FlowEvent(BaseModel):
    id: Optional[str] = None
    timestamp: float
    source: str
    destination: str
    protocol: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    bytes_out: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    packets_in: int = 0
    duration: float = 0.0
    threat_flag: int = 0
    threat_class: Optional[str] = None
