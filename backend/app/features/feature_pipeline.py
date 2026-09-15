"""
CyberSentinel Canonical Feature Pipeline.
Transforms collections of NormalizedFlow instances into standardized feature
dictionaries compatible with all six CyberSentinel threat detectors:
  1. DDoS (dos_hgb)
  2. C2 Beaconing (c2_hgb)
  3. DGA / DNS Tunneling (dns_hgb)
  4. Encrypted Malware (encrypted_hgb)
  5. Reconnaissance (Port Scanning / Sweep)
  6. Data Exfiltration

Used identically across:
  - Offline Datasets (Parquet/CSV batch processing)
  - CSV / Flow Replay (Scenario replayer)
  - PCAP Replay (Offline packet streams)
  - Live Wi-Fi Telemetry (Passive network sensor)
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

import pandas as pd

from backend.app.features.dns_features import DNS_FEATURES, route_dns
from backend.app.features.tls_features import ENCRYPTED_FEATURES, route_encrypted
from backend.app.schemas.flow import NormalizedFlow


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        val = float(value)
        return val if math.isfinite(val) else default
    except (TypeError, ValueError):
        return default


def _safe_div(a: float, b: float) -> float:
    try:
        fa, fb = float(a), float(b)
        if not math.isfinite(fa) or not math.isfinite(fb) or fb == 0.0:
            return 0.0
        res = fa / fb
        return res if math.isfinite(res) else 0.0
    except (ZeroDivisionError, ValueError, TypeError):
        return 0.0


def _dominant_source(flows: List[NormalizedFlow]) -> Optional[str]:
    if not flows:
        return None
    counts: Dict[str, int] = defaultdict(int)
    for f in flows:
        counts[f.source_ip] += max(1, f.total_packets)
    return max(counts, key=counts.get) if counts else None


def _base_stats(flows: List[NormalizedFlow]) -> Dict[str, float]:
    if not flows:
        return {}
    packets = [float(f.total_packets) for f in flows]
    bytes_ = [float(f.total_bytes) for f in flows]
    duration = [float(f.duration) for f in flows]
    
    first_ts = min((f.first_ts or f.timestamp) for f in flows)
    last_ts = max((f.last_ts or f.timestamp) for f in flows)
    elapsed = max(0.001, last_ts - first_ts)
    
    iats = []
    timestamps = sorted((f.first_ts or f.timestamp) for f in flows)
    for a, b in zip(timestamps, timestamps[1:]):
        iats.append(max(0.0, b - a))
    mean_iat = sum(iats) / len(iats) if iats else 0.0
    mean_d = sum(duration) / len(duration) if duration else 0.0
    
    return {
        "flow_count": float(len(flows)),
        "total_packets": float(sum(packets)),
        "total_bytes": float(sum(bytes_)),
        "mean_flow_duration": mean_d,
        "median_flow_duration": float(pd.Series(duration).median()) if duration else 0.0,
        "mean_packets_per_second": _safe_div(sum(packets), elapsed),
        "max_packets_per_second": max((_safe_div(p, max(d, 0.001)) for p, d in zip(packets, duration)), default=0.0),
        "mean_bytes_per_second": _safe_div(sum(bytes_), elapsed),
        "max_bytes_per_second": max((_safe_div(b, max(d, 0.001)) for b, d in zip(bytes_, duration)), default=0.0),
        "mean_packet_size": _safe_div(sum(bytes_), sum(packets)),
        "mean_iat": mean_iat,
        "mean_syn_count": _safe_div(sum(f.syn for f in flows), len(flows)),
        "mean_ack_count": _safe_div(sum(f.ack for f in flows), len(flows)),
        "mean_rst_count": _safe_div(sum(f.rst for f in flows), len(flows)),
    }


def _with_lags_roll3(
    current: Dict[str, float],
    history: Deque[Dict[str, float]],
    bases: List[str],
) -> Dict[str, float]:
    out = dict(current)
    previous = list(history)[-3:][::-1]
    for col in bases:
        out[f"{col}_lag1"] = previous[0].get(col, 0.0) if previous else 0.0
        out[f"{col}_lag2"] = previous[1].get(col, 0.0) if len(previous) > 1 else 0.0
        out[f"{col}_lag3"] = previous[2].get(col, 0.0) if len(previous) > 2 else 0.0
        vals = [x.get(col, 0.0) for x in list(history)[-3:]]
        out[f"{col}_rolling3"] = sum(vals) / len(vals) if vals else 0.0
    return out


def build_ddos_features(
    flows: List[NormalizedFlow],
    history: Optional[Deque[Dict[str, float]]] = None,
) -> Dict[str, float]:
    base = _base_stats(flows)
    cols = [
        "flow_count", "total_packets", "total_bytes",
        "mean_packets_per_second",
        "max_packets_per_second", "mean_bytes_per_second",
        "max_bytes_per_second", "mean_packet_size", "mean_iat",
        "mean_syn_count", "mean_ack_count", "mean_rst_count",
    ]
    hist = history if history is not None else deque(maxlen=8)
    feat = _with_lags_roll3(base, hist, cols)
    if history is not None:
        history.append(base)
    return feat


def build_c2_features(
    flows: List[NormalizedFlow],
    history: Optional[Deque[Dict[str, float]]] = None,
) -> Dict[str, float]:
    if not flows:
        return {"flow_count": 0.0}

    pair_counts: Dict[Tuple[str, int], int] = defaultdict(int)
    dst_counts: Dict[str, int] = defaultdict(int)
    for f in flows:
        pair_counts[(f.destination_ip, f.destination_port)] += 1
        dst_counts[f.destination_ip] += 1

    pair_iats: List[float] = []
    ordered = sorted(flows, key=lambda x: (x.first_ts or x.timestamp))
    last_by_pair: Dict[Tuple[str, int, str], float] = {}
    for f in ordered:
        f_ts = f.first_ts or f.timestamp
        key = (f.destination_ip, f.destination_port, f.protocol)
        if key in last_by_pair:
            pair_iats.append(max(0.0, f_ts - last_by_pair[key]))
        last_by_pair[key] = f_ts

    def mean(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else 0.0

    def std(vals: List[float]) -> float:
        if len(vals) < 2:
            return 0.0
        m = mean(vals)
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))

    flow_count = float(len(flows))
    total_packets = float(sum(f.total_packets for f in flows))
    total_bytes = float(sum(f.total_bytes for f in flows))
    iat_mean = mean(pair_iats)
    iat_std = std(pair_iats)
    iat_cv = _safe_div(iat_std, iat_mean)
    max_pair = float(max(pair_counts.values(), default=0))
    max_dst = float(max(dst_counts.values(), default=0))
    entropy = 0.0
    if dst_counts:
        for n in dst_counts.values():
            p = n / flow_count
            entropy -= p * math.log2(p) if p > 0 else 0.0

    current = {
        "flow_count": flow_count,
        "unique_destinations": float(len(dst_counts)),
        "unique_ports": float(len({f.destination_port for f in flows})),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "mean_packets": _safe_div(total_packets, flow_count),
        "mean_bytes": _safe_div(total_bytes, flow_count),
        "mean_duration": mean([f.duration for f in flows]),
        "max_destination_count": max_dst,
        "destination_concentration": _safe_div(max_dst, flow_count),
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_median": float(pd.Series(pair_iats).median()) if pair_iats else 0.0,
        "iat_min": min(pair_iats, default=0.0),
        "iat_max": max(pair_iats, default=0.0),
        "iat_cv": iat_cv,
        "max_pair_repetition": max_pair,
        "pair_repetition_ratio": _safe_div(max_pair, flow_count),
        "destination_entropy": entropy,
    }

    hist = list(history) if history else []
    for col in [
        "flow_count", "unique_destinations", "unique_ports", "total_packets",
        "total_bytes", "destination_concentration", "iat_mean", "iat_cv",
        "max_pair_repetition", "pair_repetition_ratio"
    ]:
        for n, min_count in [(6, 2), (12, 3), (24, 5)]:
            vals = [x.get(col, 0.0) for x in hist[-n:] if x]
            current[f"{col}_rolling{n}"] = mean(vals) if len(vals) >= min_count else 0.0

    current["flow_rate_change"] = _safe_div(
        current["flow_count"], current.get("flow_count_rolling12", 0.0) + 1e-6
    )
    current["byte_rate_change"] = _safe_div(
        current["total_bytes"], current.get("total_bytes_rolling12", 0.0) + 1e-6
    )
    current["packet_rate_change"] = _safe_div(
        current["total_packets"], current.get("total_packets_rolling12", 0.0) + 1e-6
    )
    pair_values = list(pair_counts.values())
    current["max_pair_seen"] = max_pair
    current["mean_pair_seen"] = mean(pair_values)
    current["max_recent_contacts_60s"] = float(len({(f.destination_ip, f.destination_port) for f in flows}))
    current["mean_recent_contacts_60s"] = mean([1.0 for _ in flows])
    current["max_recent_contacts_300s"] = current["max_recent_contacts_60s"]
    current["mean_recent_contacts_300s"] = current["mean_recent_contacts_60s"]
    current["median_pair_iat"] = current["iat_median"]
    current["mean_pair_iat"] = current["iat_mean"]
    current["std_pair_iat"] = current["iat_std"]
    current["pair_iat_cv"] = current["iat_cv"]

    if history is not None:
        history.append(current.copy())
    return current


def build_dns_features(
    flows: List[NormalizedFlow],
    window_seconds: float = 5.0,
    history: Optional[Deque[Dict[str, float]]] = None,
) -> Optional[Dict[str, float]]:
    def mean(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else 0.0

    def std(vals: List[float]) -> float:
        if len(vals) < 2:
            return 0.0
        m = mean(vals)
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))

    dns = [
        f for f in flows
        if f.destination_port in (53, 853)
        or f.source_port in (53, 853)
        or (f.dns_query is not None and len(f.dns_query) > 0)
        or f.service == "dns"
    ]
    if not dns or len(dns) < 3:
        return None

    source = defaultdict(list)
    for f in dns:
        source[f.source_ip].append(f)
    dominant = max(source.values(), key=len) if source else dns
    packet_total = sum(f.total_packets for f in dominant)
    byte_total = sum(f.total_bytes for f in dominant)
    query_rate = _safe_div(len(dominant), max(window_seconds, 1.0))
    
    dest_counts = defaultdict(int)
    dest_bytes = defaultdict(int)
    for f in dominant:
        dest_counts[f.destination_ip] += f.total_packets
        dest_bytes[f.destination_ip] += f.total_bytes
        
    packet_conc = _safe_div(max(dest_counts.values(), default=0), packet_total)
    byte_conc = _safe_div(max(dest_bytes.values(), default=0), byte_total)
    
    dom_sorted = sorted(dominant, key=lambda x: (x.first_ts or x.timestamp))
    timing = [max(0.0, (b.first_ts or b.timestamp) - (a.first_ts or a.timestamp)) for a, b in zip(dom_sorted, dom_sorted[1:])]
    mean_time = sum(timing) / len(timing) if timing else 0.0
    cv = _safe_div(
        math.sqrt(sum((x - mean_time) ** 2 for x in timing) / (len(timing) - 1)) if len(timing) > 1 else 0.0,
        mean_time
    )

    hist = list(history) if history else []
    prior = hist[-1].get("dns_query_rate", query_rate) if hist else query_rate
    roll3 = mean([x.get("dns_query_rate", 0.0) for x in hist[-3:]]) if hist else query_rate
    roll6 = mean([x.get("dns_query_rate", 0.0) for x in hist[-6:]]) if hist else query_rate
    std6 = std([x.get("dns_query_rate", 0.0) for x in hist[-6:]]) if hist else 0.0
    
    std_timing = math.sqrt(sum((x - mean_time) ** 2 for x in timing) / (len(timing) - 1)) if len(timing) > 1 else 0.0
    med_timing = float(pd.Series(timing).median()) if timing else 0.0

    current = {
        "dns_query_count": float(len(dominant)),
        "dns_total_packets": float(packet_total),
        "dns_total_bytes": float(byte_total),
        "dns_unique_destinations": float(len(dest_counts)),
        "dns_query_rate": query_rate,
        "dns_max_destination_count": float(max(dest_counts.values(), default=0)),
        "dns_packet_concentration": packet_conc,
        "dns_max_destination_bytes": float(max(dest_bytes.values(), default=0)),
        "dns_byte_concentration": byte_conc,
        "dns_iat_mean": mean_time,
        "dns_iat_std": std_timing,
        "dns_iat_median": med_timing,
        "dns_iat_cv": cv,
        "query_rate_prev": prior,
        "query_rate_roll3": roll3,
        "query_rate_roll6": roll6,
        "query_rate_std6": std6,
        "query_rate_change": query_rate - prior,
        "query_rate_z6": _safe_div(query_rate - roll6, std6 or 1.0),
        "destination_change": abs(float(len(dest_counts)) - (hist[-1].get("dns_unique_destinations", len(dest_counts)) if hist else len(dest_counts))),
        "bytes_per_query": _safe_div(byte_total, len(dominant)),
        "packets_per_query": _safe_div(packet_total, len(dominant)),
    }
    if history is not None:
        history.append(current.copy())
    return current


def build_encrypted_features(
    flows: List[NormalizedFlow],
    history: Optional[Deque[Dict[str, float]]] = None,
) -> Optional[Dict[str, float]]:
    def mean(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else 0.0

    encrypted = [
        f for f in flows
        if f.destination_port in (443, 8443, 853)
        or f.source_port in (443, 8443, 853)
        or f.tls_sni is not None
        or f.service in ("ssl", "tls", "https")
    ]
    if not encrypted:
        return None

    count = len(encrypted)
    packets = sum(f.total_packets for f in encrypted)
    bytes_ = sum(f.total_bytes for f in encrypted)
    hist = list(history) if history else []
    
    current = {
        "encrypted_flow_count": float(count),
        "encrypted_total_packets": float(packets),
        "encrypted_total_bytes": float(bytes_),
        "encrypted_unique_destinations": float(len({f.destination_ip for f in encrypted})),
        "encrypted_unique_ports": float(len({f.destination_port for f in encrypted})),
        "encrypted_mean_duration": mean([f.duration for f in encrypted]),
        "bytes_per_flow": _safe_div(bytes_, count),
        "packets_per_flow": _safe_div(packets, count),
        "flow_count_prev": float(hist[-1].get("encrypted_flow_count", count) if hist else count),
        "flow_count_change": float(count - (hist[-1].get("encrypted_flow_count", count) if hist else count)),
        "bytes_prev": float(hist[-1].get("encrypted_total_bytes", bytes_) if hist else bytes_),
        "bytes_change": float(bytes_ - (hist[-1].get("encrypted_total_bytes", bytes_) if hist else bytes_)),
        "destination_change": float(len({f.destination_ip for f in encrypted}) - (hist[-1].get("encrypted_unique_destinations", len({f.destination_ip for f in encrypted})) if hist else len({f.destination_ip for f in encrypted}))),
    }
    if history is not None:
        history.append(current.copy())
    return current


def extract_features_from_flows(
    flows: List[NormalizedFlow],
    window_seconds: float = 5.0,
    history_queues: Optional[Dict[str, Deque]] = None,
    bytes_in: Optional[int] = None,
    bytes_out: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Canonical extractor that maps any collection of NormalizedFlow objects
    into the exact input payload for the 6 CyberSentinel detectors.
    """
    if not flows:
        return {}

    queues = history_queues or {}
    h_ddos = queues.get("ddos")
    h_c2 = queues.get("c2")
    h_dns = queues.get("dns")
    h_encrypted = queues.get("encrypted")

    ts_sample = flows[0].timestamp if flows else time.time()
    window_time = datetime.fromtimestamp(
        ts_sample, timezone.utc
    ).replace(microsecond=0).isoformat()

    source = _dominant_source(flows) or "0.0.0.0"

    dst_counts: Dict[str, int] = defaultdict(int)
    proto_counts: Dict[str, int] = defaultdict(int)
    for f in flows:
        dst_counts[f.destination_ip] += max(1, f.total_packets)
        proto_counts[f.protocol] += max(1, f.total_packets)
    destination = max(dst_counts, key=dst_counts.get) if dst_counts else "0.0.0.0"
    protocol = max(proto_counts, key=proto_counts.get) if proto_counts else "TCP"
    flow_id = flows[0].flow_id if flows else f"flow_{source}_{destination}_{int(ts_sample)}"

    payload: Dict[str, Any] = {
        "flow_id": flow_id,
        "timestamp": ts_sample,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "time_window": window_time,
        "ddos_features": build_ddos_features(flows, history=h_ddos),
        "c2_features": build_c2_features(flows, history=h_c2),
    }

    dns_feats = build_dns_features(flows, window_seconds=window_seconds, history=h_dns)
    if dns_feats is not None:
        payload["dns_features"] = dns_feats

    enc_feats = build_encrypted_features(flows, history=h_encrypted)
    if enc_feats is not None:
        payload["encrypted_features"] = enc_feats

    # Reconnaissance: Port scanning / sweep
    non_web_ports = len({f.destination_port for f in flows if f.destination_port not in (80, 443, 853, 53)})
    unique_ports = len({f.destination_port for f in flows})
    unique_dests = len({f.destination_ip for f in flows})
    total_syn = sum(f.syn for f in flows)
    total_pkts = sum(f.total_packets for f in flows)
    syn_ratio = total_syn / max(1, total_pkts)

    if non_web_ports >= 15 or (unique_dests >= 15 and non_web_ports >= 5 and syn_ratio > 0.4):
        payload["recon_features"] = {
            "unique_dst_ports": non_web_ports,
            "unique_destinations": unique_dests,
            "flow_count": len(flows),
            "window_seconds": float(window_seconds),
            "total_bytes": sum(f.total_bytes for f in flows),
            "mean_syn_count": round(syn_ratio, 2),
            "total_packets": total_pkts,
        }

    # Data Exfiltration: Large outbound volume & high asymmetry
    b_sent = bytes_out if bytes_out is not None else sum(f.orig_bytes for f in flows)
    b_recv = bytes_in if bytes_in is not None else sum(f.resp_bytes for f in flows)
    if b_sent >= 2_000_000 and b_sent > (b_recv * 2):
        payload["exfil_features"] = {
            "bytes_out": b_sent,
            "bytes_in": max(100, b_recv),
            "unique_destinations": unique_dests,
            "flow_count": len(flows),
            "mean_flow_duration": sum(f.duration for f in flows) / max(1, len(flows)),
            "window_seconds": float(window_seconds),
        }

    return payload


# --- Metadata & Helper utilities for pandas dataframes ---
def get_available_features(df: pd.DataFrame, required: List[str]) -> List[str]:
    return [f for f in required if f in df.columns]


def has_features(df: pd.DataFrame, required: List[str]) -> bool:
    return all(f in df.columns for f in required)


def describe_features(df: pd.DataFrame) -> Dict[str, List[str]]:
    return {
        "DNS": get_available_features(df, DNS_FEATURES),
        "ENCRYPTED_TRAFFIC": get_available_features(df, ENCRYPTED_FEATURES),
    }
