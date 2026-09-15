"""
CyberSentinel Offline PCAP Ingestion & Replay Engine.
Reads PCAP files offline without packet injection or transmission,
normalizes packets into canonical NormalizedFlow representations,
and routes through the canonical 10-stage detection pipeline:
NORMALIZED FLOW -> FEATURE PIPELINE -> DETECTORS -> ML -> CORRELATION -> RISK -> EXPLAINABILITY -> THREAT STATE -> TRAJECTORY -> ALERT.
"""

from __future__ import annotations

import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.app.features.feature_pipeline import extract_features_from_flows
from backend.app.ingestion.base import BaseIngestor
from backend.app.schemas.flow import NormalizedFlow


class PCAPIngestor(BaseIngestor):

    """
    Passive offline PCAP file reader that yields NormalizedFlow instances.
    """

    def __init__(self, callback: Callable[[NormalizedFlow], None]):
        super().__init__(callback)

    def start(self, pcap_path: Path) -> bool:
        self.is_running = True
        try:
            from scapy.all import IP, TCP, UDP, rdpcap
            packets = rdpcap(str(pcap_path))
            for pkt in packets:
                if not self.is_running:
                    break
                if IP in pkt:
                    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
                    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                    pkt_len = len(pkt)
                    ts = float(getattr(pkt, "time", time.time()))

                    flags = str(getattr(pkt[TCP], "flags", "")) if TCP in pkt else ""
                    syn = int("S" in flags and "A" not in flags)
                    ack = int("A" in flags)
                    rst = int("R" in flags)

                    flow = NormalizedFlow(
                        flow_id=f"pcap_{ts}_{pkt[IP].src}_{sport}",
                        timestamp=ts,
                        first_ts=ts,
                        last_ts=ts,
                        source_ip=pkt[IP].src,
                        destination_ip=pkt[IP].dst,
                        source_port=sport,
                        destination_port=dport,
                        protocol=proto,
                        orig_bytes=pkt_len,
                        resp_bytes=0,
                        total_bytes=pkt_len,
                        orig_pkts=1,
                        resp_pkts=0,
                        total_packets=1,
                        syn=syn,
                        ack=ack,
                        rst=rst,
                    )
                    self.callback(flow)
            return True
        except Exception as e:
            self.is_running = False
            return False

    def stop(self) -> None:
        self.is_running = False


def replay_pcap_to_alerts(
    pcap_path: Path,
    window_seconds: float = 5.0,
    analyze_fn: Optional[Callable] = None,
) -> List[Dict[str, Any]]:
    """
    Canonical PCAP Replay Pipeline:
    Ingests PCAP -> Groups packets into NormalizedFlow windows
    -> Passes to Canonical Feature Pipeline
    -> Evaluates Detectors & ML
    -> Evaluates Correlation, Risk, Explainability, Threat State, Trajectory
    -> Returns canonical Alert objects.
    """
    from scapy.all import IP, TCP, UDP, rdpcap

    if analyze_fn is None:
        from backend.app.schemas.threat import DetectionRequest
        from backend.app.services.alert_service import analyze_request
        analyze_fn = analyze_request
    else:
        from backend.app.schemas.threat import DetectionRequest

    if not Path(pcap_path).exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    if not packets:
        return []

    # Group packets into time windows
    windows: Dict[int, Dict[Tuple[str, str, int, int, str], NormalizedFlow]] = defaultdict(dict)
    first_pkt_time = None

    for pkt in packets:
        if IP not in pkt:
            continue
        pkt_time = float(getattr(pkt, "time", time.time()))
        if first_pkt_time is None:
            first_pkt_time = pkt_time

        win_idx = int((pkt_time - first_pkt_time) // window_seconds)

        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        pkt_len = len(pkt)

        flags = str(getattr(pkt[TCP], "flags", "")) if TCP in pkt else ""
        syn = int("S" in flags and "A" not in flags)
        ack = int("A" in flags)
        rst = int("R" in flags)

        key = (pkt[IP].src, pkt[IP].dst, sport, dport, proto)
        if key not in windows[win_idx]:
            windows[win_idx][key] = NormalizedFlow(
                flow_id=f"pcap_{win_idx}_{pkt[IP].src}_{sport}",
                timestamp=pkt_time,
                first_ts=pkt_time,
                last_ts=pkt_time,
                source_ip=pkt[IP].src,
                destination_ip=pkt[IP].dst,
                source_port=sport,
                destination_port=dport,
                protocol=proto,
                orig_bytes=pkt_len,
                total_bytes=pkt_len,
                orig_pkts=1,
                total_packets=1,
                syn=syn,
                ack=ack,
                rst=rst,
            )
        else:
            fl = windows[win_idx][key]
            fl.last_ts = max(fl.last_ts, pkt_time)
            fl.duration = max(0.0, fl.last_ts - fl.first_ts)
            fl.total_bytes += pkt_len
            fl.orig_bytes += pkt_len
            fl.total_packets += 1
            fl.orig_pkts += 1
            fl.syn += syn
            fl.ack += ack
            fl.rst += rst

    alerts: List[Dict[str, Any]] = []

    # Process each window through the canonical pipeline
    for win_idx in sorted(windows.keys()):
        flows = list(windows[win_idx].values())
        if not flows:
            continue

        # 1. Normalized Flows -> 2. Feature Pipeline
        payload = extract_features_from_flows(flows=flows, window_seconds=window_seconds)

        # 3. Detectors -> 4. ML -> 5. Correlation -> 6. Risk
        # -> 7. Explainability -> 8. Threat State -> 9. Trajectory -> 10. Alert
        req = DetectionRequest(**payload)
        alert = analyze_fn(req)
        alerts.append(alert)

    return alerts

