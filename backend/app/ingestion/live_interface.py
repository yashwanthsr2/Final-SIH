"""
CODEZILLA live passive traffic monitor.

This module captures traffic only; it never injects, blocks, probes,
or decrypts packets. It aggregates observed metadata into short windows
and feeds compatible behavioral features into the existing CODEZILLA
ML detector service.

Windows: Scapy + Npcap are required for live capture on Windows.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

import math
import pandas as pd

from backend.app.schemas.flow import NormalizedFlow
from backend.app.features.feature_pipeline import extract_features_from_flows


FlowKey = Tuple[str, str, int, int, str]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        value = float(value)
        return value if math.isfinite(value) else default
    except (TypeError, ValueError):
        return default


def _safe_div(a: float, b: float) -> float:
    return float(a) / float(b) if b else 0.0


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0
    syn: int = 0
    ack: int = 0
    rst: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class LiveState:
    running: bool = False
    interface: Optional[str] = None
    started_at: Optional[str] = None
    packets_seen: int = 0
    bytes_seen: int = 0
    windows_processed: int = 0
    last_window: Optional[str] = None
    flows_seen: int = 0
    last_error: Optional[str] = None
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    flow_rate: float = 0.0
    detections: int = 0
    last_detection: Optional[Dict[str, Any]] = None
    detector_status: Dict[str, str] = field(default_factory=lambda: {
        "DDoS": "READY",
        "C2": "READY",
        "DNS": "READY",
        "ENCRYPTED_TRAFFIC": "READY",
    })


class LiveMonitor:
    """Threaded passive monitor with detector-specific feature adapters."""

    def __init__(
        self,
        detect_callback: Callable[[Dict[str, Any]], Dict[str, Any]],
        default_window_seconds: int = 5,
    ) -> None:
        self.detect_callback = detect_callback
        self.default_window_seconds = default_window_seconds
        self.state = LiveState()
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._zeek_sensor: Optional[Any] = None
        self._stop_event = threading.Event()
        self._flows: Dict[FlowKey, Flow] = {}
        self._window_started: Optional[float] = None
        self._history_ddos: Deque[Dict[str, float]] = deque(maxlen=8)
        self._history_c2: Deque[Dict[str, float]] = deque(maxlen=30)
        self._history_dns: Deque[Dict[str, float]] = deque(maxlen=10)
        self._history_encrypted: Deque[Dict[str, float]] = deque(maxlen=10)
        self._recent_packets: Deque[Tuple[float, str, str, int, int, str, int]] = deque(maxlen=50000)
        self._recent_observed_flows: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._last_delta_bytes_sent: int = 0
        self._last_delta_bytes_recv: int = 0

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------
    def list_interfaces(self) -> List[Dict[str, str]]:
        """List active network interfaces with friendly names (e.g. Wi-Fi)."""
        seen = set()
        result: List[Dict[str, str]] = []
        try:
            import psutil
            for iface in psutil.net_io_counters(pernic=True).keys():
                if "Loopback" not in iface and iface not in seen:
                    seen.add(iface)
                    result.append({"name": iface, "description": iface})
        except Exception:
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            for item in get_windows_if_list():
                name = item.get("name")
                desc = item.get("description", "")
                if name and "Filter" not in desc and "Loopback" not in name and "Virtual" not in desc:
                    if name not in seen:
                        seen.add(name)
                        result.append({"name": name, "description": desc})
        except Exception:
            pass

        if not result:
            result = [{"name": "Wi-Fi", "description": "Default Wireless Interface"}]

        # Sort with Wi-Fi first
        result.sort(key=lambda x: (0 if "wi-fi" in x["name"].lower() or "wlan" in x["name"].lower() else 1, x["name"]))
        return result

    def start(self, interface: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if self.state.running:
                return self.snapshot()
            self.state = LiveState(
                running=True,
                interface=interface or "Wi-Fi",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            self._flows.clear()
            self._recent_packets.clear()
            self._history_ddos.clear()
            self._history_c2.clear()
            self._history_dns.clear()
            self._history_encrypted.clear()
            self._window_started = time.time()
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._capture_loop,
                name="cybersentinel-live-capture",
                daemon=True,
            )
            self._thread.start()
        return self.snapshot()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self.state.running:
                return self.snapshot()
            self.state.running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        with self._lock:
            self._thread = None
        return self.snapshot()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            result = dict(self.state.__dict__)
            now = time.time()
            recent = [item for item in self._recent_packets if now - item[0] <= 5.0]
            result["packet_rate"] = round(len(recent) / 5.0, 1)
            result["byte_rate"] = round(sum(item[6] for item in recent) / 5.0, 1)
            recent_flows = {(item[1], item[2], item[3], item[4], item[5]) for item in recent}
            result["flow_rate"] = round(len(recent_flows) / 5.0, 1)
            result["uptime_seconds"] = self._uptime_seconds()
            try:
                from backend.app.core.baseline_engine import get_baseline_engine
                result["baseline"] = get_baseline_engine().get_status()
            except Exception:

                result["baseline"] = {"state": "OFF"}
            return result

    def get_recent_flows(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._recent_observed_flows)

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------
    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff

            kwargs: Dict[str, Any] = {
                "store": False,
                "prn": self._packet_callback,
            }
            if self.state.interface and self.state.interface != "Wi-Fi":
                kwargs["iface"] = self.state.interface

            # Quick probe to see if layer 2 sniffing is supported without exception
            sniff(count=1, timeout=0.8, **kwargs)

            # Continue sniffing
            sniff(
                stop_filter=lambda _pkt: self._stop_event.is_set(),
                **kwargs,
            )
        except Exception:
            # Fallback to driverless Windows socket & interface flow poller
            self._psutil_flow_monitor_loop()
        finally:
            self._finalize_window(force=True)

    def _psutil_flow_monitor_loop(self) -> None:
        """
        Passive native Windows socket & interface flow monitor.
        Runs driverless — zero Npcap driver required, zero elevation needed.
        """
        try:
            import psutil
        except ImportError:
            return

        iface = self.state.interface or "Wi-Fi"
        all_nics = psutil.net_io_counters(pernic=True)
        target_nic = None
        for nic in all_nics.keys():
            if iface.lower() in nic.lower() or nic.lower() in iface.lower():
                target_nic = nic
                break
        if not target_nic:
            target_nic = "Wi-Fi" if "Wi-Fi" in all_nics else (list(all_nics.keys())[0] if all_nics else None)

        prev_io = all_nics.get(target_nic) if target_nic else psutil.net_io_counters()

        while not self._stop_event.is_set():
            time.sleep(max(1.0, float(self.default_window_seconds)))
            now = time.time()

            curr_nics = psutil.net_io_counters(pernic=True)
            curr_io = curr_nics.get(target_nic) if target_nic else psutil.net_io_counters()

            if curr_io and prev_io:
                delta_pkts_sent = max(0, curr_io.packets_sent - prev_io.packets_sent)
                delta_pkts_recv = max(0, curr_io.packets_recv - prev_io.packets_recv)
                delta_bytes_sent = max(0, curr_io.bytes_sent - prev_io.bytes_sent)
                delta_bytes_recv = max(0, curr_io.bytes_recv - prev_io.bytes_recv)
                delta_pkts = delta_pkts_sent + delta_pkts_recv
                delta_bytes = delta_bytes_sent + delta_bytes_recv
            else:
                delta_pkts_sent = 0
                delta_pkts_recv = 0
                delta_bytes_sent = 0
                delta_bytes_recv = 0
                delta_pkts = 0
                delta_bytes = 0
            prev_io = curr_io

            self._last_delta_bytes_sent = delta_bytes_sent
            self._last_delta_bytes_recv = delta_bytes_recv

            try:
                conns = psutil.net_connections(kind="inet")
            except Exception:
                conns = []

            # Only monitor active external non-loopback network connections (exclude closed TIME_WAIT/CLOSE_WAIT)
            active_conns = [
                c for c in conns
                if c.raddr
                and c.raddr.ip not in ("127.0.0.1", "::1", "0.0.0.0")
                and (not c.laddr or c.laddr.ip not in ("127.0.0.1", "::1"))
                and (c.status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV") or c.type == 2)
            ]

            with self._lock:
                self.state.packets_seen += delta_pkts
                self.state.bytes_seen += delta_bytes

                for c in active_conns:
                    src = c.laddr.ip if c.laddr else "127.0.0.1"
                    dst = c.raddr.ip
                    sport = c.laddr.port if c.laddr else 0
                    dport = c.raddr.port
                    proto = "TCP" if c.type == 1 else "UDP"

                    key: FlowKey = (src, dst, sport, dport, proto)
                    flow = self._flows.get(key)
                    if flow is None:
                        flow = Flow(
                            src=src,
                            dst=dst,
                            sport=sport,
                            dport=dport,
                            proto=proto,
                            first_ts=now - float(self.default_window_seconds),
                            last_ts=now,
                        )
                        self._flows[key] = flow
                        self.state.flows_seen += 1

                    flow.last_ts = now
                    flow.packets += max(1, delta_pkts // max(1, len(active_conns)))
                    flow.bytes += max(10, delta_bytes // max(1, len(active_conns)))
                    if getattr(c, "status", "") == "SYN_SENT":
                        flow.syn += 1
                    elif getattr(c, "status", "") == "ESTABLISHED":
                        flow.ack += 1

            self._finalize_window(force=True)

    def _packet_callback(self, packet: Any) -> None:
        now = _safe_float(getattr(packet, "time", time.time()), time.time())
        length = len(packet) if hasattr(packet, "__len__") else 0

        try:
            meta = self._packet_to_flow_meta(packet, now, length)
        except Exception:
            return

        if meta is None:
            with self._lock:
                self.state.packets_seen += 1
                self.state.bytes_seen += length
            self._tick_window(now)
            return

        src, dst, sport, dport, proto, flags, payload_len = meta

        with self._lock:
            self.state.packets_seen += 1
            self.state.bytes_seen += length
            self._recent_packets.append((now, src, dst, sport, dport, proto, length))

            key: FlowKey = (src, dst, sport, dport, proto)
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    proto=proto,
                    first_ts=now,
                    last_ts=now,
                )
                self._flows[key] = flow
                self.state.flows_seen += 1

            flow.last_ts = now
            flow.packets += 1
            flow.bytes += max(0, payload_len)

            flag_text = str(flags or "").upper()
            flow.syn += int("S" in flag_text and "A" not in flag_text)
            flow.ack += int("A" in flag_text)
            flow.rst += int("R" in flag_text)

        self._tick_window(now)

    def _packet_to_flow_meta(self, packet: Any, ts: float, wire_len: int):
        if not hasattr(packet, "haslayer") or not packet.haslayer("IP"):
            return None

        ip = packet["IP"]
        src = str(getattr(ip, "src", ""))
        dst = str(getattr(ip, "dst", ""))
        proto_num = int(getattr(ip, "proto", 0) or 0)

        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            sport = int(getattr(tcp, "sport", 0) or 0)
            dport = int(getattr(tcp, "dport", 0) or 0)
            flags = str(getattr(tcp, "flags", ""))
            payload_len = max(0, wire_len - 40)
            proto = "TCP"
        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            sport = int(getattr(udp, "sport", 0) or 0)
            dport = int(getattr(udp, "dport", 0) or 0)
            flags = ""
            payload_len = max(0, wire_len - 28)
            proto = "UDP"
        else:
            sport = 0
            dport = 0
            flags = ""
            payload_len = max(0, wire_len - 20)
            proto = str(proto_num)

        return src, dst, sport, dport, proto, flags, payload_len

    def _tick_window(self, now: float) -> None:
        start = self._window_started
        if start is None:
            self._window_started = now
            return
        if now - start >= self.default_window_seconds:
            self._finalize_window()
            self._window_started = now

    # ------------------------------------------------------------------
    # Feature construction
    # ------------------------------------------------------------------
    def _finalize_window(self, force: bool = False) -> None:
        with self._lock:
            if not self._flows:
                return
            flows = list(self._flows.values())
            self._flows = {}
            window_time = datetime.fromtimestamp(
                self._window_started or time.time(), timezone.utc
            ).replace(microsecond=0).isoformat()
            self.state.windows_processed += 1
            self.state.last_window = window_time

            elapsed = max(1.0, self.default_window_seconds)
            self.state.packet_rate = self.state.packets_seen / max(elapsed, 1.0)
            self.state.byte_rate = self.state.bytes_seen / max(elapsed, 1.0)
            self.state.flow_rate = len(flows) / max(elapsed, 1.0)

        try:
            # Convert to canonical NormalizedFlow instances
            normalized_flows = [
                f if isinstance(f, NormalizedFlow) else NormalizedFlow(
                    flow_id=f"flow_{f.src}_{f.dst}_{f.sport}_{f.dport}_{f.first_ts}",
                    timestamp=f.last_ts,
                    first_ts=f.first_ts,
                    last_ts=f.last_ts,
                    source_ip=f.src,
                    destination_ip=f.dst,
                    source_port=f.sport,
                    destination_port=f.dport,
                    protocol=f.proto,
                    duration=f.duration,
                    total_bytes=f.bytes,
                    orig_bytes=f.bytes,
                    total_packets=f.packets,
                    orig_pkts=f.packets,
                    syn=f.syn,
                    ack=f.ack,
                    rst=f.rst,
                )
                for f in flows
            ]

            bytes_sent = getattr(self, "_last_delta_bytes_sent", 0)
            bytes_recv = getattr(self, "_last_delta_bytes_recv", 0)

            # Canonical Feature Pipeline Transformation
            payload = extract_features_from_flows(
                flows=normalized_flows,
                window_seconds=float(self.default_window_seconds),
                history_queues={
                    "ddos": self._history_ddos,
                    "c2": self._history_c2,
                    "dns": self._history_dns,
                    "encrypted": self._history_encrypted,
                },
                bytes_in=bytes_recv,
                bytes_out=bytes_sent,
            )

            # Record observation in BaselineEngine
            try:
                from backend.app.core.baseline_engine import get_baseline_engine
                dom_src = payload.get("source") or self._dominant_source(flows)
                unique_ports = len({f.dport for f in flows})
                unique_dests = len({f.dst for f in flows})
                get_baseline_engine().record_window_observation(
                    byte_rate=self.state.byte_rate,
                    packet_rate=self.state.packet_rate,
                    unique_destinations=unique_dests,
                    unique_ports=unique_ports,
                    destination_ips=[f.dst for f in flows[:50]],
                    bytes_in=bytes_recv,
                    bytes_out=bytes_sent,
                )
            except Exception:
                pass

            # Store recent flows for live table
            with self._lock:
                for f in flows[:20]:
                    self._recent_observed_flows.appendleft({
                        "timestamp": f.last_ts,
                        "source": f.src,
                        "destination": f.dst,
                        "sport": f.sport,
                        "dport": f.dport,
                        "proto": f.proto,
                        "packets": f.packets,
                        "bytes": f.bytes,
                        "duration": round(f.duration, 2),
                    })

            result = self.detect_callback(payload)
            with self._lock:
                if result.get("prediction") == "THREAT":
                    self.state.detections += 1
                    self.state.last_detection = result
        except Exception as exc:
            with self._lock:
                self.state.last_error = str(exc)

    @staticmethod
    def _dominant_source(flows: List[Flow]) -> Optional[str]:
        counts: Dict[str, int] = defaultdict(int)
        for f in flows:
            counts[f.src] += f.packets
        return max(counts, key=counts.get) if counts else None

    @staticmethod
    def _base_stats(flows: List[Flow]) -> Dict[str, float]:
        if not flows:
            return {}
        packets = [float(f.packets) for f in flows]
        bytes_ = [float(f.bytes) for f in flows]
        duration = [float(f.duration) for f in flows]
        elapsed = max(0.001, max(f.last_ts for f in flows) - min(f.first_ts for f in flows))
        iats = []
        timestamps = sorted(f.first_ts for f in flows)
        for a, b in zip(timestamps, timestamps[1:]):
            iats.append(max(0.0, b - a))
        mean_iat = sum(iats) / len(iats) if iats else 0.0
        mean_d = sum(duration) / len(duration)
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
        self,
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

    def _build_ddos(self, flows: List[Flow]) -> Dict[str, float]:
        base = self._base_stats(flows)
        cols = [
            "flow_count", "total_packets", "total_bytes",
            "mean_packets_per_second",
            "max_packets_per_second", "mean_bytes_per_second",
            "max_bytes_per_second", "mean_packet_size", "mean_iat",
            "mean_syn_count", "mean_ack_count", "mean_rst_count",
        ]
        feat = self._with_lags_roll3(base, self._history_ddos, cols)
        self._history_ddos.append(base)
        return feat

    # C2 feature builder follows the deployed training schema: source-centric
    # behavioral windows + past-only history. It is intentionally metadata-only.
    def _build_c2(self, flows: List[Flow]) -> Dict[str, float]:
        if not flows:
            return {"flow_count": 0.0}
        pair_counts: Dict[Tuple[str, int], int] = defaultdict(int)
        dst_counts: Dict[str, int] = defaultdict(int)
        for f in flows:
            pair_counts[(f.dst, f.dport)] += 1
            dst_counts[f.dst] += 1

        pair_iats: List[float] = []
        ordered = sorted(flows, key=lambda x: x.first_ts)
        last_by_pair: Dict[Tuple[str, int, str], float] = {}
        for f in ordered:
            key = (f.dst, f.dport, f.proto)
            if key in last_by_pair:
                pair_iats.append(max(0.0, f.first_ts - last_by_pair[key]))
            last_by_pair[key] = f.first_ts

        def mean(vals): return sum(vals) / len(vals) if vals else 0.0
        def std(vals):
            if len(vals) < 2: return 0.0
            m = mean(vals)
            return math.sqrt(sum((x-m)**2 for x in vals) / (len(vals)-1))

        flow_count = float(len(flows))
        total_packets = float(sum(f.packets for f in flows))
        total_bytes = float(sum(f.bytes for f in flows))
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
            "unique_ports": float(len({f.dport for f in flows})),
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

        hist = list(self._history_c2)
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
        current["max_recent_contacts_60s"] = float(len({(f.dst, f.dport) for f in flows}))
        current["mean_recent_contacts_60s"] = mean([1.0 for _ in flows])
        current["max_recent_contacts_300s"] = current["max_recent_contacts_60s"]
        current["mean_recent_contacts_300s"] = current["mean_recent_contacts_60s"]
        current["median_pair_iat"] = current["iat_median"]
        current["mean_pair_iat"] = current["iat_mean"]
        current["std_pair_iat"] = current["iat_std"]
        current["pair_iat_cv"] = current["iat_cv"]

        self._history_c2.append(current.copy())
        return current

    def _build_dns(self, flows: List[Flow]) -> Optional[Dict[str, float]]:
        def mean(vals: List[float]) -> float:
            return sum(vals) / len(vals) if vals else 0.0

        def std(vals: List[float]) -> float:
            if len(vals) < 2:
                return 0.0
            m = mean(vals)
            return math.sqrt(
                sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
            )

        dns = [f for f in flows if f.dport in (53, 853) or f.sport in (53, 853)]
        if not dns:
            return None
        base = self._base_stats(dns)
        source = defaultdict(list)
        for f in dns:
            source[f.src].append(f)
        dominant = max(source.values(), key=len) if source else dns
        packet_total = sum(f.packets for f in dominant)
        byte_total = sum(f.bytes for f in dominant)
        query_rate = _safe_div(len(dominant), max(self.default_window_seconds, 1))
        dest_counts = defaultdict(int)
        dest_bytes = defaultdict(int)
        for f in dominant:
            dest_counts[f.dst] += f.packets
            dest_bytes[f.dst] += f.bytes
        packet_conc = _safe_div(max(dest_counts.values(), default=0), packet_total)
        byte_conc = _safe_div(max(dest_bytes.values(), default=0), byte_total)
        timing = [max(0.0, b.first_ts-a.first_ts) for a,b in zip(sorted(dominant,key=lambda x:x.first_ts), sorted(dominant,key=lambda x:x.first_ts)[1:])]
        cv = _safe_div(math.sqrt(sum((x-(sum(timing)/len(timing)))**2 for x in timing)/(len(timing)-1)) if len(timing)>1 else 0.0, sum(timing)/len(timing) if timing else 0.0)
        hist = list(self._history_dns)
        prior = hist[-1].get("dns_query_rate", query_rate) if hist else query_rate
        roll3 = mean([x.get("dns_query_rate", 0.0) for x in hist[-3:]]) if hist else query_rate
        roll6 = mean([x.get("dns_query_rate", 0.0) for x in hist[-6:]]) if hist else query_rate
        std6 = std([x.get("dns_query_rate", 0.0) for x in hist[-6:]]) if hist else 0.0
        current = {
            "dns_query_rate": query_rate,
            "dns_unique_destinations": float(len(dest_counts)),
            "dns_packet_concentration": packet_conc,
            "dns_byte_concentration": byte_conc,
            "dns_iat_cv": cv,
            "query_rate_prev": prior,
            "query_rate_roll3": roll3,
            "query_rate_roll6": roll6,
            "query_rate_std6": std6,
            "query_rate_change": query_rate - prior,
            "query_rate_z6": _safe_div(query_rate-roll6, std6 or 1.0),
            "destination_change": abs(float(len(dest_counts)) - (hist[-1].get("dns_unique_destinations", len(dest_counts)) if hist else len(dest_counts))),
            "bytes_per_query": _safe_div(byte_total, len(dominant)),
            "packets_per_query": _safe_div(packet_total, len(dominant)),
        }
        self._history_dns.append(current.copy())
        return current

    def _build_encrypted(self, flows: List[Flow]) -> Optional[Dict[str, float]]:
        def mean(vals: List[float]) -> float:
            return sum(vals) / len(vals) if vals else 0.0
        encrypted = [
            f for f in flows
            if f.dport in (443, 8443, 853) or f.sport in (443, 8443, 853)
        ]
        if not encrypted:
            return None
        count = len(encrypted)
        packets = sum(f.packets for f in encrypted)
        bytes_ = sum(f.bytes for f in encrypted)
        hist = list(self._history_encrypted)
        current = {
            "encrypted_flow_count": float(count),
            "encrypted_total_packets": float(packets),
            "encrypted_total_bytes": float(bytes_),
            "encrypted_unique_destinations": float(len({f.dst for f in encrypted})),
            "encrypted_unique_ports": float(len({f.dport for f in encrypted})),
            "encrypted_mean_duration": mean([f.duration for f in encrypted]),
            "bytes_per_flow": _safe_div(bytes_, count),
            "packets_per_flow": _safe_div(packets, count),
            "flow_count_change": float(count - (hist[-1].get("encrypted_flow_count", count) if hist else count)),
            "bytes_change": float(bytes_ - (hist[-1].get("encrypted_total_bytes", bytes_) if hist else bytes_)),
            "destination_change": float(len({f.dst for f in encrypted}) - (hist[-1].get("encrypted_unique_destinations", len({f.dst for f in encrypted})) if hist else len({f.dst for f in encrypted}))),
        }
        self._history_encrypted.append(current.copy())
        return current

    def _uptime_seconds(self) -> float:
        with self._lock:
            if not self.state.started_at:
                return 0.0
            try:
                start = datetime.fromisoformat(self.state.started_at)
                return max(0.0, (datetime.now(timezone.utc) - start).total_seconds())
            except Exception:
                return 0.0
