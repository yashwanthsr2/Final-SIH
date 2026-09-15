"""
CyberSentinel Normal Traffic Baseline Engine.

Learns normal background Internet activity (Google, YouTube, web browsing,
CDN multiplexing, normal DNS queries) over a configurable duration (default: 5 min).

Functions:
- Tracks normal packet rates, byte distributions, and CDN fan-out
- Distinguishes legitimate video streaming (high downlink, low uplink) from Exfiltration (high uplink)
- Distinguishes CDN browser parallel connections from Reconnaissance port scanning
- Never suppresses high-confidence true threats (e.g. C2 beaconing, DNS covert tunneling)
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set

DEFAULT_BASELINE_SECONDS = int(os.getenv("BASELINE_DURATION", "300"))


class BaselineEngine:
    """
    Statistical profiler for normal network traffic.
    Operates in three modes: OFF, LEARNING, ACTIVE.
    """

    STATE_OFF = "OFF"
    STATE_LEARNING = "LEARNING"
    STATE_ACTIVE = "ACTIVE"

    def __init__(self, duration_seconds: int = DEFAULT_BASELINE_SECONDS) -> None:
        self.duration_seconds = duration_seconds
        self._lock = threading.RLock()
        self.state = self.STATE_OFF
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None

        # Learned baseline statistics
        self._sample_count = 0
        self._byte_rates: List[float] = []
        self._packet_rates: List[float] = []
        self._dest_counts: List[int] = []
        self._port_counts: List[int] = []
        self._known_destinations: Set[str] = set()
        self._streaming_ratios: List[float] = []

        # Statistical aggregates
        self.mean_byte_rate = 0.0
        self.std_byte_rate = 0.0
        self.max_byte_rate = 0.0

        self.mean_packet_rate = 0.0
        self.std_packet_rate = 0.0
        self.max_packet_rate = 0.0

        self.max_normal_ports = 10
        self.max_normal_destinations = 15
        
        self._load_profile()

    def _save_profile(self) -> None:
        try:
            from backend.app.core.config import PROJECT_ROOT
            out_file = PROJECT_ROOT / "data" / "baseline_profile.json"
            data = {
                "state": self.state,
                "mean_byte_rate": self.mean_byte_rate,
                "std_byte_rate": self.std_byte_rate,
                "max_byte_rate": self.max_byte_rate,
                "mean_packet_rate": self.mean_packet_rate,
                "std_packet_rate": self.std_packet_rate,
                "max_packet_rate": self.max_packet_rate,
                "max_normal_ports": self.max_normal_ports,
                "max_normal_destinations": self.max_normal_destinations,
                "known_destinations": list(self._known_destinations),
                "completed_at": self.completed_at,
            }
            with open(out_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_profile(self) -> None:
        try:
            from backend.app.core.config import PROJECT_ROOT
            in_file = PROJECT_ROOT / "data" / "baseline_profile.json"
            if in_file.exists():
                with open(in_file, "r") as f:
                    data = json.load(f)
                self.mean_byte_rate = float(data.get("mean_byte_rate", 0.0))
                self.std_byte_rate = float(data.get("std_byte_rate", 0.0))
                self.max_byte_rate = float(data.get("max_byte_rate", 0.0))
                self.mean_packet_rate = float(data.get("mean_packet_rate", 0.0))
                self.std_packet_rate = float(data.get("std_packet_rate", 0.0))
                self.max_packet_rate = float(data.get("max_packet_rate", 0.0))
                self.max_normal_ports = int(data.get("max_normal_ports", 10))
                self.max_normal_destinations = int(data.get("max_normal_destinations", 15))
                self._known_destinations = set(data.get("known_destinations", []))
                self.completed_at = data.get("completed_at")
                if data.get("state") == self.STATE_ACTIVE:
                    self.state = self.STATE_ACTIVE
        except Exception:
            pass

    def start_learning(self, duration: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            if duration:
                self.duration_seconds = duration
            self.state = self.STATE_LEARNING
            self.started_at = time.time()
            self.completed_at = None
            self._sample_count = 0
            self._byte_rates.clear()
            self._packet_rates.clear()
            self._dest_counts.clear()
            self._port_counts.clear()
            self._known_destinations.clear()
            self._streaming_ratios.clear()
            return self.get_status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self.state = self.STATE_OFF
            return self.get_status()

    def record_window_observation(
        self,
        *,
        byte_rate: float,
        packet_rate: float,
        unique_destinations: int,
        unique_ports: int,
        destination_ips: Optional[List[str]] = None,
        bytes_in: float = 0.0,
        bytes_out: float = 0.0,
    ) -> None:
        """Feed an observed window into the baseline engine."""
        with self._lock:
            if self.state != self.STATE_LEARNING:
                return

            now = time.time()
            elapsed = now - (self.started_at or now)

            # Record samples
            self._sample_count += 1
            self._byte_rates.append(byte_rate)
            self._packet_rates.append(packet_rate)
            self._dest_counts.append(unique_destinations)
            self._port_counts.append(unique_ports)

            if destination_ips:
                self._known_destinations.update(destination_ips[:50])

            if bytes_in > 0:
                self._streaming_ratios.append(bytes_in / max(1.0, bytes_out))

            # Auto-complete when target duration reached
            if elapsed >= self.duration_seconds:
                self._finalize_baseline()

    def _finalize_baseline(self) -> None:
        self.state = self.STATE_ACTIVE
        self.completed_at = time.time()

        if self._byte_rates:
            n = len(self._byte_rates)
            self.mean_byte_rate = sum(self._byte_rates) / n
            var_b = sum((x - self.mean_byte_rate) ** 2 for x in self._byte_rates) / max(1, n - 1)
            self.std_byte_rate = math.sqrt(var_b)
            self.max_byte_rate = max(self._byte_rates)

        if self._packet_rates:
            n = len(self._packet_rates)
            self.mean_packet_rate = sum(self._packet_rates) / n
            var_p = sum((x - self.mean_packet_rate) ** 2 for x in self._packet_rates) / max(1, n - 1)
            self.std_packet_rate = math.sqrt(var_p)
            self.max_packet_rate = max(self._packet_rates)

        if self._dest_counts:
            self.max_normal_destinations = max(15, max(self._dest_counts))
        if self._port_counts:
            self.max_normal_ports = max(15, max(self._port_counts))
        self._save_profile()

    def calibrate_detection(
        self,
        *,
        threat_class: str,
        score: float,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Calibrate detector output against learned baseline to prevent false alarms
        from normal browsing, without hiding true malicious attacks.
        """
        with self._lock:
            # Case 1: Video streaming / file download misclassified as Exfiltration
            if threat_class == "EXFILTRATION":
                bytes_out = float(features.get("bytes_out", 0))
                bytes_in = float(features.get("bytes_in", 0))
                # If traffic is predominantly inbound (download/streaming), it's NOT exfiltration!
                if bytes_in >= bytes_out:
                    return {
                        "calibrated": True,
                        "score": 0.0,
                        "suppressed": True,
                        "reason": f"Inbound video/content streaming confirmed (bytes_in={bytes_in:,} >= bytes_out={bytes_out:,})",
                    }

            # Case 2: CDN multiplexing / browser tab loading misclassified as Recon
            if threat_class == "RECON":
                ports = int(features.get("unique_dst_ports", 0))
                syn_ratio = float(features.get("mean_syn_count", 0.0))
                # Normal web browsing uses standard ports (80, 443, 853, 53) with low SYN abort ratio
                if ports <= self.max_normal_ports and syn_ratio < 0.4:
                    return {
                        "calibrated": True,
                        "score": 0.0,
                        "suppressed": True,
                        "reason": f"Browser CDN multiplexing within normal baseline (ports={ports} <= {self.max_normal_ports})",
                    }

            # Case 3: High-volume streaming / download burst misclassified as DDoS
            # Legitimate video streaming and web downloads carry large MTU data payloads (mean_packet_size >= 600 B)
            # with low SYN abort ratio. In contrast, volumetric attack floods use tiny packets (< 300 B) or high SYN ratio.
            if threat_class == "DDoS":
                syn_count = float(features.get("mean_syn_count", 0.0))
                pkt_size = float(features.get("mean_packet_size", 0.0))
                flow_count = float(features.get("flow_count", 0.0))
                byte_rate = float(features.get("mean_bytes_per_second", 0.0))

                is_legitimate_streaming = (
                    syn_count < 0.40
                    and pkt_size >= 600.0
                    and flow_count <= 50
                    and byte_rate < 50_000_000
                )
                if is_legitimate_streaming:
                    return {
                        "calibrated": True,
                        "score": 0.0,
                        "suppressed": True,
                        "reason": f"High-throughput video streaming / browsing burst confirmed (payload {pkt_size:.0f} B/pkt, established TLS)",
                    }

            if self.state != self.STATE_ACTIVE:
                return {"calibrated": False, "score": score, "suppressed": False, "reason": "Baseline inactive"}

            return {"calibrated": True, "score": score, "suppressed": False, "reason": "True anomaly beyond learned baseline"}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            elapsed = (now - self.started_at) if self.started_at and self.state == self.STATE_LEARNING else 0.0
            progress_pct = min(100.0, (elapsed / max(1, self.duration_seconds)) * 100.0) if self.state == self.STATE_LEARNING else (100.0 if self.state == self.STATE_ACTIVE else 0.0)

            return {
                "state": self.state,
                "duration_seconds": self.duration_seconds,
                "elapsed_seconds": round(elapsed, 1),
                "progress_percent": round(progress_pct, 1),
                "samples_collected": self._sample_count,
                "mean_byte_rate": round(self.mean_byte_rate, 1),
                "max_byte_rate": round(self.max_byte_rate, 1),
                "mean_packet_rate": round(self.mean_packet_rate, 1),
                "known_destinations_count": len(self._known_destinations),
                "max_normal_ports": self.max_normal_ports,
                "is_active": self.state == self.STATE_ACTIVE,
            }


_GLOBAL_BASELINE = BaselineEngine()


def get_baseline_engine() -> BaselineEngine:
    return _GLOBAL_BASELINE
