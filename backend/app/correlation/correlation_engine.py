"""
CyberSentinel Threat Correlation Engine.

Groups alerts from the same source within a time window and
detects multi-signal attack patterns across detectors.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

KILL_CHAIN_PATTERNS: Dict[frozenset, str] = {
    frozenset({"RECON", "C2"}): "RECON_TO_C2",
    frozenset({"C2", "EXFILTRATION"}): "C2_EXFIL",
    frozenset({"RECON", "C2", "EXFILTRATION"}): "FULL_KILL_CHAIN",
    frozenset({"DDoS", "C2"}): "BOTNET_DDOS",
    frozenset({"DNS", "C2"}): "DNS_C2_TUNNEL",
    frozenset({"RECON", "DNS"}): "RECON_DNS_PROBE",
    frozenset({"ENCRYPTED_TRAFFIC", "C2"}): "ENCRYPTED_C2",
    frozenset({"ENCRYPTED_TRAFFIC", "EXFILTRATION"}): "ENCRYPTED_EXFIL",
}

class CorrelationEngine:
    """
    Maintains a rolling window of alerts per source IP.
    Computes correlation scores when multiple detectors fire.
    """

    WINDOW_SECONDS = 300  # 5-minute window per source/destination

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._dest_windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _clean_window(self, source: str) -> None:
        cutoff = time.time() - self.WINDOW_SECONDS
        self._windows[source] = [
            e for e in self._windows[source]
            if e["timestamp"] >= cutoff
        ]

    def _clean_dest_window(self, dest: str) -> None:
        cutoff = time.time() - self.WINDOW_SECONDS
        self._dest_windows[dest] = [
            e for e in self._dest_windows[dest]
            if e["timestamp"] >= cutoff
        ]

    def record_alert(
        self,
        source: str,
        threat_class: str,
        confidence: float,
        timestamp: Optional[float] = None,
        destination: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            ts = timestamp or time.time()
            tc = threat_class.upper()
            self._windows[source].append({
                "threat_class": tc,
                "confidence": confidence,
                "timestamp": ts,
            })
            self._clean_window(source)

            if destination:
                self._dest_windows[destination].append({
                    "source": source,
                    "threat_class": tc,
                    "confidence": confidence,
                    "timestamp": ts,
                })
                self._clean_dest_window(destination)


            events = self._windows[source]
            active_classes = list({e["threat_class"] for e in events})
            detector_count = len(active_classes)

            if events:
                avg_confidence = sum(e["confidence"] for e in events) / len(events)
            else:
                avg_confidence = confidence

            if detector_count >= 3:
                boost = 1.20
            elif detector_count == 2:
                boost = 1.10
            else:
                boost = 1.0

            correlation_score = min(1.0, avg_confidence * boost)

            pattern = None
            sorted_patterns = sorted(KILL_CHAIN_PATTERNS.items(), key=lambda x: len(x[0]), reverse=True)
            for pattern_set, pattern_name in sorted_patterns:
                if pattern_set.issubset(set(active_classes)):
                    pattern = pattern_name
                    break

            # Target-centric correlation for distributed multi-source attacks
            dest_correlated = False
            if destination:
                dest_events = self._dest_windows.get(destination, [])
                dest_sources = {e["source"] for e in dest_events}
                if len(dest_sources) > 1:
                    dest_correlated = True
                    dest_classes = {e["threat_class"] for e in dest_events}
                    if pattern is None:
                        if "DDOS" in dest_classes:
                            pattern = "DISTRIBUTED_DDOS"
                        elif "RECON" in dest_classes:
                            pattern = "DISTRIBUTED_RECON_SWEEP"
                        else:
                            pattern = "DISTRIBUTED_TARGET_CORRELATION"

            is_correlated = (detector_count > 1) or dest_correlated

            return {
                "correlated": is_correlated,
                "correlated_threats": active_classes,
                "correlation_score": round(correlation_score, 4),
                "detector_count": detector_count,
                "pattern": pattern,
                "events_in_window": len(events),
            }


    def get_source_history(self, source: str) -> List[Dict[str, Any]]:
        with self._lock:
            self._clean_window(source)
            return list(self._windows[source])

    def get_all_active_sources(self) -> Dict[str, Any]:
        with self._lock:
            result = {}
            for source, events in self._windows.items():
                cutoff = time.time() - self.WINDOW_SECONDS
                active = [e for e in events if e["timestamp"] >= cutoff]
                if len(active) > 1:
                    classes = list({e["threat_class"] for e in active})
                    result[source] = {
                        "active_threats": classes,
                        "event_count": len(active),
                        "detector_count": len(classes),
                    }
            return result

    def get_persistence_count(self, source: str) -> int:
        with self._lock:
            self._clean_window(source)
            return len(self._windows[source])

_engine: Optional[CorrelationEngine] = None
_engine_lock = threading.Lock()

def get_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = CorrelationEngine()
    return _engine
