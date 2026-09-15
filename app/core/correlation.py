"""
CyberSentinel Threat Correlation Engine.

Groups alerts from the same source within a time window and
detects multi-signal attack patterns.

Methodology (documented):
- Window: 300 seconds (5 minutes) per source IP
- Each unique detector firing = 1 signal
- Correlation score = weighted sum of active signals
- Multi-detector patterns increase overall threat severity

Scoring logic:
  Each detector contributes its confidence score.
  When multiple detectors fire for the same source IP:
    - 2 detectors: +10% score boost
    - 3+ detectors: +20% score boost
  Known kill-chain patterns (e.g., Recon + C2 + Exfil) flag CORRELATED_ATTACK.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


# ============================================================
# KNOWN KILL-CHAIN PATTERNS
# ============================================================

# Maps (frozenset of threat classes) -> correlated_threat_name
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


# ============================================================
# CORRELATION WINDOW TRACKER
# ============================================================

class CorrelationEngine:
    """
    Maintains a rolling window of alerts per source IP.
    Computes correlation scores when multiple detectors fire.
    """

    WINDOW_SECONDS = 300  # 5-minute window per source

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # source_ip -> list of {threat_class, confidence, timestamp}
        self._windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _clean_window(self, source: str) -> None:
        """Remove events older than WINDOW_SECONDS."""
        cutoff = time.time() - self.WINDOW_SECONDS
        self._windows[source] = [
            e for e in self._windows[source]
            if e["timestamp"] >= cutoff
        ]

    def record_alert(
        self,
        source: str,
        threat_class: str,
        confidence: float,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Record an alert and return correlation analysis.

        Returns:
            correlated (bool): True if multiple detectors fired
            correlated_threats (list): all threat classes in window
            correlation_score (float): 0.0–1.0 composite
            pattern (str | None): named kill-chain pattern if matched
            detector_count (int): number of distinct detectors in window
        """
        with self._lock:
            ts = timestamp or time.time()
            self._windows[source].append({
                "threat_class": threat_class.upper(),
                "confidence": confidence,
                "timestamp": ts,
            })
            self._clean_window(source)

            events = self._windows[source]
            active_classes = list({e["threat_class"] for e in events})
            detector_count = len(active_classes)

            # Compute weighted average confidence
            if events:
                avg_confidence = sum(e["confidence"] for e in events) / len(events)
            else:
                avg_confidence = confidence

            # Boost for multi-detector agreement
            if detector_count >= 3:
                boost = 1.20
            elif detector_count == 2:
                boost = 1.10
            else:
                boost = 1.0

            correlation_score = min(1.0, avg_confidence * boost)

            # Check kill-chain patterns (prioritize largest/most specific patterns first)
            pattern = None
            sorted_patterns = sorted(KILL_CHAIN_PATTERNS.items(), key=lambda x: len(x[0]), reverse=True)
            for pattern_set, pattern_name in sorted_patterns:
                if pattern_set.issubset(set(active_classes)):
                    pattern = pattern_name
                    break

            return {
                "correlated": detector_count > 1,
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
        """Return all sources with active correlated threats."""
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
        """Return how many distinct alert events a source has generated in the window."""
        with self._lock:
            self._clean_window(source)
            return len(self._windows[source])


# ============================================================
# SINGLETON
# ============================================================

_engine: Optional[CorrelationEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = CorrelationEngine()
    return _engine
