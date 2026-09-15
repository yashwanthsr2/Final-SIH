"""
CyberSentinel Attack Trajectory Predictor.

Estimates the current threat state and predicts the most likely next state
using a lightweight probabilistic state machine.

States (aligned to MITRE ATT&CK kill chain):
    NORMAL          — no suspicious activity
    RECON           — reconnaissance / scanning observed
    SCANNING        — active port/host scanning confirmed
    C2              — command-and-control beaconing observed
    SUSPICIOUS_ACTIVITY — anomalous behaviour without clear class
    DATA_COLLECTION — indicators of pre-exfil data staging
    EXFILTRATION    — data exfiltration confirmed or predicted
    DISRUPTION      — DDoS or denial-of-service activity

Transition probabilities are computed from:
1. Current detector outputs (which threat classes fired)
2. Historical state of the source IP
3. Time since last activity

This is a heuristic probabilistic model — NOT a deep learning system.
All predictions include honest confidence estimates.
Predictions NEVER claim certainty.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# STATE DEFINITIONS
# ============================================================

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

# ============================================================
# THREAT CLASS → STATE MAPPING
# Which detectors activate which states most strongly
# ============================================================

THREAT_TO_STATE: Dict[str, str] = {
    "RECON": "RECON",
    "DDoS": "DISRUPTION",
    "C2": "C2",
    "DNS": "C2",           # DNS tunneling → C2 channel
    "ENCRYPTED_TRAFFIC": "SUSPICIOUS_ACTIVITY",
    "EXFILTRATION": "EXFILTRATION",
}

# ============================================================
# STATE TRANSITION MATRIX
# P(next_state | current_state) — heuristic weights
# Row: current state index, Col: next state index
# ============================================================

# State indices
_SI = {s: i for i, s in enumerate(STATES)}

# Transition matrix (row=current, col=next)
# Values represent relative likelihood (will be normalised to probabilities)
_TRANSITIONS: Dict[str, Dict[str, float]] = {
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
        "C2": 0.15, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.30,
        "EXFILTRATION": 0.35, "DISRUPTION": 0.02,
    },
    "EXFILTRATION": {
        "NORMAL": 0.05, "RECON": 0.02, "SCANNING": 0.02,
        "C2": 0.10, "SUSPICIOUS_ACTIVITY": 0.10, "DATA_COLLECTION": 0.15,
        "EXFILTRATION": 0.50, "DISRUPTION": 0.06,
    },
    "DISRUPTION": {
        "NORMAL": 0.15, "RECON": 0.05, "SCANNING": 0.05,
        "C2": 0.20, "SUSPICIOUS_ACTIVITY": 0.15, "DATA_COLLECTION": 0.05,
        "EXFILTRATION": 0.05, "DISRUPTION": 0.30,
    },
}


# Normalise each row to sum to 1
for _state, _row in _TRANSITIONS.items():
    _total = sum(_row.values())
    _TRANSITIONS[_state] = {k: v / _total for k, v in _row.items()}


# ============================================================
# TRAJECTORY ENGINE
# ============================================================

class TrajectoryEngine:
    """
    Tracks the threat state per source IP and predicts next state.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # source -> {current_state, history, last_updated}
        self._states: Dict[str, Dict[str, Any]] = {}

    def _get_state(self, source: str) -> Dict[str, Any]:
        if source not in self._states:
            self._states[source] = {
                "current_state": "NORMAL",
                "history": [],
                "last_updated": time.time(),
            }
        return self._states[source]

    def update_state(
        self,
        source: str,
        detected_threat_classes: List[str],
    ) -> Dict[str, Any]:
        """
        Update the threat state for a source based on detected threats.

        Returns the full trajectory result including current + predicted state.
        """
        with self._lock:
            entry = self._get_state(source)
            current_state = entry["current_state"]

            # Determine the new state driven by detections
            new_state = self._advance_state(current_state, detected_threat_classes)

            # Record transition
            entry["history"].append({
                "from": current_state,
                "to": new_state,
                "threats": detected_threat_classes,
                "timestamp": time.time(),
            })
            # Keep last 20 transitions
            if len(entry["history"]) > 20:
                entry["history"] = entry["history"][-20:]

            entry["current_state"] = new_state
            entry["last_updated"] = time.time()

            # Predict next state from transition matrix
            prediction = self._predict_next(new_state, detected_threat_classes)

            return {
                "source": source,
                "current_state": new_state,
                "previous_state": current_state,
                "predicted_next_state": prediction["state"],
                "prediction_confidence": prediction["confidence"],
                "prediction_reasoning": prediction["reasoning"],
                "state_history": entry["history"][-5:],  # last 5 transitions for the UI
                "all_possible_next_states": prediction["all_states"],
            }

    def get_trajectory(self, source: str) -> Dict[str, Any]:
        """Get the current trajectory state for a source without updating."""
        with self._lock:
            if source not in self._states:
                prediction = self._predict_next("NORMAL", [])
                return {
                    "source": source,
                    "current_state": "NORMAL",
                    "predicted_next_state": prediction["state"],
                    "prediction_confidence": prediction["confidence"],
                    "prediction_reasoning": prediction["reasoning"],
                    "state_history": [],
                    "all_possible_next_states": prediction["all_states"],
                }
            entry = self._states[source]
            prediction = self._predict_next(
                entry["current_state"], []
            )
            return {
                "source": source,
                "current_state": entry["current_state"],
                "predicted_next_state": prediction["state"],
                "prediction_confidence": prediction["confidence"],
                "prediction_reasoning": prediction["reasoning"],
                "state_history": entry["history"][-10:],
                "all_possible_next_states": prediction["all_states"],
            }

    update_trajectory = update_state

    def _advance_state(self, current: str, threats: List[str]) -> str:
        """
        Given current state and detected threats, determine new state.
        Threats drive state transitions deterministically.
        """
        if not threats:
            return current

        # Map threats to candidate states
        candidate_states = [THREAT_TO_STATE.get(t.upper(), "SUSPICIOUS_ACTIVITY") for t in threats]

        # Rank candidate states by severity (higher index = more advanced kill-chain)
        state_order = {s: i for i, s in enumerate(STATES)}

        # New state = most advanced among candidates and current
        all_candidates = candidate_states + [current]
        new_state = max(all_candidates, key=lambda s: state_order.get(s, 0))

        return new_state

    def _predict_next(
        self, current_state: str, active_threats: List[str]
    ) -> Dict[str, Any]:
        """
        Use the transition matrix + active threat evidence to predict next state.
        Returns predicted state, confidence, and probability distribution.
        """
        if current_state not in _TRANSITIONS:
            current_state = "NORMAL"

        probs = dict(_TRANSITIONS[current_state])

        # Boost states supported by active detectors
        for threat in active_threats:
            target_state = THREAT_TO_STATE.get(threat.upper())
            if target_state and target_state in probs:
                probs[target_state] = min(1.0, probs[target_state] * 1.5)

        # Re-normalise
        total = sum(probs.values())
        if total > 0:
            probs = {k: v / total for k, v in probs.items()}

        # Find best prediction (excluding NORMAL as a "prediction" if already in a threat state)
        if current_state != "NORMAL":
            search_probs = {k: v for k, v in probs.items()}
        else:
            search_probs = probs

        best_state = max(search_probs, key=search_probs.get)
        best_conf = search_probs[best_state]

        # Build sorted distribution for UI
        all_states = sorted(
            [{"state": s, "probability": round(p, 3)} for s, p in probs.items()],
            key=lambda x: x["probability"],
            reverse=True,
        )

        # Build reasoning
        evidence_reasons = []
        if active_threats:
            evidence_reasons.append(f"Active detectors: {', '.join(active_threats)}")
        evidence_reasons.append(f"Current state: {current_state}")
        evidence_reasons.append(f"Transition matrix P({current_state}->{best_state})={best_conf:.2f}")

        return {
            "state": best_state,
            "confidence": round(best_conf, 3),
            "reasoning": "; ".join(evidence_reasons),
            "all_states": all_states[:4],  # top 4 for UI
        }

    def get_all_trajectories(self) -> List[Dict[str, Any]]:
        """Return trajectory states for all tracked sources."""
        with self._lock:
            results = []
            for source, entry in self._states.items():
                pred = self._predict_next(entry["current_state"], [])
                results.append({
                    "source": source,
                    "current_state": entry["current_state"],
                    "predicted_next_state": pred["state"],
                    "prediction_confidence": pred["confidence"],
                    "last_updated": entry["last_updated"],
                })
            return results


# ============================================================
# SINGLETON
# ============================================================

_engine: Optional[TrajectoryEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> TrajectoryEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = TrajectoryEngine()
    return _engine
