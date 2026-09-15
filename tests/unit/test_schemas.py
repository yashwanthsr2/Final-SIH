"""
CyberSentinel Schema Unit Tests.
Validates NormalizedFlow creation and UnifiedAlert schema integrity.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.schemas.flow import NormalizedFlow
from backend.app.schemas.alert import UnifiedAlert


def test_normalized_flow_creation():
    nf = NormalizedFlow(flow_id="test1", source_ip="192.168.1.10", destination_ip="8.8.8.8")
    assert nf.source_ip == "192.168.1.10"
    assert nf.total_packets == 0


def test_unified_alert():
    al = UnifiedAlert(prediction="BENIGN", severity="LOW", score=0.0)
    assert al.prediction == "BENIGN"
    assert al.severity == "LOW"


if __name__ == "__main__":
    test_normalized_flow_creation()
    test_unified_alert()
    print("Unit tests passed: NormalizedFlow and UnifiedAlert schemas validated.")
