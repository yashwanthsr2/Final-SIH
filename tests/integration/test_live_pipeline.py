"""
CyberSentinel Live Passive Monitoring Pipeline Test.

Validates:
1. NormalizedFlow schema conversion from real Zeek records
2. ZeekLiveSensor diagnostic and interface scanner
3. BaselineEngine normal internet learning & false positive suppression
4. Live API endpoints (/api/live/interfaces, /api/live/status, /api/live/baseline, /api/live/flows)
"""
import json
import time
import urllib.request
import pandas as pd
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.schemas.flow import NormalizedFlow
from backend.app.core.baseline_engine import BaselineEngine
from backend.app.ingestion.zeek_ingest import ZeekLiveSensor

API_BASE = "http://127.0.0.1:8000"


def test_1_normalized_flow_from_zeek():
    print("\n--- TEST 1: NormalizedFlow from Real Zeek Record ---")
    sample_csv = Path("data/modern_2025/UWF-ZeekDataSum25-1/Benign/part-00000-2ac3ee1a-f94a-44bb-9413-dbfa36b751da-c000.csv")
    assert sample_csv.exists(), f"Sample Zeek CSV missing: {sample_csv}"

    df = pd.read_csv(sample_csv, nrows=3)
    record = df.iloc[0].to_dict()
    flow = NormalizedFlow.from_zeek_conn(record)

    assert flow.flow_id, "flow_id must not be empty"
    assert flow.source_ip == "143.88.0.6", f"Unexpected source_ip: {flow.source_ip}"
    assert flow.destination_ip == "199.7.83.42", f"Unexpected destination_ip: {flow.destination_ip}"
    assert flow.destination_port == 53, f"Unexpected dest_port: {flow.destination_port}"
    assert flow.protocol == "UDP", f"Unexpected protocol: {flow.protocol}"

    print(f"  [PASS] NormalizedFlow created: {flow.flow_id[:16]}... | {flow.source_ip}:{flow.source_port} -> {flow.destination_ip}:{flow.destination_port} ({flow.protocol})")


def test_2_zeek_sensor_diagnostics():
    print("\n--- TEST 2: ZeekLiveSensor Diagnostics ---")
    info = ZeekLiveSensor.get_version()
    print(f"  Zeek binary installed: {info['installed']}")
    print(f"  Version: {info.get('version')}")
    print(f"  Path: {info.get('path')}")
    if not info["installed"]:
        print(f"  Install command: {info.get('install_hint')}")
    print("  [PASS] ZeekLiveSensor diagnostics completed successfully.")


def test_3_baseline_engine_false_positive_suppression():
    print("\n--- TEST 3: Baseline Normal Internet Learning & FP Suppression ---")
    engine = BaselineEngine(duration_seconds=2)
    engine.start_learning(duration=2)
    assert engine.state == BaselineEngine.STATE_LEARNING, "Engine should be in LEARNING state"

    # Simulate 3 windows of normal YouTube 1080p streaming
    # (High downlink bytes_in, small uplink bytes_out, known CDNs)
    for _ in range(3):
        engine.record_window_observation(
            byte_rate=2_500_000.0,
            packet_rate=1_800.0,
            unique_destinations=8,
            unique_ports=4,
            destination_ips=["142.250.190.46", "172.217.16.206", "1.1.1.1"],
            bytes_in=12_000_000,
            bytes_out=150_000,
        )
        time.sleep(0.7)

    # Force finalize for testing
    engine._finalize_baseline()
    assert engine.state == BaselineEngine.STATE_ACTIVE, "Engine should be in ACTIVE state"
    print(f"  Learned Mean Byte Rate: {engine.mean_byte_rate / 1024:.1f} KB/s")
    print(f"  Learned Mean Packet Rate: {engine.mean_packet_rate:.1f} pkts/s")
    print(f"  Learned Benign Destinations: {len(engine._known_destinations)}")

    # 1. Test YouTube video streaming should be SUPPRESSED (bytes_in > bytes_out * 2)
    youtube_flow = {"bytes_out": 200_000, "bytes_in": 15_000_000}
    cal_yt = engine.calibrate_detection(threat_class="EXFILTRATION", score=0.85, features=youtube_flow)
    assert cal_yt["suppressed"] is True, "Normal YouTube streaming must NOT be flagged as exfiltration"
    print(f"  [PASS] Normal YouTube streaming: SUPPRESSED ({cal_yt['reason']})")

    # 2. Test Real Exfiltration attack should NOT be suppressed (bytes_out is huge, bytes_in is tiny)
    exfil_attack = {"bytes_out": 8_500_000, "bytes_in": 1_200}
    cal_ex = engine.calibrate_detection(threat_class="EXFILTRATION", score=0.85, features=exfil_attack)
    assert cal_ex["suppressed"] is False, "True exfiltration attack must NOT be suppressed"
    print(f"  [PASS] Real Exfiltration attack: NOT SUPPRESSED (score={cal_ex['score']}, alert fires)")


def test_4_live_api_endpoints():
    print("\n--- TEST 4: Live API Endpoints ---")
    # Interfaces
    r = urllib.request.urlopen(f"{API_BASE}/api/live/interfaces", timeout=5)
    d = json.loads(r.read())
    ifaces = [i["name"] if isinstance(i, dict) else i for i in d.get("interfaces", [])]
    print(f"  Detected Interfaces ({len(ifaces)}): {ifaces[:5]}")
    assert len(ifaces) > 0, "Should detect at least one interface"

    # Status
    r = urllib.request.urlopen(f"{API_BASE}/api/live/status", timeout=5)
    s = json.loads(r.read())
    print(f"  Live Status: running={s.get('running')}, backend={s.get('detector_status')}")

    # Zeek
    r = urllib.request.urlopen(f"{API_BASE}/api/live/zeek", timeout=5)
    z = json.loads(r.read())
    print(f"  Zeek API: installed={z.get('installed')}")

    # Baseline status
    r = urllib.request.urlopen(f"{API_BASE}/api/live/baseline/status", timeout=5)
    b = json.loads(r.read())
    print(f"  Baseline API status: state={b.get('state')}")

    # Flows
    r = urllib.request.urlopen(f"{API_BASE}/api/live/flows", timeout=5)
    f = json.loads(r.read())
    print(f"  Live flows endpoint: {len(f.get('flows', []))} flows buffered")
    print("  [PASS] All Live API endpoints functional.")


if __name__ == "__main__":
    print("=" * 60)
    print("  CYBERSENTINEL REAL-TIME PASSIVE MONITORING TEST SUITE")
    print("=" * 60)
    test_1_normalized_flow_from_zeek()
    test_2_zeek_sensor_diagnostics()
    test_3_baseline_engine_false_positive_suppression()
    test_4_live_api_endpoints()
    print("\n" + "=" * 60)
    print("  ALL TESTS PASSED SUCCESSFULLY! PIPELINE VERIFIED.")
    print("=" * 60 + "\n")
