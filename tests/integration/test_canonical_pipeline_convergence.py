"""
CyberSentinel Canonical Pipeline Convergence Verification Test Suite.

Verifies that all 4 input sources:
  1. Offline Dataset (UWF-ZeekDataSum25)
  2. CSV / Flow Replay (Replayed flow logs)
  3. PCAP Replay (Offline packet captures)
  4. Live Wi-Fi Telemetry (Passive network sensor)

converge into the identical 10-stage processing pipeline:
  NORMALIZED FLOW
  -> FEATURE PIPELINE
  -> DETECTORS
  -> ML
  -> CORRELATION
  -> RISK
  -> EXPLAINABILITY
  -> THREAT STATE
  -> TRAJECTORY
  -> ALERT
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from backend.app.schemas.flow import NormalizedFlow
from backend.app.schemas.threat import DetectionRequest
from backend.app.features.feature_pipeline import extract_features_from_flows
from backend.app.services.alert_service import analyze_request
from backend.app.services.replay_service import replay_flow_csv, replay_dataset_batch
from backend.app.ingestion.pcap_ingest import replay_pcap_to_alerts
from backend.app.ingestion.live_interface import LiveMonitor, Flow


MANDATORY_ALERT_FIELDS = [
    "alert_id",
    "prediction",
    "severity",
    "score",
    "confidence",
    "risk_score",
    "source",
    "time_window",
    "current_state",
    "predicted_next_state",
    "prediction_confidence",
    "inference_latency_ms",
]


def verify_alert_schema(alert: dict, source_name: str):
    """Ensure output conforms exactly to canonical CyberSentinel alert specification."""
    for field in MANDATORY_ALERT_FIELDS:
        assert field in alert, f"[{source_name}] Missing required alert field: '{field}'"
    assert alert["prediction"] in ("BENIGN", "THREAT"), f"[{source_name}] Invalid prediction: {alert['prediction']}"
    assert alert["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), f"[{source_name}] Invalid severity: {alert['severity']}"
    assert isinstance(alert["risk_score"], (int, float)), f"[{source_name}] Invalid risk_score: {alert['risk_score']}"
    assert alert["current_state"] is not None, f"[{source_name}] Missing current_state"
    assert alert["predicted_next_state"] is not None, f"[{source_name}] Missing predicted_next_state"
    print(f"  [PASS] {source_name} alert schema verified: prediction={alert['prediction']} | risk_score={alert['risk_score']} | state={alert['current_state']} -> {alert['predicted_next_state']} ({alert['inference_latency_ms']}ms)")


def test_1_dataset_input():
    print("\n======================================================================")
    print("TEST 1: DATASET INGESTION CONVERGENCE")
    print("======================================================================")
    dataset_file = PROJECT_ROOT / "data" / "modern_2025" / "UWF-ZeekDataSum25-1" / "Benign" / "part-00000-2ac3ee1a-f94a-44bb-9413-dbfa36b751da-c000.csv"
    assert dataset_file.exists(), f"Dataset file missing: {dataset_file}"

    # 1. Dataset -> NORMALIZED FLOW
    df = pd.read_csv(dataset_file, nrows=10)
    flows = [NormalizedFlow.from_zeek_conn(row.to_dict()) for _, row in df.iterrows()]
    assert len(flows) == 10
    assert isinstance(flows[0], NormalizedFlow)
    assert flows[0].source_ip != "0.0.0.0"
    print(f"  1. NORMALIZED FLOW: Ingested {len(flows)} flows from dataset ({flows[0].source_ip} -> {flows[0].destination_ip}:{flows[0].destination_port})")

    # 2. FEATURE PIPELINE
    payload = extract_features_from_flows(flows, window_seconds=5.0)
    assert "ddos_features" in payload
    assert "c2_features" in payload
    print("  2. FEATURE PIPELINE: Extracted canonical behavioral features (DDoS/C2/DNS/Encrypted)")

    # 3. DETECTORS -> 4. ML -> 5. CORRELATION -> 6. RISK -> 7. EXPLAINABILITY -> 8. THREAT STATE -> 9. TRAJECTORY -> 10. ALERT
    req = DetectionRequest(**payload)
    alert = analyze_request(req)
    verify_alert_schema(alert, "Dataset")


def test_2_csv_flow_replay():
    print("\n======================================================================")
    print("TEST 2: CSV / FLOW REPLAY CONVERGENCE")
    print("======================================================================")
    csv_file = PROJECT_ROOT / "data" / "sample" / "small_demo_dataset.csv"
    assert csv_file.exists(), f"CSV file missing: {csv_file}"

    # Execute canonical CSV flow replay pipeline
    alerts = replay_flow_csv(csv_file, window_size=10, window_seconds=5.0)
    assert len(alerts) > 0, "No alerts generated from CSV flow replay"
    alert = alerts[0]
    verify_alert_schema(alert, "CSV / Flow Replay")


def test_3_pcap_replay():
    print("\n======================================================================")
    print("TEST 3: PCAP REPLAY CONVERGENCE")
    print("======================================================================")
    pcap_file = PROJECT_ROOT / "data" / "sample" / "test_sample.pcap"
    assert pcap_file.exists(), f"PCAP file missing: {pcap_file}"

    # Execute canonical PCAP replay pipeline
    alerts = replay_pcap_to_alerts(pcap_file, window_seconds=5.0)
    assert len(alerts) > 0, "No alerts generated from PCAP replay"
    alert = alerts[0]
    verify_alert_schema(alert, "PCAP Replay")


def test_4_live_wifi_telemetry():
    print("\n======================================================================")
    print("TEST 4: LIVE WI-FI TELEMETRY CONVERGENCE")
    print("======================================================================")
    captured_alerts = []

    def mock_alert_callback(payload: dict) -> dict:
        req = DetectionRequest(**payload)
        res = analyze_request(req)
        captured_alerts.append(res)
        return res

    monitor = LiveMonitor(detect_callback=mock_alert_callback, default_window_seconds=1)

    # Feed synthetic observed packets from Wi-Fi interface into monitor
    now = time.time()
    mock_flows = [
        Flow(src="192.168.1.50", dst="142.250.190.46", sport=54321, dport=443, proto="TCP", first_ts=now-2.0, last_ts=now, packets=15, bytes=8000),
        Flow(src="192.168.1.50", dst="8.8.8.8", sport=54322, dport=53, proto="UDP", first_ts=now-1.8, last_ts=now, packets=3, bytes=300),
        Flow(src="192.168.1.50", dst="1.1.1.1", sport=54323, dport=53, proto="UDP", first_ts=now-1.5, last_ts=now, packets=3, bytes=300),
        Flow(src="192.168.1.50", dst="9.9.9.9", sport=54324, dport=53, proto="UDP", first_ts=now-1.2, last_ts=now, packets=3, bytes=300),
    ]

    for f in mock_flows:
        key = (f.src, f.dst, f.sport, f.dport, f.proto)
        monitor._flows[key] = f
    monitor.state.packets_seen = 24
    monitor.state.bytes_seen = 8900

    # Finalize window using canonical feature pipeline
    monitor._finalize_window(force=True)

    assert len(captured_alerts) > 0, "No alerts captured from live Wi-Fi telemetry window"
    alert = captured_alerts[0]
    verify_alert_schema(alert, "Live Wi-Fi Telemetry")


def run_all_convergence_tests():
    print("======================================================================")
    print("CANONICAL PIPELINE CONVERGENCE VERIFICATION")
    print("Verifying 4 Inputs -> 10-Stage Pipeline -> Output Alert")
    print("======================================================================")
    test_1_dataset_input()
    test_2_csv_flow_replay()
    test_3_pcap_replay()
    test_4_live_wifi_telemetry()
    print("\n======================================================================")
    print("ALL 4 INPUT SOURCES SUCCESSFULLY CONVERGE INTO CANONICAL PIPELINE!")
    print("======================================================================")


if __name__ == "__main__":
    run_all_convergence_tests()
