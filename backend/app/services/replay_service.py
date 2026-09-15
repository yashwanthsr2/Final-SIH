"""
CyberSentinel Replay Service.
Houses verified attack scenarios and replay controller.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, EVALUATION_DIR
from backend.app.schemas.flow import NormalizedFlow
from backend.app.schemas.threat import DetectionRequest
from backend.app.features.feature_pipeline import extract_features_from_flows
from backend.app.services.alert_service import analyze_request

def _load_verified_c2() -> Dict[str, float]:
    c2_path = EVALUATION_DIR / "packaging" / "c2_verified_attack_input.csv"
    schema_path = MODELS_DIR / "c2_feature_schema.json"
    if not c2_path.exists() or not schema_path.exists():
        schema_path = MODELS_DIR / "preprocessing" / "c2_feature_schema.json"
    if not c2_path.exists() or not schema_path.exists():
        return {}
    df = pd.read_csv(c2_path)
    if df.empty:
        return {}
    with open(schema_path) as f:
        schema = json.load(f)
    features = schema.get("features", [])
    row = df.iloc[0]
    return {f: float(row[f]) for f in features if f in row.index}

VERIFIED_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "dns": {
        "flow_id": "flow_dns_tunnel_147.32.84.165",
        "source": "147.32.84.165",
        "destination": "8.8.8.8",
        "protocol": "UDP",
        "domain": "tunnel.apt29-data.net",
        "time_window": "2011-08-10T13:33:00",
        "dns_features": {
            "dns_query_count": 2.0,
            "dns_total_packets": 4.0,
            "dns_total_bytes": 793.0,
            "dns_unique_destinations": 1.0,
            "dns_query_rate": 0.2,
            "dns_max_destination_count": 2.0,
            "dns_packet_concentration": 1.0,
            "dns_max_destination_bytes": 793.0,
            "dns_byte_concentration": 1.0,
            "dns_iat_mean": 2.255544,
            "dns_iat_std": 0.0,
            "dns_iat_median": 2.255544,
            "dns_iat_cv": 0.0,
            "query_rate_prev": 0.0,
            "query_rate_roll3": 0.2,
            "query_rate_roll6": 0.2,
            "query_rate_std6": 0.0,
            "query_rate_change": 0.0,
            "query_rate_z6": 0.0,
            "destination_change": 0.0,
            "bytes_per_query": 396.5,
            "packets_per_query": 2.0,
        },
    },
    "c2": {
        "flow_id": "flow_c2_beacon_147.32.84.165",
        "source": "147.32.84.165",
        "destination": "198.51.100.24",
        "protocol": "TCP",
        "time_window": "2011-08-10T15:13:40",
        "c2_features": {
            "flow_count": 595.0,
            "unique_destinations": 73.0,
            "unique_ports": 34.0,
            "total_packets": 8337.0,
            "total_bytes": 4494266.0,
            "mean_packets": 14.011765,
            "mean_bytes": 7553.388235,
            "mean_duration": 356.795946,
            "max_destination_count": 223.0,
            "destination_concentration": 0.37479,
            "iat_mean": 9.602416,
            "iat_std": 80.3288,
            "iat_median": 0.009076,
            "iat_min": 0.000004,
            "iat_max": 1489.884621,
            "iat_cv": 8.365478,
            "max_pair_repetition": 215.0,
            "pair_repetition_ratio": 0.361345,
            "destination_entropy": 2.784545,
        },
    },
    "encrypted": {
        "flow_id": "flow_malware_tls_147.32.84.165",
        "source": "147.32.84.165",
        "destination": "185.220.101.5",
        "protocol": "TCP",
        "time_window": "2011-08-10T11:07:00",
        "encrypted_features": {
            "encrypted_flow_count": 1.0,
            "encrypted_total_packets": 7.0,
            "encrypted_total_bytes": 558.0,
            "encrypted_unique_destinations": 1.0,
            "encrypted_unique_ports": 1.0,
            "encrypted_mean_duration": 9.560554,
            "bytes_per_flow": 558.0,
            "packets_per_flow": 7.0,
            "flow_count_prev": 1.0,
            "flow_count_change": 0.0,
            "bytes_prev": 366.0,
            "bytes_change": 192.0,
            "destination_change": 0.0,
        },
    },
    "recon": {
        "flow_id": "flow_port_scan_10.0.0.45",
        "source": "10.0.0.45",
        "destination": "10.0.0.1",
        "protocol": "TCP",
        "time_window": "2025-01-15T09:22:00",
        "recon_features": {
            "unique_dst_ports": 48,
            "unique_destinations": 12,
            "flow_count": 320,
            "window_seconds": 60.0,
            "total_bytes": 14400,
            "mean_syn_count": 0.85,
            "total_packets": 320,
        },
    },
    "exfil": {
        "flow_id": "flow_exfil_192.168.1.102",
        "source": "192.168.1.102",
        "destination": "203.0.113.88",
        "protocol": "TCP",
        "time_window": "2025-01-15T02:14:00",
        "exfil_features": {
            "bytes_out": 8_500_000,
            "bytes_in": 1_200,
            "unique_destinations": 1,
            "flow_count": 3,
            "mean_flow_duration": 480.0,
            "window_seconds": 600.0,
        },
    },
}

VERIFIED_SCENARIOS["correlated"] = {
    "flow_id": "flow_apt29_c2_147.32.84.165",
    "source": "147.32.84.165",
    "destination": "198.51.100.24",
    "protocol": "TCP",
    "domain": "c2.stealth-ops.org",
    "time_window": "2011-08-10T15:13:40",
    "c2_features": VERIFIED_SCENARIOS["c2"]["c2_features"],
    "dns_features": VERIFIED_SCENARIOS["dns"]["dns_features"],
    "encrypted_features": VERIFIED_SCENARIOS["encrypted"]["encrypted_features"],
}

class ReplayService:
    def __init__(self):
        self.is_running = False
        self.speed = 1.0
        self._lock = threading.Lock()

    def set_speed(self, speed: float) -> None:
        with self._lock:
            self.speed = speed

    def run_scenario(self, scenario_name: str) -> Dict[str, Any]:
        if scenario_name == "ddos":
            # Real DDoS from validation_dos.csv or parquet
            p = EVALUATION_DIR / "packaging" / "verified_attack_input.csv"
            if not p.exists():
                p = PROJECT_ROOT / "data" / "sample" / "small_demo_dataset.csv"
            df = pd.read_csv(p)
            row = df.iloc[0].to_dict()
            numeric = {k: float(v) for k, v in row.items() if isinstance(v, (int, float)) and pd.notnull(v)}
            req = DetectionRequest(
                source="192.168.1.105",
                destination="192.168.1.1",
                protocol="TCP",
                ddos_features=numeric,
            )
            return analyze_request(req)

        data = VERIFIED_SCENARIOS.get(scenario_name)
        if not data:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        req = DetectionRequest(**data)
        return analyze_request(req)


def replay_flow_csv(
    csv_path: Path,
    window_size: int = 50,
    window_seconds: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Replay raw flow records from CSV through the canonical 10-stage pipeline:
    CSV Rows -> NormalizedFlow -> Feature Pipeline -> Detectors -> ML -> Correlation -> Risk -> Explainability -> Threat State -> Trajectory -> Alert.
    """
    p = Path(csv_path)
    if not p.exists():
        raise FileNotFoundError(f"Flow CSV not found: {csv_path}")

    df = pd.read_csv(p)
    if df.empty:
        return []

    flows: List[NormalizedFlow] = []
    for idx, row in df.iterrows():
        row_dict = row.to_dict()
        if "id.orig_h" in row_dict or "src_ip_zeek" in row_dict:
            fl = NormalizedFlow.from_zeek_conn(row_dict)
        else:
            src = str(row_dict.get("source_ip") or row_dict.get("src_ip") or row_dict.get("src") or row_dict.get("SrcAddr") or "192.168.1.100")
            dst = str(row_dict.get("destination_ip") or row_dict.get("dst_ip") or row_dict.get("dst") or row_dict.get("DstAddr") or "10.0.0.1")
            sport = int(row_dict.get("source_port") or row_dict.get("src_port") or row_dict.get("sport") or row_dict.get("Sport") or 0)
            dport = int(row_dict.get("destination_port") or row_dict.get("dst_port") or row_dict.get("dport") or row_dict.get("Dport") or 80)
            proto = str(row_dict.get("protocol") or row_dict.get("proto") or "TCP").upper()
            bytes_val = int(row_dict.get("bytes") or row_dict.get("total_bytes") or row_dict.get("orig_bytes") or row_dict.get("TotBytes") or 500)
            pkts_val = int(row_dict.get("packets") or row_dict.get("total_packets") or row_dict.get("orig_pkts") or row_dict.get("TotPkts") or 1)
            ts = float(row_dict.get("timestamp") or row_dict.get("ts") or time.time())
            dur = float(row_dict.get("duration") or row_dict.get("Dur") or 0.0)

            fl = NormalizedFlow(
                flow_id=f"csv_{idx}_{src}_{sport}",
                timestamp=ts,
                first_ts=ts,
                last_ts=ts + dur,
                source_ip=src,
                destination_ip=dst,
                source_port=sport,
                destination_port=dport,
                protocol=proto,
                duration=dur,
                orig_bytes=bytes_val,
                total_bytes=bytes_val,
                orig_pkts=pkts_val,
                total_packets=pkts_val,
                syn=int(row_dict.get("syn", 0)),
                ack=int(row_dict.get("ack", 0)),
                rst=int(row_dict.get("rst", 0)),
            )
        flows.append(fl)

    alerts: List[Dict[str, Any]] = []
    chunk_size = max(1, window_size)
    for i in range(0, len(flows), chunk_size):
        window_flows = flows[i:i + chunk_size]
        payload = extract_features_from_flows(window_flows, window_seconds=window_seconds)
        req = DetectionRequest(**payload)
        alert = analyze_request(req)
        alerts.append(alert)

    return alerts


def replay_dataset_batch(
    dataset_path: Path,
    limit: int = 100,
    window_seconds: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Replay real offline dataset (e.g. UWF-ZeekDataSum25) through the canonical 10-stage pipeline:
    Dataset Records -> NormalizedFlow -> Feature Pipeline -> Detectors -> ML -> Correlation -> Risk -> Explainability -> Threat State -> Trajectory -> Alert.
    """
    p = Path(dataset_path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset path not found: {p}")

    if p.suffix == ".parquet":
        df = pd.read_parquet(p)
    else:
        df = pd.read_csv(p, nrows=limit)

    if df.empty:
        return []

    flows = [NormalizedFlow.from_zeek_conn(row.to_dict()) for _, row in df.iterrows()]
    payload = extract_features_from_flows(flows, window_seconds=window_seconds)
    req = DetectionRequest(**payload)
    alert = analyze_request(req)
    return [alert]


_replay_service = ReplayService()

def get_replay_service() -> ReplayService:
    return _replay_service
