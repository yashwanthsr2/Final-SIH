"""
CyberSentinel Comprehensive Performance Benchmark Script.
Measures:
  1. Ingestion latency (parsing Zeek record -> NormalizedFlow)
  2. Feature extraction latency
  3. Individual detector ML / rule inference latency (all 6)
  4. Correlation & risk scoring latency
  5. Trajectory prediction latency
  6. End-to-end unified detection pipeline throughput (flows/sec) and latency (ms)
"""

import time
import numpy as np
import pandas as pd
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.schemas.flow import NormalizedFlow
from backend.app.services.alert_service import run_detector, analyze_request
from backend.app.schemas.threat import DetectionRequest
from backend.app.correlation import get_engine as get_corr
from backend.app.risk import calculate_risk_score
from backend.app.prediction import get_engine as get_traj
from backend.app.digital_twin import get_twin

def run_benchmark():
    print("=" * 65)
    print("      CYBERSENTINEL PERFORMANCE & LATENCY BENCHMARK")
    print("=" * 65)
    
    # Sample Zeek raw log record
    sample_raw = {
        "uid": "Cbench001",
        "id.orig_h": "192.168.1.55",
        "id.orig_p": 49152,
        "id.resp_h": "203.0.113.10",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 0.45,
        "orig_bytes": 1250,
        "resp_bytes": 8400,
        "orig_pkts": 12,
        "resp_pkts": 18,
        "history": "ShADadFf",
        "conn_state": "SF"
    }

    # 1. Ingestion & Feature Extraction Latency
    iters = 1000
    t0 = time.perf_counter()
    for _ in range(iters):
        nf = NormalizedFlow.from_zeek_conn(sample_raw)
    t1 = time.perf_counter()
    ingest_lat_us = ((t1 - t0) / iters) * 1_000_000
    print(f"1. Ingestion & Normalization: {ingest_lat_us:.2f} us/flow ({iters / (t1 - t0):.1f} flows/sec)")

    # Load dataset features for detectors
    def to_float_dict(row):
        res = {}
        for k, v in row.items():
            try:
                if not isinstance(v, (str, bytes)) and pd.notnull(v):
                    res[k] = float(v)
            except (ValueError, TypeError):
                pass
        return res

    df_ddos = pd.read_parquet("data/processed/ddos_features.parquet")
    df_c2 = pd.read_parquet("data/processed/c2_features.parquet")
    df_dns = pd.read_parquet("data/processed/dns_source_features.parquet")
    df_enc = pd.read_parquet("data/processed/encrypted_source_features.parquet")

    f_ddos = to_float_dict(df_ddos.iloc[0].to_dict())
    f_c2 = to_float_dict(df_c2.iloc[0].to_dict())
    f_dns = to_float_dict(df_dns.iloc[0].to_dict())
    f_enc = to_float_dict(df_enc.iloc[0].to_dict())

    f_recon = {
        "unique_dst_ports": 65,
        "unique_destinations": 14,
        "flow_count": 350,
        "mean_syn_count": 0.92,
        "total_packets": 350,
        "total_bytes": 14000,
        "window_seconds": 60.0
    }
    f_exfil = {
        "bytes_out": 25000000,
        "bytes_in": 1500,
        "unique_destinations": 1,
        "flow_count": 4,
        "mean_flow_duration": 500.0,
        "window_seconds": 600.0
    }

    test_features = {
        "DDoS": f_ddos,
        "C2": f_c2,
        "DNS": f_dns,
        "ENCRYPTED_TRAFFIC": f_enc,
        "RECON": f_recon,
        "EXFILTRATION": f_exfil,
    }

    # 2. Individual Detector Inference Latency
    print("\n--- 2. Individual Detector Latency (200 runs each) ---")
    det_latencies = {}
    for det, feats in test_features.items():
        # warm up
        run_detector(det, feats)
        
        t_start = time.perf_counter()
        n_runs = 200
        for _ in range(n_runs):
            run_detector(det, feats)
        t_end = time.perf_counter()
        lat_ms = ((t_end - t_start) / n_runs) * 1000
        det_latencies[det] = lat_ms
        print(f"  Detector [{det:18}]: {lat_ms:.3f} ms/eval ({1000/lat_ms:.1f} evals/sec)")

    # 3. Correlation & Risk Scoring
    print("\n--- 3. Correlation & Risk Scoring Latency ---")
    corr = get_corr()
    t_start = time.perf_counter()
    for _ in range(iters):
        r = calculate_risk_score(confidence=0.85, severity="HIGH", threat_class="C2", correlated_detector_count=2)
    t_end = time.perf_counter()
    risk_lat_us = ((t_end - t_start) / iters) * 1_000_000
    print(f"  Risk Scoring Engine:        {risk_lat_us:.2f} us/eval ({iters / (t_end - t_start):.1f} evals/sec)")

    # 4. Trajectory Prediction
    traj = get_traj()
    t_start = time.perf_counter()
    for _ in range(iters):
        tr = traj.get_trajectory("192.168.1.55")
    t_end = time.perf_counter()
    traj_lat_us = ((t_end - t_start) / iters) * 1_000_000
    print(f"  Trajectory Prediction Engine: {traj_lat_us:.2f} us/eval ({iters / (t_end - t_start):.1f} evals/sec)")

    # 5. Full End-to-End Unified Pipeline Latency
    print("\n--- 4. Full End-to-End Pipeline (Ingestion -> 6 Detectors -> Fusion -> Risk -> Trajectory -> Twin -> DB) ---")
    n_e2e = 50
    req = DetectionRequest(
        source="192.168.1.55",
        ddos_features=f_ddos,
        c2_features=f_c2,
        dns_features=f_dns,
        encrypted_features=f_enc,
        recon_features=f_recon,
        exfil_features=f_exfil,
    )
    # warm up
    analyze_request(req)
    
    t_start = time.perf_counter()
    for i in range(n_e2e):
        req_i = DetectionRequest(
            source=f"192.168.1.{i%50}",
            ddos_features=f_ddos,
            c2_features=f_c2,
            dns_features=f_dns,
            encrypted_features=f_enc,
            recon_features=f_recon,
            exfil_features=f_exfil,
        )
        analyze_request(req_i)
    t_end = time.perf_counter()
    e2e_lat_ms = ((t_end - t_start) / n_e2e) * 1000
    throughput = n_e2e / (t_end - t_start)
    
    print(f"  Full Pipeline Latency:      {e2e_lat_ms:.2f} ms/request")
    print(f"  Full Pipeline Throughput:   {throughput:.1f} requests/sec")
    print("=" * 65)

if __name__ == "__main__":
    run_benchmark()
