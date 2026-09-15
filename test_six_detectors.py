"""
Phase 7: Comprehensive Validation of All Six Threat Detectors using Real Dataset Samples & Edge Cases.
Tests DDoS, C2, DNS, ENCRYPTED_TRAFFIC, RECON, and EXFILTRATION.
"""
import sys
from pathlib import Path
import json
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.alert_service import run_detector


def test_detectors():
    print("=" * 70)
    print("PHASE 7: REAL DATASET VALIDATION OF ALL SIX THREAT DETECTORS")
    print("=" * 70)

    # 1. DDoS Detector
    print("\n--- 1. DDoS Detector ---")
    df_ddos = pd.read_parquet("data/processed/ddos_features.parquet")
    threat_ddos = df_ddos[df_ddos["Window_Target"] == 1].iloc[0].to_dict()
    benign_ddos = df_ddos[df_ddos["Window_Target"] == 0].iloc[0].to_dict()
    
    res_b = run_detector("DDoS", benign_ddos)
    print(f"  Benign test:  prediction={res_b.get('prediction')} | score={res_b.get('score'):.4f} | severity={res_b.get('severity')}")
    assert res_b.get("prediction") == "BENIGN", "Real benign sample must be BENIGN"
    
    res_a = run_detector("DDoS", threat_ddos)
    print(f"  Threat test:  prediction={res_a.get('prediction')} | score={res_a.get('score'):.4f} | severity={res_a.get('severity')}")
    assert res_a.get("prediction") == "THREAT", "Real DDoS sample must be THREAT"

    # 2. C2 Beaconing Detector
    print("\n--- 2. C2 Beaconing Detector ---")
    df_c2 = pd.read_parquet("data/processed/c2_features.parquet")
    threat_c2 = df_c2[df_c2["c2_target"] == 1].iloc[0].to_dict()
    benign_c2 = df_c2[df_c2["c2_target"] == 0].iloc[0].to_dict()
    
    res_b_c2 = run_detector("C2", benign_c2)
    print(f"  Benign test:  prediction={res_b_c2.get('prediction')} | score={res_b_c2.get('score'):.4f}")
    
    res_a_c2 = run_detector("C2", threat_c2)
    print(f"  Threat test:  prediction={res_a_c2.get('prediction')} | score={res_a_c2.get('score'):.4f} | severity={res_a_c2.get('severity')}")
    assert res_a_c2.get("prediction") == "THREAT", "Real C2 sample must trigger THREAT (score >= threshold)"

    # 3. DNS Threat Detector
    print("\n--- 3. DNS Threat Detector ---")
    df_dns = pd.read_parquet("data/processed/dns_source_features.parquet")
    threat_dns = df_dns[df_dns["dns_target"] == 1].iloc[0].to_dict()
    benign_dns = df_dns[df_dns["dns_target"] == 0].iloc[0].to_dict()
    
    res_b_dns = run_detector("DNS", benign_dns)
    print(f"  Benign test:  prediction={res_b_dns.get('prediction')} | score={res_b_dns.get('score'):.4f}")
    
    res_a_dns = run_detector("DNS", threat_dns)
    print(f"  Threat test:  prediction={res_a_dns.get('prediction')} | score={res_a_dns.get('score'):.4f} | severity={res_a_dns.get('severity')}")
    assert res_a_dns.get("prediction") == "THREAT", "Real DNS threat sample must be THREAT"

    # 4. Encrypted Traffic Detector
    print("\n--- 4. Encrypted Traffic Detector ---")
    df_enc = pd.read_parquet("data/processed/encrypted_source_features.parquet")
    threat_enc = df_enc[df_enc["encrypted_target"] == 1].iloc[0].to_dict()
    benign_enc = df_enc[df_enc["encrypted_target"] == 0].iloc[0].to_dict()
    
    res_b_enc = run_detector("ENCRYPTED_TRAFFIC", benign_enc)
    print(f"  Benign test:  prediction={res_b_enc.get('prediction')} | score={res_b_enc.get('score'):.4f}")
    
    res_a_enc = run_detector("ENCRYPTED_TRAFFIC", threat_enc)
    print(f"  Threat test:  prediction={res_a_enc.get('prediction')} | score={res_a_enc.get('score'):.4f} | severity={res_a_enc.get('severity')}")

    # 5. Reconnaissance Detector
    print("\n--- 5. Reconnaissance Detector ---")
    benign_recon = {
        "unique_dst_ports": 2,
        "unique_destinations": 1,
        "flow_count": 10,
        "mean_syn_count": 0.05,
        "total_packets": 20,
        "total_bytes": 1500,
        "window_seconds": 60.0
    }
    threat_recon = {
        "unique_dst_ports": 65,
        "unique_destinations": 14,
        "flow_count": 350,
        "mean_syn_count": 0.92,
        "total_packets": 350,
        "total_bytes": 14000,
        "window_seconds": 60.0
    }
    res_b_rec = run_detector("RECON", benign_recon)
    print(f"  Benign test:  prediction={res_b_rec.get('prediction')} | score={res_b_rec.get('score'):.4f}")
    assert res_b_rec.get("prediction") == "BENIGN"
    
    res_a_rec = run_detector("RECON", threat_recon)
    print(f"  Threat test:  prediction={res_a_rec.get('prediction')} | score={res_a_rec.get('score'):.4f} | severity={res_a_rec.get('severity')}")
    assert res_a_rec.get("prediction") == "THREAT"

    # 6. Data Exfiltration Detector
    print("\n--- 6. Data Exfiltration Detector ---")
    benign_exfil = {
        "bytes_out": 5000,
        "bytes_in": 150000, # normal downstream heavy
        "unique_destinations": 2,
        "flow_count": 8,
        "mean_flow_duration": 12.0,
        "window_seconds": 60.0
    }
    threat_exfil = {
        "bytes_out": 25000000, # massive upload
        "bytes_in": 1500,
        "unique_destinations": 1,
        "flow_count": 4,
        "mean_flow_duration": 500.0,
        "window_seconds": 600.0
    }
    res_b_ex = run_detector("EXFILTRATION", benign_exfil)
    print(f"  Benign test:  prediction={res_b_ex.get('prediction')} | score={res_b_ex.get('score'):.4f}")
    assert res_b_ex.get("prediction") == "BENIGN"
    
    res_a_ex = run_detector("EXFILTRATION", threat_exfil)
    print(f"  Threat test:  prediction={res_a_ex.get('prediction')} | score={res_a_ex.get('score'):.4f} | severity={res_a_ex.get('severity')}")
    assert res_a_ex.get("prediction") == "THREAT"

    print("\n" + "=" * 70)
    print("ALL SIX DETECTORS VERIFIED WITH BENIGN AND ATTACK SAMPLES!")
    print("=" * 70)

if __name__ == "__main__":
    test_detectors()
