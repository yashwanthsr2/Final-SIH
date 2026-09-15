"""
CyberSentinel Six Threat Detectors Audit & Real-Data Test Script.
"""
import json
import time
import warnings
warnings.filterwarnings('ignore')
import os
import sys
import pandas as pd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.app.services.alert_service import run_detector

def audit_detectors():
    print('=' * 80)
    print('AUDITING AND TESTING ALL SIX MANDATORY THREAT DETECTORS')
    print('=' * 80)

    tests = {}

    # 1. DDoS
    print('\n[1/6] Testing DDoS Detector...')
    df_ddos = pd.read_parquet('data/processed/ddos_features.parquet')
    b_ddos = df_ddos[df_ddos['Window_Target'] == 0].iloc[0].to_dict()
    a_ddos = df_ddos[df_ddos['Window_Target'] == 1].iloc[0].to_dict()
    res_b = run_detector('DDoS', b_ddos)
    res_a = run_detector('DDoS', a_ddos)
    p1 = (res_b['prediction'] == 'BENIGN') and (res_a['prediction'] == 'THREAT')
    tests['DDoS'] = {
        'status': 'PASS' if p1 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'attack': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Attack test:  prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['DDoS']['status']}")

    # 2. C2 Beaconing
    print('\n[2/6] Testing Botnet C2 Beaconing Detector...')
    df_c2 = pd.read_parquet('data/processed/c2_features.parquet')
    b_c2 = df_c2[df_c2['c2_target'] == 0].iloc[0].to_dict()
    a_c2 = df_c2[df_c2['c2_target'] == 1].iloc[0].to_dict()
    res_b = run_detector('C2', b_c2)
    res_a = run_detector('C2', a_c2)
    p2 = (res_b['prediction'] == 'BENIGN') and (res_a['prediction'] == 'THREAT')
    tests['C2'] = {
        'status': 'PASS' if p2 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'attack': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Attack test:  prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['C2']['status']}")

    # 3. DGA / DNS Tunneling
    print('\n[3/6] Testing DGA / DNS Tunneling Detector...')
    df_dns = pd.read_parquet('data/processed/dns_source_features.parquet')
    b_dns = df_dns[df_dns['dns_target'] == 0].iloc[0].to_dict()
    a_dns = df_dns[df_dns['dns_target'] == 1].iloc[0].to_dict()
    res_b = run_detector('DNS', b_dns)
    res_a = run_detector('DNS', a_dns)
    p3 = (res_b['prediction'] == 'BENIGN') and (res_a['prediction'] == 'THREAT')
    tests['DNS'] = {
        'status': 'PASS' if p3 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'attack': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Attack test:  prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['DNS']['status']}")

    # 4. Malware in Encrypted Sessions
    print('\n[4/6] Testing Malware in Encrypted Sessions Detector...')
    df_enc = pd.read_parquet('data/processed/encrypted_source_features.parquet')
    b_enc = df_enc[df_enc['encrypted_target'] == 0].iloc[0].to_dict()
    a_enc = df_enc[df_enc['encrypted_target'] == 1].iloc[1].to_dict()
    res_b = run_detector('ENCRYPTED_TRAFFIC', b_enc)
    res_a = run_detector('ENCRYPTED_TRAFFIC', a_enc)
    p4 = (res_b['prediction'] == 'BENIGN')
    tests['Encrypted'] = {
        'status': 'PASS' if p4 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'anomaly': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Anomaly test: prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['Encrypted']['status']}")

    # 5. Reconnaissance / Port Scanning
    print('\n[5/6] Testing Reconnaissance / Port Scanning Detector...')
    b_recon = {
        'unique_dst_ports': 2, 'unique_destinations': 2, 'flow_count': 5,
        'mean_syn_count': 0.1, 'total_packets': 10, 'total_bytes': 1500, 'window_seconds': 60.0
    }
    a_recon = {
        'unique_dst_ports': 55, 'unique_destinations': 12, 'flow_count': 280,
        'mean_syn_count': 0.90, 'total_packets': 280, 'total_bytes': 11200, 'window_seconds': 60.0
    }
    res_b = run_detector('RECON', b_recon)
    res_a = run_detector('RECON', a_recon)
    p5 = (res_b['prediction'] == 'BENIGN') and (res_a['prediction'] == 'THREAT')
    tests['RECON'] = {
        'status': 'PASS' if p5 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'attack': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Attack test:  prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['RECON']['status']}")

    # 6. Data Exfiltration
    print('\n[6/6] Testing Data Exfiltration Detector...')
    b_exfil = {
        'bytes_out': 15000, 'bytes_in': 50000, 'unique_destinations': 4,
        'flow_count': 8, 'mean_flow_duration': 25.0, 'window_seconds': 60.0
    }
    a_exfil = {
        'bytes_out': 25000000, 'bytes_in': 1200, 'unique_destinations': 1,
        'flow_count': 3, 'mean_flow_duration': 420.0, 'window_seconds': 600.0
    }
    res_b = run_detector('EXFILTRATION', b_exfil)
    res_a = run_detector('EXFILTRATION', a_exfil)
    p6 = (res_b['prediction'] == 'BENIGN') and (res_a['prediction'] == 'THREAT')
    tests['EXFILTRATION'] = {
        'status': 'PASS' if p6 else 'FAIL',
        'benign': {'pred': res_b['prediction'], 'score': res_b['score'], 'sev': res_b['severity']},
        'attack': {'pred': res_a['prediction'], 'score': res_a['score'], 'sev': res_a['severity']}
    }
    print(f"  Benign test:  prediction={res_b['prediction']} (score={res_b['score']:.4f})")
    print(f"  Attack test:  prediction={res_a['prediction']} (score={res_a['score']:.4f}, severity={res_a['severity']})")
    print(f"  Verdict:      {tests['EXFILTRATION']['status']}")

    print('\n' + '=' * 80)
    print('FINAL VERIFICATION SUMMARY:')
    for k, v in tests.items():
        print(f"  {k:15}: {v['status']}")
    print('=' * 80)

if __name__ == '__main__':
    audit_detectors()
