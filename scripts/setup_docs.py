import os

docs = {
    "architecture.md": """# CyberSentinel System Architecture

## Overview
CyberSentinel is an AI-powered cyber threat intelligence platform developed for the Smart India Hackathon (SIH26-26145 / NTRO).
It is purpose-built to detect, analyze, correlate, and predict advanced threats in unidirectional IP traffic (data diode / passive TAP / live Wi-Fi).

## Canonical Processing Pipeline
```
Network Traffic (Live Wi-Fi / Zeek / PCAP / Parquet)
       │
       ▼
[ Ingestion & Normalizer ]  -->  NormalizedFlow (Vendor-Neutral Metadata)
       │
       ▼
[ Feature Routing Pipeline ]  --> L3/L4, Timing, DNS, TLS, Statistical Features
       │
       ▼
[ Six Threat Detectors + ML ]
  ├── DDoS (HistGradientBoosting)
  ├── C2 Beaconing (RandomForest)
  ├── DNS Tunneling & DGA (RandomForest)
  ├── Encrypted Traffic Anomaly (RandomForest)
  ├── Reconnaissance Engine (Statistical Entropy & SYN Ratio)
  └── Exfiltration Engine (Volume Asymmetry & Ratio)
       │
       ▼
[ Normal Traffic Baseline Profiler ]  --> Suppresses Benign YouTube/Google Downlink
       │
       ▼
[ Threat Correlation Engine ]  --> Multi-signal Kill Chain Pattern Matcher
       │
       ▼
[ Risk Scoring Engine ]  --> Transparent 4-Part Formula (0-100)
       │
       ▼
[ Predictive Trajectory Engine ]  --> Markov State Machine + MITRE ATT&CK Playbooks
       │
       ▼
[ Digital Twin Graph ]  --> In-memory Topology & Node Scoring
       │
       ▼
[ Unified Alert Schema ]  --> SQLite DAL + WebSocket Broadcast + SOC Dashboard
```

## Security Constraints
- Strictly PASSIVE and READ-ONLY
- ZERO packet transmission
- ZERO packet injection
- ZERO external port scanning
- ZERO payload decryption
""",

    "data-pipeline.md": """# CyberSentinel Data Pipeline

## Data Flow
The platform supports 4 heterogeneous traffic inputs that converge into a unified flow model:
1. Live Wi-Fi sniffer (promiscuous mode, non-blocking)
2. Live Zeek sensor (tailing conn.log, dns.log, ssl.log)
3. Offline PCAP replay
4. Machine learning dataset replay (Parquet / CSV)

## Normalization
All inputs are transformed into `NormalizedFlow`, capturing:
- `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`
- Volume metrics: `orig_bytes`, `resp_bytes`, `total_bytes`, `orig_pkts`, `resp_pkts`
- State & History: `conn_state`, `history`, `duration`
- Application Metadata: `dns_query`, `tls_sni`, `service`
""",

    "ml-pipeline.md": """# CyberSentinel Machine Learning Pipeline

## Trained Models
1. **DDoS Model (`dos_hgb.joblib`):**
   - Architecture: `HistGradientBoostingClassifier`
   - Performance: Accuracy=100.0%, F1=100.0%, ROC-AUC=1.0000
   - Features: 62 temporal and flow volume statistics
2. **C2 Beaconing Model (`c2_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: ROC-AUC=0.7087, calibrated threshold 0.30
   - Features: Inter-arrival regularity, byte variance, duration
3. **DNS Threat Model (`dns_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: Accuracy=96.1%, F1=84.1%, ROC-AUC=0.9938
   - Features: Query rates, byte concentration, entropy
4. **Encrypted Anomaly Model (`encrypted_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: ROC-AUC=0.7296
   - Features: Flow duration, bytes-per-flow, port diversity
""",

    "detectors.md": """# CyberSentinel Threat Detection Engines

## Six Threat Classes
1. **DDoS Detector (ML):** Identifies volumetric SYN/UDP/ICMP floods and high-frequency request spikes.
2. **C2 Beaconing Detector (ML):** Detects periodic keep-alive signals and reverse shell beacons.
3. **DNS Tunneling & DGA (ML):** Identifies data exfiltration via TXT/NULL queries and algorithmic domain generation.
4. **Encrypted Malware Detector (ML):** Detects anomalous TLS handshake patterns and outlier byte/packet ratios.
5. **Reconnaissance Engine (Statistical):** Identifies port scans, host sweeps, and horizontal subnet probes.
6. **Exfiltration Engine (Heuristic Asymmetry):** Flags massive outbound byte transfers with minimal inbound response.
""",

    "live-monitoring.md": """# CyberSentinel Live Passive Wi-Fi Monitoring

## Requirements
- Host: Kali Linux / Ubuntu 22.04 / Debian
- Permissions: Elevated root access for socket capture (`sudo`)
- Network: Promiscuous mode on Wi-Fi interface (e.g. `wlan0`)

## Usage
```bash
chmod +x run_kali_sensor.sh
sudo ./run_kali_sensor.sh wlan0 http://127.0.0.1:8000
```
""",

    "alert-schema.md": """# CyberSentinel Unified Alert Schema

## JSON Schema Example
```json
{
  "alert_id": "c1f7a4e2-...",
  "timestamp": 1773489201.5,
  "prediction": "THREAT",
  "severity": "HIGH",
  "score": 0.85,
  "confidence": 0.85,
  "risk_score": 88,
  "primary_threat": "C2",
  "threat_class": "C2",
  "source": "192.168.1.105",
  "destination": "198.51.100.24",
  "protocol": "TCP",
  "current_state": "C2",
  "predicted_next_state": "EXFILTRATION",
  "prediction_confidence": 0.60,
  "correlated": true,
  "correlated_threats": ["RECON", "C2"],
  "correlation_pattern": "RECON_TO_C2",
  "evidence": [
    {"feature": "iat_mean", "value": 9.60, "contribution": 0.35}
  ]
}
```
""",

    "api.md": """# CyberSentinel REST API Documentation

## Core Endpoints
- `GET /health` or `GET /api/health`: System health and passive verification
- `GET /api/metrics`: Performance telemetry, flows count, alert count
- `GET /api/alerts`: Historical alerts with filtering
- `POST /detect`: Synchronous flow analysis through all 6 detectors
- `GET /api/flows`: Flow metadata query
- `GET /api/network`: Digital twin graph topology
- `GET /api/trajectory`: Probabilistic attack predictions
- `GET /api/models`: Model registry status
- `POST /demo/run-all`: Replay full multi-scenario attack suite
""",

    "deployment.md": """# CyberSentinel Deployment Guide

## Standalone Host
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\\Scripts\\activate on Windows
pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

## Docker Compose
```bash
docker compose up --build
```
""",

    "testing.md": """# CyberSentinel Automated Testing Guide

## Running Tests
```bash
# Unit & Security tests
python backend/tests/unit/test_schemas.py
python tests/unit/test_security_audit.py

# Detector tests
python tests/integration/test_six_detectors.py

# Integration & E2E tests
python tests/integration/test_integration.py
python tests/e2e/test_e2e.py

# Benchmark
python tests/performance/benchmark_performance.py
```
""",

    "demo.md": """# CyberSentinel SIH Presentation & Demo Guide

## 5-Minute Live Pitch Walkthrough
1. **Overview Tab:** Highlight real-time passive ingestion and sub-15ms latency.
2. **Demo Attack Trigger:** Click "Trigger Correlated Attack" or run `curl -X POST http://127.0.0.1:8000/demo/run-all`.
3. **Threat Center:** Show multi-engine detections with SHAP feature evidence.
4. **Network Graph:** Demonstrate the Digital Twin highlighting compromised nodes in red.
5. **Attack Trajectory:** Explain Markov predictions and automated MITRE ATT&CK mitigation playbooks.
6. **Live Wi-Fi Mode:** Demonstrate background YouTube learning suppressing false alarms while catching real exfiltration.
"""
}

os.makedirs('docs', exist_ok=True)
for filename, content in docs.items():
    with open(f'docs/{filename}', 'w', encoding='utf-8') as f:
        f.write(content.strip() + '\n')

print('All 10 documentation files generated in docs/.')
