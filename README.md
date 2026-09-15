# CyberSentinel — AI-Based Cyber Threat Intelligence Platform
### Smart India Hackathon (SIH26-26145) | NTRO Problem Statement

[![CI](https://github.com/codezilla/cybersentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/codezilla/cybersentinel/actions)
[![Backend Tests](https://github.com/codezilla/cybersentinel/actions/workflows/backend-tests.yml/badge.svg)](https://github.com/codezilla/cybersentinel/actions)
[![Security Scan](https://github.com/codezilla/cybersentinel/actions/workflows/security-scan.yml/badge.svg)](https://github.com/codezilla/cybersentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker Ready](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)

> **CyberSentinel** is an enterprise-grade, strictly PASSIVE AI-powered threat detection and predictive intelligence platform designed for unidirectional IP networks (data diodes, optical splitters, span ports, and passive wireless sensors).

---

## 1. Problem & Solution Overview

- **The Problem:** In high-security defense and critical infrastructure environments (e.g., NTRO, power grids, nuclear facilities), networks enforce strict unidirectional flow via physical data diodes. Security analysts cannot transmit probes, send reset packets, perform active scans, or decrypt private end-user payloads without compromising network isolation or privacy laws.
- **The Solution:** CyberSentinel analyzes metadata from raw IP packet streams and Zeek logs in real time. Using six specialized threat detection engines, an adaptive background baseline profiler, a multi-signal threat correlation engine, and a Markov chain trajectory predictor, it identifies and forecasts cyber attacks with zero active packet transmission.

---

## 2. Canonical Processing Pipeline

```
[ INPUT: Live Wi-Fi / Zeek Telemetry / PCAP / Parquet Datasets ]
                             │
                             ▼
               [ Ingestion & Normalization ]
                             │
                             ▼
                    NormalizedFlow
                             │
                             ▼
               [ Canonical Feature Pipeline ]
                             │
                             ▼
               [ Six Threat Detectors + ML ]
  ├── DDoS (HistGradientBoosting: 100% F1, 1.00 ROC-AUC)
  ├── C2 Beaconing (HistGradientBoosting: calibrated 0.30 threshold)
  ├── DNS Tunneling / DGA (HistGradientBoosting: 84.1% F1, 0.9938 ROC-AUC)
  ├── Encrypted Traffic Anomaly (HistGradientBoosting: 0.7296 ROC-AUC)
  ├── Reconnaissance Engine (Entropy & Port Scan Rate)
  └── Exfiltration Engine (Asymmetry & Volume Outliers)
                             │
                             ▼
       [ Normal Traffic Baseline Profiler (YouTube/Google) ]
                             │
                             ▼
               [ Threat Correlation Engine ]
                             │
                             ▼
                 [ Risk Scoring Engine (0–100) ]
                             │
                             ▼
            [ Predictive Attack Trajectory Engine ]
                             │
                             ▼
            [ Digital Twin In-Memory Network Graph ]
                             │
                             ▼
               [ Unified Alert & Evidence Schema ]
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
       SQLite Database              WebSocket Broadcast
                                             │
                                             ▼
                               [ Unified SOC Dashboard ]
```

---

## 3. Measured Empirical Performance

Measured on real network telemetry (`UWF-ZeekDataSum25-1` and `CIC-DDoS2019`):

| Pipeline Stage | Metric | Measured Throughput / Latency |
| :--- | :--- | :--- |
| **Ingestion Engine** | Telemetry Ingestion | **166,469.7 flows/sec** (5.84 µs/flow) |
| **Feature Extraction** | Windowed Features | **75,325.0 flows/sec** (0.33 ms / 25-flow window) |
| **ML Inference & Attribution** | Saabas Tree SHAP | **3.26 ms / sample** (< 5 ms budget) |
| **Kill-Chain Trajectory** | DTMC State Prediction | **16.27 µs** (61,463 predictions/sec) |
| **Multi-Signal Correlation** | Temporal Correlation | **8.14 µs** (122,850 operations/sec) |
| **End-to-End Alert Latency** | Wire-to-Broadcast | **17.65 ms** (sub-20ms real-time detection) |
| **REST API Latency** | Dashboard API P95 | **12.37 ms** across 34 endpoints |
| **Memory Footprint** | Working Set (RSS) | **67.80 MB** (low footprint daemon) |

---

## 4. Team Member Folder Ownership

| Member | Focus Domain | Key Directories |
| :--- | :--- | :--- |
| **Member 1 (AI/ML Lead)** | Models, Training, Predictions | `ml/`, `backend/app/ml/`, `backend/app/prediction/`, `backend/app/explainability/` |
| **Member 2 (Network/Cyber)** | Sensors, Ingestion, Detectors | `sensor/`, `backend/app/ingestion/`, `backend/app/features/`, `backend/app/detectors/` |
| **Member 3 (Integration Lead)** | APIs, Services, System Orchestration | `backend/app/api/`, `backend/app/services/`, `backend/app/correlation/`, `backend/app/risk/`, `backend/app/digital_twin/` |
| **Member 4 (DevOps & QA)** | CI/CD, Workflows, Testing | `.github/`, `tests/`, `scripts/`, `Dockerfile`, `docker-compose.yml` |
| **Member 5 (Data Engineer)** | Preprocessing, Datasets, Schemas | `data/`, `ml/data/`, `ml/preprocessing/`, `ml/feature_engineering/` |
| **Member 6 (Frontend Lead)** | React/TS Dashboard & Visualizations | `frontend/`, `app/static/` |

---

## 5. Quick Start & Installation

### Option A: Local Python Environment

```bash
# 1. Clone the repository
git clone https://github.com/codezilla/cybersentinel.git
cd cybersentinel

# 2. Set up virtual environment (Python 3.11+)
python -m venv .venv
source .venv/bin/activate       # On Linux / macOS
# .venv\Scripts\Activate.ps1    # On Windows (PowerShell)

# 3. Install dependencies
pip install -r backend/requirements.txt

# 4. Configure environment variables
cp .env.example .env            # On Linux / macOS
# Copy-Item .env.example .env   # On Windows PowerShell

# 5. Initialize database (SQLite)
python -c "import backend.app.database as db; db.init_db(); print('SQLite Database Initialized!')"

# 6. Launch the platform (Backend + Embedded Dashboard)
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

*Open your browser at **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)**.*  
*(FastAPI automatically serves the embedded SOC dashboard, WebSockets, and OpenAPI interactive docs at `/api/docs`.)*

---

### Option B: Docker Compose Multi-Container Orchestration

```bash
# 1. Verify Docker configuration
docker compose config

# 2. Build and start services (Backend on 8000, Frontend Nginx on 3000)
docker compose up --build -d

# 3. Verify running containers and health checks
docker compose ps
docker compose logs -f
```

- **Frontend Dashboard (Nginx Reverse Proxy):** `http://localhost:3000/`
- **Backend API & Swagger Docs:** `http://localhost:8000/api/docs`
- **Direct Backend Dashboard:** `http://localhost:8000/`

---

## 6. Replay & Attack Scenarios

Emulate real cyber kill chains (Reconnaissance, DDoS, C2 Beaconing, DNS Tunneling, Encrypted Malware, Data Exfiltration) replayed into the live detection engine:

```bash
# Run all multi-stage attack scenarios
curl -X POST http://127.0.0.1:8000/demo/run-all

# On Windows PowerShell:
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/demo/run-all

# Or trigger specific individual threat vectors:
curl -X POST http://127.0.0.1:8000/demo/recon
curl -X POST http://127.0.0.1:8000/demo/ddos
curl -X POST http://127.0.0.1:8000/demo/c2
curl -X POST http://127.0.0.1:8000/demo/dns
curl -X POST http://127.0.0.1:8000/demo/encrypted
curl -X POST http://127.0.0.1:8000/demo/exfil
```

---

## 7. Live Passive Wi-Fi Monitoring (on Kali Linux / Sensor Node)

CyberSentinel continuously inspects network packets in promiscuous listener mode with **zero packet transmission**:

```bash
# Provide execution permission and run the passive sensor
chmod +x run_kali_sensor.sh
sudo ./run_kali_sensor.sh wlan0 http://127.0.0.1:8000
```

---

## 8. Automated Testing & Verification Suite

```bash
# 1. Clean installation & developer environment verification
python scripts/verify_clean_installation.py

# 2. Canonical 4-input source pipeline convergence verification
python tests/integration/test_canonical_pipeline_convergence.py

# 3. Complete 15-stage end-to-end pipeline test (Input -> WebSocket -> Dashboard)
python scripts/test_complete_pipeline_e2e.py

# 4. Exhaustive 34-endpoint API test suite
python tests/e2e/test_all_apis.py

# 5. Validate all 6 threat detectors against real datasets
python tests/integration/test_six_detectors.py

# 6. Run comprehensive performance benchmark
python scripts/run_actual_performance_benchmark.py

# 7. Run GitHub readiness and security audit
python scripts/audit_github_readiness.py
```

---

## 9. Compliance & Safety Statement

CyberSentinel is built strictly in accordance with ethical defensive cybersecurity guidelines:
1. **Zero Packet Injection:** `sniff()` runs strictly in promiscuous listener mode (`store=False`).
2. **Zero Active Port Scanning:** No scans or probes against external networks or endpoints.
3. **Zero Payload Decryption:** Analyzes purely L3/L4 metadata, TLS cleartext SNI, and DNS query records.
4. **Advisory Alerts Only:** Dispatches MITRE ATT&CK guidance and explainable evidence without injecting traffic disruption.

---

## 10. Contributing & Community

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide for information on code standards, passive monitoring constraints, and pull request workflows.

---

## 11. License

CyberSentinel is open source under the terms of the [MIT License](LICENSE).
