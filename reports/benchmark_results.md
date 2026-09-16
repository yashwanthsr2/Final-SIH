# CyberSentinel Empirical Performance Benchmark Report

**Generated:** 2026-09-15 18:42:36 UTC  
**Platform:** `win32` (Python 3.14.0)  
**Measurement Principle:** Real-data executions with zero synthetic or mock benchmarks.  

## 1. Executive Performance Summary

| Component | Metric | Value | Unit |
| :--- | :--- | :--- | :--- |
| **Ingestion Throughput** | Zeek Record Normalization | **249,115.6** | flows / sec |
| **Ingestion Latency** | Mean Normalization Time | **3.89** | us / flow |
| **Feature Extraction** | Window Processing Latency | **0.3299** | ms / window |
| **Feature Throughput** | Effective Feature Rate | **75,780.0** | flows / sec |
| **ML Inference** | Mean Classifier Attributed Inference | **2.79** | ms / inference |
| **Correlation** | Multi-Signal Threat Fusion | **7.24** | us / event |
| **Trajectory** | DTMC Markov Progression | **12.35** | us / prediction |
| **End-to-End Alert** | Full 10-Stage Pipeline + SQLite | **15.0339** | ms / alert |
| **Full Pipeline Throughput** | Alert Generation Throughput | **66.3** | alerts / sec |
| **Dashboard API** | Average REST Endpoint Latency | **42.52** | ms / request |
| **Working Memory** | Server Daemon Working Set (RSS) | **192.98** | MB |

## 2. Ingestion & Feature Engineering Details

- **Ingestion (1,000 Real Flows)**:
  - Mean: `3.89 us/flow` | Median: `3.8 us/flow` | p95: `4.1 us/flow`
  - Throughput: `249,115.6 flows/sec`
- **Feature Extraction (40 windows of 25 flows)**:
  - Mean: `0.3299 ms/window` | p95: `0.3654 ms/window`
  - Throughput: `75,780.0 flows/sec`

## 3. Threat Detectors & ML Inference Details

| Detector | Type | Mean (ms) | Median (ms) | p95 (ms) | Throughput (evals/sec) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DDoS** | ML (HistGradientBoosting) | 3.6697 | 3.6575 | 5.0812 | 272.5 |
| **C2** | ML (HistGradientBoosting) | 1.174 | 1.1907 | 1.5666 | 851.8 |
| **DNS** | ML (HistGradientBoosting) | 2.0262 | 2.0285 | 2.9533 | 493.5 |
| **ENCRYPTED_TRAFFIC** | ML (HistGradientBoosting) | 3.9475 | 4.0117 | 4.5262 | 253.3 |
| **RECON** | Heuristic / Behavioral | 0.1182 | 0.1124 | 0.1541 | 8,460.2 |
| **EXFILTRATION** | Heuristic / Behavioral | 0.11 | 0.1063 | 0.125 | 9,090.9 |

### Direct Classifier Inference + Tree Attribution (Saabas SHAP Decomposition)

| Model Artifact | Estimator | Mean (ms) | p95 (ms) | Inferences / sec |
| :--- | :--- | :--- | :--- | :--- |
| `dos_hgb` | `HistGradientBoostingClassifier` | 3.6827 | 5.1812 | 271.5 |
| `c2_hgb` | `HistGradientBoostingClassifier` | 1.963 | 2.5377 | 509.4 |
| `dns_hgb` | `HistGradientBoostingClassifier` | 3.7405 | 4.6116 | 267.3 |
| `encrypted_hgb` | `HistGradientBoostingClassifier` | 1.7758 | 2.2431 | 563.1 |

## 4. Correlation, Trajectory & End-to-End Pipeline

- **Correlation Engine**:
  - Mean: `7.24 us` | p95: `8.4 us` | Rate: `138,121.5 ops/sec`
- **Trajectory Engine**:
  - Mean: `12.35 us` | p95: `13.2 us` | Rate: `80,971.7 ops/sec`
- **Full Canonical Alert Pipeline**:
  - Mean: `15.0339 ms` | Median: `14.4924 ms` | p95: `16.6298 ms`
  - Throughput: `66.3 full pipeline alerts/sec`

## 5. Dashboard REST API Response Times

| Endpoint | Description | Mean (ms) | p95 (ms) | Req / sec |
| :--- | :--- | :--- | :--- | :--- |
| `/api/alerts?limit=50` | Dashboard Feed | 196.1244 | 640.3633 | 5.1 |
| `/api/metrics` | Dashboard Feed | 8.1127 | 24.4192 | 123.3 |
| `/api/network` | Dashboard Feed | 6.5624 | 17.3432 | 152.4 |
| `/api/threat-summary` | Dashboard Feed | 35.9232 | 51.9519 | 27.8 |
| `/api/timeline?hours=24` | Dashboard Feed | 40.1461 | 57.5536 | 24.9 |
| `/api/trajectory` | Dashboard Feed | 6.6608 | 22.5505 | 150.1 |
| `/health` | Dashboard Feed | 4.1009 | 15.2724 | 243.8 |

## 6. Process Memory Consumption

- **Uvicorn Daemon RSS**: `192.98 MB`
- **Benchmark Process RSS**: `194.23 MB`
- **Combined Memory Footprint**: `387.21 MB`
