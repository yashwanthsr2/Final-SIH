# CyberSentinel Empirical Performance Benchmark Report

**Generated:** 2026-09-15 05:13:07 UTC  
**Platform:** `win32` (Python 3.14.0)  
**Measurement Principle:** Real-data executions with zero synthetic or mock benchmarks.  

## 1. Executive Performance Summary

| Component | Metric | Value | Unit |
| :--- | :--- | :--- | :--- |
| **Ingestion Throughput** | Zeek Record Normalization | **166,469.7** | flows / sec |
| **Ingestion Latency** | Mean Normalization Time | **5.84** | us / flow |
| **Feature Extraction** | Window Processing Latency | **0.3319** | ms / window |
| **Feature Throughput** | Effective Feature Rate | **75,325.0** | flows / sec |
| **ML Inference** | Mean Classifier Attributed Inference | **3.26** | ms / inference |
| **Correlation** | Multi-Signal Threat Fusion | **8.14** | us / event |
| **Trajectory** | DTMC Markov Progression | **16.27** | us / prediction |
| **End-to-End Alert** | Full 10-Stage Pipeline + SQLite | **17.652** | ms / alert |
| **Full Pipeline Throughput** | Alert Generation Throughput | **56.5** | alerts / sec |
| **Dashboard API** | Average REST Endpoint Latency | **12.37** | ms / request |
| **Working Memory** | Server Daemon Working Set (RSS) | **67.8** | MB |

## 2. Ingestion & Feature Engineering Details

- **Ingestion (1,000 Real Flows)**:
  - Mean: `5.84 us/flow` | Median: `6.2 us/flow` | p95: `8.0 us/flow`
  - Throughput: `166,469.7 flows/sec`
- **Feature Extraction (40 windows of 25 flows)**:
  - Mean: `0.3319 ms/window` | p95: `0.3711 ms/window`
  - Throughput: `75,325.0 flows/sec`

## 3. Threat Detectors & ML Inference Details

| Detector | Type | Mean (ms) | Median (ms) | p95 (ms) | Throughput (evals/sec) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DDoS** | ML (HistGradientBoosting) | 4.1288 | 4.1971 | 4.9696 | 242.2 |
| **C2** | ML (HistGradientBoosting) | 1.1836 | 1.2628 | 1.448 | 844.9 |
| **DNS** | ML (HistGradientBoosting) | 2.328 | 2.3245 | 3.1374 | 429.6 |
| **ENCRYPTED_TRAFFIC** | ML (HistGradientBoosting) | 4.3262 | 4.2616 | 6.666 | 231.1 |
| **RECON** | Heuristic / Behavioral | 0.1499 | 0.16 | 0.1774 | 6,671.1 |
| **EXFILTRATION** | Heuristic / Behavioral | 0.117 | 0.1161 | 0.1241 | 8,547.0 |

### Direct Classifier Inference + Tree Attribution (Saabas SHAP Decomposition)

| Model Artifact | Estimator | Mean (ms) | p95 (ms) | Inferences / sec |
| :--- | :--- | :--- | :--- | :--- |
| `dos_hgb` | `HistGradientBoostingClassifier` | 4.4615 | 5.6803 | 224.1 |
| `c2_hgb` | `HistGradientBoostingClassifier` | 2.7751 | 3.4467 | 360.3 |
| `dns_hgb` | `HistGradientBoostingClassifier` | 4.211 | 4.901 | 237.5 |
| `encrypted_hgb` | `HistGradientBoostingClassifier` | 1.5903 | 1.9896 | 628.8 |

## 4. Correlation, Trajectory & End-to-End Pipeline

- **Correlation Engine**:
  - Mean: `8.14 us` | p95: `9.5 us` | Rate: `122,850.1 ops/sec`
- **Trajectory Engine**:
  - Mean: `16.27 us` | p95: `20.31 us` | Rate: `61,462.8 ops/sec`
- **Full Canonical Alert Pipeline**:
  - Mean: `17.652 ms` | Median: `17.2289 ms` | p95: `20.893 ms`
  - Throughput: `56.5 full pipeline alerts/sec`

## 5. Dashboard REST API Response Times

| Endpoint | Description | Mean (ms) | p95 (ms) | Req / sec |
| :--- | :--- | :--- | :--- | :--- |
| `/api/alerts?limit=50` | Dashboard Feed | 31.4966 | 61.9939 | 31.7 |
| `/api/metrics` | Dashboard Feed | 11.8233 | 17.3564 | 84.6 |
| `/api/network` | Dashboard Feed | 8.7625 | 17.0487 | 114.1 |
| `/api/threat-summary` | Dashboard Feed | 13.2887 | 25.0404 | 75.3 |
| `/api/timeline?hours=24` | Dashboard Feed | 8.5311 | 25.043 | 117.2 |
| `/api/trajectory` | Dashboard Feed | 5.433 | 15.912 | 184.1 |
| `/health` | Dashboard Feed | 7.2388 | 16.227 | 138.1 |

## 6. Process Memory Consumption

- **Uvicorn Daemon RSS**: `67.8 MB`
- **Benchmark Process RSS**: `188.33 MB`
- **Combined Memory Footprint**: `256.13 MB`
