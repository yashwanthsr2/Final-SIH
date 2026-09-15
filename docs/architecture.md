# CyberSentinel System Architecture

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
