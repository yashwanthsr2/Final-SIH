# 🏆 CyberSentinel — SIH 2026 Champion Presentation & Jury Defense Guide

**Problem Statement:** SIH26-26145  
**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## ⚡ 1. The 3-Minute Winning Pitch Script

### Minute 1: The Critical National Problem
> *"Good morning, respected judges. In high-security strategic defense networks and national infrastructure guarded by hardware data diodes, traffic flows in **one direction only**. Traditional cybersecurity tools fail here because they rely on bidirectional TCP handshakes, active pinging, deep packet inspection, and decryption proxies.*
> 
> *When an advanced adversary penetrates this boundary, security teams are flying blind. **CyberSentinel** solves this exact challenge for NTRO: a **100% passive, non-intrusive, privacy-preserving AI threat intelligence platform** engineered specifically for unidirectional IP streams."*

### Minute 2: The Core Innovation (What Makes Us Win)
> *"Rather than relying on basic signature matching or synthetic toys, CyberSentinel delivers 4 breakthrough architectural pillars:*
> 
> 1. **Zero-Packet Transmission & Zero Decryption:** We extract flow-level statistical dynamics — packet size distributions, inter-arrival time variance, burst entropy, and destination concentrations. We never inspect packet payloads or attempt decryption.
> 2. **All 6 Mandatory Threat Detectors Working in Unison:** DDoS (HistGradientBoosting, F1=1.00), Command & Control Beaconing, DNS Covert Tunneling, Malicious Encrypted Sessions, Network Reconnaissance/Port Scans, and Asymmetric Data Exfiltration.
> 3. **Autonomous Threat Correlation & Explainable Risk Scoring:** A sliding-window correlation engine connects multi-stage signals into coherent kill-chain incidents. Our 0–100 risk score is fully transparent, breaking down exact mathematical contributions rather than acting as a black box.
> 4. **Predictive Attack Trajectory & Digital Twin:** An 8-state Markov model aligned to MITRE ATT&CK predicts the adversary's next likely move before damage occurs, visualized live on our real-time Digital Twin topology graph."*

### Minute 3: The Live Demonstration
> *"Let us show you CyberSentinel running live right now on actual modern Zeek network captures..."*
> *(Open dashboard at `http://127.0.0.1:8000/`, click 'Start Replay' or run 'Demo Scenarios', show real-time WebSocket alert stream, click on an alert for feature explainability, show the live Digital Twin graph, and highlight the attack trajectory).*

---

## 🛡️ 2. Direct Mapping to NTRO Hard Constraints

| Requirement | NTRO Specification | CyberSentinel Implementation |
| :--- | :--- | :--- |
| **Data Diode / Passive** | No packet transmission, no probing | Strictly passive ingestion; zero raw packets emitted; Scapy sniffing / Zeek log replay only |
| **No Decryption** | TLS/HTTPS traffic cannot be decrypted | Metadata-only features: byte entropy, packet count, inter-arrival times, flow duration |
| **6 Threat Classes** | DDoS, C2, DNS, Encrypted, Recon, Exfiltration | All 6 implemented with dedicated ML models and statistical heuristic detectors |
| **Explainability** | Black box neural networks are disallowed in high-assurance SOCs | Tree feature contributions, SHAP-style weights, and human-readable evidence chains |
| **Trajectory Forecasting** | Early warning of multi-stage intrusions | 8-stage MITRE ATT&CK Markov state transition matrix |
| **Zero Heavy Dependencies** | Standalone deployment in air-gapped zones | SQLite + FastAPI + Vanilla JS; zero node_modules or heavy graph databases needed |

---

## 🎯 3. Tough Jury Questions & How to Answer

### Q1: *"Why can't you just use Snort, Suricata, or Zeek alone?"*
**Answer:**
> *"Snort and Suricata rely primarily on payload signatures and bidirectional TCP state tracking. In unidirectional data diode traffic, TCP ACK packets never return! Traditional stateful inspection breaks. CyberSentinel uses unidirectional flow aggregation and statistical ML that operates purely on forward packet dynamics, detecting zero-day patterns that have no known signature."*

### Q2: *"How do you detect malicious encrypted traffic without decrypting it?"*
**Answer:**
> *"We analyze side-channel behavioral fingerprints:
> - Packet size progression during session setup
> - Flow duration vs bytes exchanged (e.g. C2 heartbeats have distinct periodicity)
> - Destination diversity and entropy
> - Statistical asymmetry between outbound and inbound byte counts.
> Malware command-and-control exhibits repetitive beaconing cycles and anomalous timing intervals that distinguish it from standard HTTPS browser traffic without ever touching encrypted payloads."*

### Q3: *"How does your Trajectory Prediction work mathematically?"*
**Answer:**
> *"We model adversary progression as a discrete-time Markov chain across 8 MITRE ATT&CK stages: `NORMAL`, `RECON`, `INITIAL_ACCESS`, `C2`, `CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `EXFILTRATION`, and `IMPACT/DDOS`.
> Each state transition has an empirical prior probability matrix calibrated against real attack kill-chains. When an alert arrives, the system computes the conditional transition probabilities $P(S_{t+1} \mid S_t)$ to forecast the adversary's next move with quantified confidence."*

### Q4: *"How does the 0–100 Risk Score work? Is it arbitrary?"*
**Answer:**
> *"No, it is strictly governed by a published multi-factor formula:
> $$\text{Risk} = \min(100, (\text{Confidence} \times 40) + \text{BaseSeverity} + \text{CorrelationBoost} + \text{PersistenceScore}) \times W_{\text{threat}}$$
> - Confidence contributes up to 40 points
> - Base severity contributes 10 to 30 points
> - Correlation across multiple detectors adds up to 20 points
> - Temporal persistence adds up to 10 points
> Every alert displays its exact numerical breakdown so SOC analysts can verify why an alert reached High or Critical severity."*

### Q5: *"Did you use real datasets or mock data?"*
**Answer:**
> *"We trained and validated on real modern network datasets from the UWF-ZeekDataSum25-1 repository, spanning 7 attack categories across 4 parquet datasets with over 90,000 real network flows. All 4 ML models were trained on these exact parquet features."*

---

## 🚀 4. How to Run the Demo for Judges

1. **Local Launch:**
   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. **Open Dashboard:**
   Navigate to `http://127.0.0.1:8000/` in the browser.
3. **Step-by-step Demo Flow:**
   - **Step 1:** Show **SOC Overview** — clean dark glassmorphism UI with real-time KPI counters.
   - **Step 2:** Click **Replay Live Attacks** — watch the live WebSocket feed update instantly with zero page reload.
   - **Step 3:** Click **Network Topology** — demonstrate the Digital Twin IP graph with live nodes, connected edges, and threat-color coding.
   - **Step 4:** Click **Attack Trajectory** — show the 8-state MITRE ATT&CK progression matrix and predictive next-stage forecast.
   - **Step 5:** Click **Threat Detail** on any alert — show the exact feature contribution breakdown and explainability evidence.
   - **Step 6:** Click **Model Center** — show the 4 ML models, feature counts, F1 scores, and training metadata.
