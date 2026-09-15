
# CyberSentinel — Kali Linux Live Passive Wi-Fi Monitoring Guide
**Project Statement:** SIH26-26145 | **Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | **Architecture:** Strictly Passive, Read-Only AI Network Monitor

---

## 1. Executive Safety & Operational Constraints

CyberSentinel operates as a **strictly passive, non-intrusive metadata sensor**:
- ❌ **NO packet injection** or transmission of probe packets
- ❌ **NO active port scanning** against external networks
- ❌ **NO payload decryption** or TLS inspection
- ❌ **NO MITM / ARP spoofing / DNS redirection**
- ❌ **NO traffic blocking or firewall disruption**
- ✅ **100% Read-Only:** Inspects L3/L4 packet headers and protocol metadata only
- ✅ **Privacy-Preserving:** Never collects passwords, session cookies, tokens, or email/chat bodies

---

## 2. Prerequisites on Kali Linux

### A. Python Environment
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git libpcap-dev
```

### B. Zeek Sensor (Recommended for high-throughput zero-drop monitoring)
```bash
# Install Zeek on Debian/Kali Linux
sudo apt install -y zeek

# Verify Zeek installation:
zeek --version
# Should output: zeek version 5.x or 6.x / 7.x
```
> *Note:* If Zeek is not installed, CyberSentinel automatically falls back to its built-in Linux `AF_PACKET` / Scapy raw socket engine.

---

## 3. Connecting to Wi-Fi on Kali Linux

Connect Kali Linux to your regular home, lab, or mobile hotspot Wi-Fi:
```bash
# Verify your Wi-Fi interface name (usually wlan0 or wlp2s0)
ip link show

# Scan for available Wi-Fi SSIDs:
nmcli dev wifi list

# Connect to your Wi-Fi network:
nmcli dev wifi connect "YOUR_WIFI_SSID" password "YOUR_WIFI_PASSWORD"

# Verify IP address and gateway connectivity:
ip -4 addr show wlan0
ping -c 3 8.8.8.8
```

---

## 4. Launching CyberSentinel Live Monitor

Clone or navigate into the repository:
```bash
cd /path/to/CODEZILLA-SIH26145
```

Make the launcher executable and start with root privileges (required for raw packet capture):
```bash
chmod +x run_kali_sensor.sh
sudo bash run_kali_sensor.sh
```

The script will:
1. Auto-detect your Wi-Fi card (e.g., `wlan0`).
2. Verify Python dependencies and Zeek status.
3. Start the FastAPI + Uvicorn server on port `8000`.

Open your browser on Kali Linux (or from another machine on the LAN):
- **Local:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Dashboard Mode:** Click **`[ 📡 LIVE KALI ]`** in the top navigation bar.

---

## 5. Calibrating the 5-Minute "Normal Baseline"

To eliminate false positives during normal user activities (YouTube 4K/1080p streaming, Google searches, CDN browsing):

1. On the **Live Network Traffic & Passive Monitor** page, locate the **5-Minute Normal Traffic Baseline** card.
2. Click **`[ ⏱️ Start 5-Min Baseline ]`**.
3. For the next 5 minutes, use the Internet normally on the machine:
   - Open YouTube and stream a video in 1080p.
   - Search Google, visit Wikipedia, GitHub, and news portals.
   - Run DNS queries and download a regular file.
4. **How the Baseline Engine works:**
   - **YouTube Video Streaming:** Learns high inbound throughput (`bytes_in >> bytes_out`). Data exfiltration detectors will NOT trigger on incoming video segments.
   - **Google & CDN Multiplexing:** Learns parallel HTTP/2 / HTTP/3 connections to Google/Cloudflare IP clusters, preventing false port-scan alerts.
   - **DNS Bursting:** Records normal resolver IPs and query rates to prevent DNS tunneling false alarms.
5. After 5 minutes, the baseline automatically transitions to **ACTIVE**. The calibrated thresholds dynamically adjust detector sensitivity without suppressing true attacks.

---

## 6. How to Test Defensive Detection Safely

To demonstrate threat detection to SIH evaluators **without active scanning or violating passive rules**:

### Option A: Use the Built-in Live Simulation Trigger (Safest)
In the CyberSentinel Live Dashboard, click any of the 4 simulated traffic injectors:
- `[ 🎯 Simulate Port Scan ]`: Emulates reconnaissance SYN burst
- `[ 🌊 Simulate DDoS Burst ]`: Emulates high-frequency flow flooding
- `[ 📤 Simulate Exfiltration ]`: Emulates outbound ratio anomaly
- `[ 🕳️ Simulate DNS Tunnel ]`: Emulates base64-encoded TXT DNS queries

### Option B: Passive Replay of Standard Benchmark PCAPs
In the dashboard topbar, switch to **`[ 📊 REPLAY ]`** mode and click:
- `[ 🛡️ Load Modern 2025 Dataset ]` (UWF-Zeek modern dataset)
- `[ ▶ Start Replay ]` to see real-time packet-by-packet inference across the 6 ML models.

### Option C: Safe Local Loopback Probe (On your own machine only)
You can run a single benign port probe against localhost:
```bash
# Safe 1-port check on localhost (does NOT scan external networks)
nc -zv 127.0.0.1 8000
```
CyberSentinel's passive sensor will log the flow metadata and display it in the **Observed Live Flows** table.

---

## 7. REST API Reference for Headless Operation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/live/interfaces` | Lists available physical and wireless interfaces |
| `POST` | `/api/live/start` | Starts passive capture on specified interface (default: `wlan0`) |
| `POST` | `/api/live/stop` | Stops passive capture and resets buffers |
| `GET` | `/api/live/status` | Current monitoring status, packet count, throughput |
| `POST` | `/api/live/baseline/start` | Initiates 300s baseline calibration |
| `POST` | `/api/live/baseline/stop` | Aborts or finalizes baseline calibration |
| `GET` | `/api/live/baseline/status` | Baseline state (`LEARNING`, `ACTIVE`, `OFF`) & learned thresholds |
| `GET` | `/api/live/flows?limit=50` | Streams normalized flow records for the UI |
| `GET` | `/api/live/zeek` | Zeek daemon status, version, and diagnostic report |

---

## 8. SIH 2026 Pitch Highlights for Evaluators

When explaining this live monitoring capability to the NTRO jury:
1. **Unidirectional Compatibility:** Emphasize that the sensor operates purely on the receiving side of an optical tap or data diode — it emits 0 bytes into the monitored network.
2. **True Modern Zeek Compatibility:** Ingests standard Zeek connection logs (`conn.log`, `dns.log`, `ssl.log`) natively with sub-millisecond parsing.
3. **Adaptive Baseline vs Static Rules:** Show how YouTube streaming does not trigger "Data Exfiltration" alarms because the baseline learns directional asymmetry (`bytes_in` vs `bytes_out`).
4. **Multi-Model Explainability:** Every alert highlights the specific statistical features (flow duration, inter-packet arrival time, entropy) that triggered the classifier.
