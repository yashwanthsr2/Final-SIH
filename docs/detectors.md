# CyberSentinel Threat Detection Engines

## Six Threat Classes
1. **DDoS Detector (ML):** Identifies volumetric SYN/UDP/ICMP floods and high-frequency request spikes.
2. **C2 Beaconing Detector (ML):** Detects periodic keep-alive signals and reverse shell beacons.
3. **DNS Tunneling & DGA (ML):** Identifies data exfiltration via TXT/NULL queries and algorithmic domain generation.
4. **Encrypted Malware Detector (ML):** Detects anomalous TLS handshake patterns and outlier byte/packet ratios.
5. **Reconnaissance Engine (Statistical):** Identifies port scans, host sweeps, and horizontal subnet probes.
6. **Exfiltration Engine (Heuristic Asymmetry):** Flags massive outbound byte transfers with minimal inbound response.
