"""
Verification script for CyberSentinel passive live monitoring during normal browsing.
Simulates real normal user web browsing (Google, YouTube, Wikipedia HTTPS).
Captures real-time passive telemetry, feature extraction, detector execution,
and alert suppression.
"""
import json
import time
import urllib.request

def run_test():
    print("=" * 65)
    print("CYBERSENTINEL: NORMAL BROWSING TELEMETRY & THREAT VERIFICATION")
    print("=" * 65)

    # 1. Baseline status check
    st0 = json.loads(urllib.request.urlopen("http://127.0.0.1:8000/api/live/status").read().decode())
    pkts0 = st0.get("packets_seen", 0)
    bytes0 = st0.get("bytes_seen", 0)
    flows0 = st0.get("flows_seen", 0)
    print(f"\n[1] Initial State: {pkts0:,} packets, {bytes0:,} bytes, {flows0:,} flows recorded.")

    # 2. Browse normal HTTPS websites
    print("\n[2] Performing Real Normal Browsing over Wi-Fi...")
    urls = [
        ("Google Search", "https://www.google.com"),
        ("YouTube Home", "https://www.youtube.com"),
        ("Wikipedia AI Article", "https://en.wikipedia.org/wiki/Deep_learning"),
        ("Wikipedia ML Article", "https://en.wikipedia.org/wiki/Machine_learning"),
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }

    total_downloaded = 0
    for label, u in urls:
        try:
            t0 = time.time()
            req = urllib.request.Request(u, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = resp.read()
                total_downloaded += len(data)
                dt = round((time.time() - t0) * 1000, 1)
                status_code = resp.getcode()
                print(f"  -> {label:22} ({u})")
                print(f"     Status: {status_code} OK | Size: {len(data):,} bytes | Latency: {dt} ms")
        except Exception as e:
            print(f"  -> {label:22} Error: {e}")

    print(f"\nTotal normal HTTPS content downloaded: {total_downloaded:,} bytes ({total_downloaded / (1024*1024):.2f} MB)")

    # 3. Wait for sliding window to capture telemetry
    print("\n[3] Waiting for live passive capture window to process...")
    time.sleep(4.0)

    # 4. Check telemetry after browsing
    st1 = json.loads(urllib.request.urlopen("http://127.0.0.1:8000/api/live/status").read().decode())
    pkts1 = st1.get("packets_seen", 0)
    bytes1 = st1.get("bytes_seen", 0)
    flows1 = st1.get("flows_seen", 0)
    delta_pkts = pkts1 - pkts0
    delta_bytes = bytes1 - bytes0
    delta_flows = flows1 - flows0

    print(f"\n[4] Observed Network Telemetry Delta:")
    print(f"    Packets Observed : +{delta_pkts:,} packets")
    print(f"    Bytes Observed   : +{delta_bytes:,} bytes ({delta_bytes / (1024*1024):.2f} MB)")
    print(f"    Flows Generated  : +{delta_flows:,} flows")
    print(f"    Current Pkt Rate : {st1.get('packet_rate', 0):.1f} pkts/sec")
    print(f"    Current Byte Rate: {st1.get('byte_rate', 0):,.1f} B/sec ({st1.get('byte_rate', 0)*8/1_000_000:.2f} Mbps)")

    # 5. Query Flow Buffer
    fl_res = json.loads(urllib.request.urlopen("http://127.0.0.1:8000/api/live/flows").read().decode())
    flows = fl_res.get("flows", [])
    web_flows = [f for f in flows if f.get("dport") in (80, 443) or f.get("sport") in (80, 443)]
    non_web_flows = [f for f in flows if f.get("dport") not in (80, 443) and f.get("sport") not in (80, 443)]

    print(f"\n[5] Traffic Breakdown:")
    print(f"    Total Buffered Flows : {len(flows)}")
    print(f"    Legitimate Web Flows : {len(web_flows)} (Port 80/443 HTTPS/TLS)")
    print(f"    Other/P2P Flows      : {len(non_web_flows)} (Non-standard ports)")

    print("\n    Sample Legitimate Web Flows (Normal Browsing):")
    for wf in web_flows[:6]:
        print(f"      {wf['source']}:{wf['sport']} -> {wf['destination']}:{wf['dport']} [{wf['proto']}] "
              f"| {wf['packets']} pkts | {wf['bytes']:,} B | {wf['duration']}s")

    # 6. Check Detection Results
    last_det = st1.get("last_detection") or {}
    primary = last_det.get("primary_threat")
    severity = last_det.get("severity")
    risk_score = last_det.get("risk_score")
    confidence = last_det.get("confidence")
    threats = last_det.get("threats", [])
    evidence = last_det.get("evidence", [])

    print(f"\n[6] CyberSentinel Detection & Risk Output:")
    print(f"    Primary Threat Fired : {primary}")
    print(f"    Overall Severity     : {severity}")
    print(f"    Risk Score           : {risk_score}/100")
    print(f"    Confidence           : {confidence}")
    print(f"    Inference Latency    : {last_det.get('inference_latency_ms', 0)} ms")

    print("\n    Detector Audit:")
    for t in threats:
        print(f"      - Detector: {t.get('detector')} | Score: {t.get('score')} | Type: {t.get('detector_type')}")
        for feat in t.get("supporting_features", []):
            print(f"        * Feature {feat.get('feature')}: {feat.get('value')} -> {feat.get('human_label')}")

    # 7. False Positive Check on High-Volume Traffic
    print("\n[7] Normal Browsing False Positive Suppression Check:")
    ddos_fired = any(t.get("threat_class") == "DDoS" for t in threats)
    exfil_fired = any(t.get("threat_class") == "EXFILTRATION" for t in threats)
    dns_fired = any(t.get("threat_class") == "DNS" for t in threats)
    c2_fired = any(t.get("threat_class") == "C2" for t in threats)

    print(f"    DDoS Detector (High packet/volume false alarm) : {'TRIGGERED (FAIL)' if ddos_fired else 'BENIGN / SUPPRESSED (PASS)'}")
    print(f"    Exfiltration Detector (High downlink false alarm): {'TRIGGERED (FAIL)' if exfil_fired else 'BENIGN / SUPPRESSED (PASS)'}")
    print(f"    DNS Tunneling (Normal web DNS false alarm)     : {'TRIGGERED (FAIL)' if dns_fired else 'BENIGN / SUPPRESSED (PASS)'}")
    print(f"    C2 Beaconing (Keep-alive false alarm)          : {'TRIGGERED (FAIL)' if c2_fired else 'BENIGN / SUPPRESSED (PASS)'}")

    if not ddos_fired and not exfil_fired:
        print("\n>>> RESULT: SUCCESS! Normal high-volume browsing was NOT labeled as a critical attack.")
    else:
        print("\n>>> RESULT: WARNING - Detection triggered.")

if __name__ == "__main__":
    run_test()
