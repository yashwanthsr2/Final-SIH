import urllib.request
import json
from backend.app.services.replay_service import VERIFIED_SCENARIOS


SERVER = "http://127.0.0.1:8000"

def post_detect(payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{SERVER}/detect",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read().decode("utf-8"))

def get_trajectory(source_ip):
    req = urllib.request.urlopen(f"{SERVER}/api/trajectory/{source_ip}", timeout=10)
    return json.loads(req.read().decode("utf-8"))

print("=" * 80)
print("SEEDING LIVE TRAJECTORY PROGRESSION VIA HTTP POST /detect")
print("Target Host: 192.168.1.100")
print("=" * 80)

# Check baseline state for 192.168.1.100
t0 = get_trajectory("192.168.1.100")
print(f"\n[Baseline / Fallback State for unobserved host]")
print(f"  CURRENT STATE        : {t0['current_state']}")
print(f"  PREDICTED NEXT STATE : {t0['predicted_next_state']}")
print(f"  CONFIDENCE           : {t0['prediction_confidence']:.3f} ({(t0['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t0.get('prediction_reasoning')}")

# Step 1: POST Reconnaissance event
print("\n>>> POST Event 1: Reconnaissance (SYN scan)")
p1 = {
    "source": "192.168.1.100",
    "destination": "10.0.0.1",
    "protocol": "TCP",
    "recon_features": VERIFIED_SCENARIOS["recon"]["recon_features"]
}
r1 = post_detect(p1)
t1 = get_trajectory("192.168.1.100")
h1_str = [f"{h['from']} -> {h['to']}" for h in t1.get('state_history', [])]
print(f"  CURRENT STATE        : {t1['current_state']}")
print(f"  PREDICTED NEXT STATE : {t1['predicted_next_state']}")
print(f"  CONFIDENCE           : {t1['prediction_confidence']:.3f} ({(t1['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t1.get('prediction_reasoning')}")
print(f"  History              : {h1_str}")

# Step 2: POST C2 & DNS event
print("\n>>> POST Event 2: C2 Channel & DNS Tunneling")
p2 = {
    "source": "192.168.1.100",
    "destination": "198.51.100.24",
    "domain": "tunnel.apt29-data.net",
    "protocol": "UDP",
    "dns_features": VERIFIED_SCENARIOS["dns"]["dns_features"],
    "c2_features": VERIFIED_SCENARIOS["c2"]["c2_features"],
}
r2 = post_detect(p2)
t2 = get_trajectory("192.168.1.100")
h2_str = [f"{h['from']} -> {h['to']}" for h in t2.get('state_history', [])]
print(f"  CURRENT STATE        : {t2['current_state']}")
print(f"  PREDICTED NEXT STATE : {t2['predicted_next_state']}")
print(f"  CONFIDENCE           : {t2['prediction_confidence']:.3f} ({(t2['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t2.get('prediction_reasoning')}")
print(f"  History              : {h2_str}")

# Step 3: POST Exfiltration event
print("\n>>> POST Event 3: Data Exfiltration (Outbound Asymmetric)")
p3 = {
    "source": "192.168.1.100",
    "destination": "203.0.113.88",
    "protocol": "TCP",
    "exfil_features": VERIFIED_SCENARIOS["exfil"]["exfil_features"]
}
r3 = post_detect(p3)
t3 = get_trajectory("192.168.1.100")
h3_str = [f"{h['from']} -> {h['to']}" for h in t3.get('state_history', [])]
print(f"  CURRENT STATE        : {t3['current_state']}")
print(f"  PREDICTED NEXT STATE : {t3['predicted_next_state']}")
print(f"  CONFIDENCE           : {t3['prediction_confidence']:.3f} ({(t3['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t3.get('prediction_reasoning')}")
print(f"  History              : {h3_str}")
print(f"  Top Candidates       : {t3['all_possible_next_states']}")
