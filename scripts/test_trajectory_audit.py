import json
import time
from backend.app.prediction import get_engine as get_traj_engine
from backend.app.schemas import DetectionRequest
from backend.app.services.alert_service import analyze_request
from backend.app.services.replay_service import VERIFIED_SCENARIOS


print("=" * 80)
print("AUDITING CYBERSENTINEL ATTACK TRAJECTORY PREDICTION SYSTEM")
print("=" * 80)

traj = get_traj_engine()
with traj._lock:
    # Clear prior state for clean deterministic audit
    traj._states.pop("192.168.1.100", None)

print("\n[Step 0] Initial State (Unseen Host):")
initial = traj.get_trajectory("192.168.1.100")
print(f"  CURRENT STATE        : {initial['current_state']}")
print(f"  PREDICTED NEXT STATE : {initial['predicted_next_state']}")
print(f"  CONFIDENCE           : {initial['prediction_confidence']:.3f} ({(initial['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {initial.get('prediction_reasoning', 'Default fallback for unobserved host')}")

# Sequence Step 1: Reconnaissance
print("\n[Step 1] Ingesting Temporal Event 1: Reconnaissance (SYN port scan observed)")
req1 = DetectionRequest(
    source="192.168.1.100",
    destination="10.0.0.1",
    protocol="TCP",
    recon_features=VERIFIED_SCENARIOS["recon"]["recon_features"]
)
alert1 = analyze_request(req1)
t1 = traj.get_trajectory("192.168.1.100")
print(f"  CURRENT STATE        : {t1['current_state']}")
print(f"  PREDICTED NEXT STATE : {t1['predicted_next_state']}")
print(f"  CONFIDENCE           : {t1['prediction_confidence']:.3f} ({(t1['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t1.get('prediction_reasoning', alert1.get('prediction_reasoning'))}")
print(f"  Top Candidates       : {t1['all_possible_next_states'][:3]}")

# Sequence Step 2: C2 Beaconing + DNS Tunneling
print("\n[Step 2] Ingesting Temporal Event 2: C2 Channel & DNS Tunneling established")
req2 = DetectionRequest(
    source="192.168.1.100",
    destination="198.51.100.24",
    protocol="UDP",
    dns_features=VERIFIED_SCENARIOS["dns"]["dns_features"],
    c2_features=VERIFIED_SCENARIOS["c2"]["c2_features"]
)
alert2 = analyze_request(req2)
t2 = traj.get_trajectory("192.168.1.100")
print(f"  CURRENT STATE        : {t2['current_state']}")
print(f"  PREDICTED NEXT STATE : {t2['predicted_next_state']}")
print(f"  CONFIDENCE           : {t2['prediction_confidence']:.3f} ({(t2['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t2.get('prediction_reasoning', alert2.get('prediction_reasoning'))}")
print(f"  Top Candidates       : {t2['all_possible_next_states'][:3]}")

# Sequence Step 3: Data Exfiltration
print("\n[Step 3] Ingesting Temporal Event 3: Outbound Data Exfiltration")
req3 = DetectionRequest(
    source="192.168.1.100",
    destination="203.0.113.88",
    protocol="TCP",
    exfil_features=VERIFIED_SCENARIOS["exfil"]["exfil_features"]
)
alert3 = analyze_request(req3)
t3 = traj.get_trajectory("192.168.1.100")
print(f"  CURRENT STATE        : {t3['current_state']}")
print(f"  PREDICTED NEXT STATE : {t3['predicted_next_state']}")
print(f"  CONFIDENCE           : {t3['prediction_confidence']:.3f} ({(t3['prediction_confidence']*100):.1f}%)")
print(f"  REASONING            : {t3.get('prediction_reasoning', alert3.get('prediction_reasoning'))}")
print(f"  Top Candidates       : {t3['all_possible_next_states'][:3]}")

print("\n" + "=" * 80)
print("AUDIT SUMMARY: VERIFIED TEMPORAL PROGRESSION THROUGH PIPELINE")
print("=" * 80)
print(f"Step 0: {initial['current_state']:15s} -> {initial['predicted_next_state']:15s} (conf: {initial['prediction_confidence']:.2f})")
print(f"Step 1: {t1['current_state']:15s} -> {t1['predicted_next_state']:15s} (conf: {t1['prediction_confidence']:.2f})")
print(f"Step 2: {t2['current_state']:15s} -> {t2['predicted_next_state']:15s} (conf: {t2['prediction_confidence']:.2f})")
print(f"Step 3: {t3['current_state']:15s} -> {t3['predicted_next_state']:15s} (conf: {t3['prediction_confidence']:.2f})")
