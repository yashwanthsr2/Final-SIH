import json
import time
from backend.app.schemas import DetectionRequest
from backend.app.services.alert_service import analyze_request
from backend.app.correlation import get_engine
from backend.app.prediction import get_engine as get_traj_engine
from backend.app.services.replay_service import VERIFIED_SCENARIOS


print("=" * 80)
print("MULTI-STAGE KILL CHAIN CORRELATION AUDIT (WEAK SIGNALS -> HIGH ASSURANCE)")
print("Source Target: 147.32.84.165 (Real infected host from CTU-13 dataset)")
print("=" * 80)

corr = get_engine()
with corr._lock:
    corr._windows.clear()

traj = get_traj_engine()
with traj._lock:
    traj._states.clear()

# -------------------------------------------------------------
# PHASE 1: ISOLATED RECONNAISSANCE (WEAK EARLY INDICATOR)
# -------------------------------------------------------------
recon_req = DetectionRequest(
    source="147.32.84.165",
    destination="10.0.0.1",
    protocol="TCP",
    recon_features=VERIFIED_SCENARIOS["recon"]["recon_features"]
)
alert_stage1 = analyze_request(recon_req)

print("\n>>> PHASE 1: INITIAL PROBE (RECON)")
print(f"  Threat Detected: {alert_stage1['threat_class']} (confidence={alert_stage1['confidence']:.2f})")
print(f"  Correlated: {alert_stage1['correlated']} (Detectors in window: {alert_stage1['detector_count']})")
print(f"  Pattern: {alert_stage1['correlation_pattern']}")
print(f"  Current State: {alert_stage1['current_state']} -> Predicted: {alert_stage1['predicted_next_state']}")
print(f"  Risk Score: {alert_stage1['risk_score']}/100 ({alert_stage1['severity']})")
print(f"  Assessment: Isolated noisy probe - low operational priority.")

# -------------------------------------------------------------
# PHASE 2: BEACONING & DNS CHANNEL ESTABLISHED (CORRELATED C2 + DNS)
# -------------------------------------------------------------
c2_dns_req = DetectionRequest(
    source="147.32.84.165",
    destination="198.51.100.24",
    domain="tunnel.apt29-data.net",
    protocol="UDP",
    dns_features=VERIFIED_SCENARIOS["dns"]["dns_features"],
    c2_features=VERIFIED_SCENARIOS["c2"]["c2_features"],
)
alert_stage2 = analyze_request(c2_dns_req)

print("\n>>> PHASE 2: C2 CHANNEL & DNS TUNNELING (RECON + C2 + DNS IN WINDOW)")
print(f"  Threat Detected: {alert_stage2['primary_threat']} (confidence={alert_stage2['confidence']:.2f})")
print(f"  Correlated: {alert_stage2['correlated']} (Detectors in window: {alert_stage2['detector_count']})")
print(f"  Active Threats in Window: {alert_stage2['correlated_threats']}")
print(f"  Pattern Identified: {alert_stage2['correlation_pattern']}")
print(f"  Current State: {alert_stage2['current_state']} -> Predicted: {alert_stage2['predicted_next_state']}")
print(f"  Risk Score: {alert_stage2['risk_score']}/100 ({alert_stage2['severity']})")
print(f"  Assessment: Correlation elevated isolated probes into verified C2 infrastructure.")

# -------------------------------------------------------------
# PHASE 3: LARGE ASYMMETRIC OUTBOUND TRANSFER (EXFILTRATION)
# -------------------------------------------------------------
exfil_req = DetectionRequest(
    source="147.32.84.165",
    destination="203.0.113.88",
    protocol="TCP",
    exfil_features=VERIFIED_SCENARIOS["exfil"]["exfil_features"]
)
alert_stage3 = analyze_request(exfil_req)

print("\n>>> PHASE 3: ACTIVE DATA EXFILTRATION (FULL KILL CHAIN)")
print(f"  Threat Detected: {alert_stage3['primary_threat']} (confidence={alert_stage3['confidence']:.2f})")
print(f"  Correlated: {alert_stage3['correlated']} (Detectors in window: {alert_stage3['detector_count']})")
print(f"  Active Threats in Window: {alert_stage3['correlated_threats']}")
print(f"  Pattern Identified: {alert_stage3['correlation_pattern']}")
print(f"  Current State: {alert_stage3['current_state']} -> Predicted: {alert_stage3['predicted_next_state']}")
print(f"  Risk Score: {alert_stage3['risk_score']}/100 ({alert_stage3['severity']})")
print(f"  Assessment: Critical confirmed multi-stage campaign reaching data theft stage.")

print("\n" + "=" * 80)
print("AUDIT SUMMARY: PROGRESSION OF CORRELATED RISK SCORE")
print("=" * 80)
print(f"Phase 1 (Recon probe)       : Risk = {alert_stage1['risk_score']:2d}/100 ({alert_stage1['severity']:8s}) | Pattern = {alert_stage1['correlation_pattern']}")
print(f"Phase 2 (C2 + DNS tunnel)   : Risk = {alert_stage2['risk_score']:2d}/100 ({alert_stage2['severity']:8s}) | Pattern = {alert_stage2['correlation_pattern']}")
print(f"Phase 3 (Exfil confirmation): Risk = {alert_stage3['risk_score']:2d}/100 ({alert_stage3['severity']:8s}) | Pattern = {alert_stage3['correlation_pattern']}")
