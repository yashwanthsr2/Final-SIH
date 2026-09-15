import json
import time
from backend.app.schemas import DetectionRequest
from backend.app.services.alert_service import analyze_request, run_detector
from backend.app.correlation import get_engine
from backend.app.prediction import get_engine as get_traj_engine
from backend.app.services.replay_service import VERIFIED_SCENARIOS


print("=" * 80)
print("AUDITING CYBERSENTINEL THREAT CORRELATION ENGINE WITH REAL EVENTS")
print("Host: 147.32.84.165 (CTU-13 / Malware Dataset Host)")
print("=" * 80)

# Clear correlation and trajectory state for fresh test
corr_engine = get_engine()
with corr_engine._lock:
    corr_engine._windows.clear()

traj_engine = get_traj_engine()
with traj_engine._lock:
    traj_engine._states.clear()

# -------------------------------------------------------------
# STEP 1: INDIVIDUAL DETECTOR RESULTS (ISOLATED WEAK/MODERATE INDICATORS)
# -------------------------------------------------------------
print("\n--- STEP 1: EVALUATING INDIVIDUAL DETECTORS SEPARATELY ---")

# 1. DNS detector alone
dns_payload = VERIFIED_SCENARIOS["dns"]["dns_features"]
dns_res = run_detector("DNS", dns_payload)
print(f"\n[1.1] DNS Detector Result (Isolated):")
print(f"      Prediction : {dns_res['prediction']}")
print(f"      Model Score: {dns_res['score']:.4f}")
print(f"      Severity   : {dns_res['severity']}")
print(f"      Supporting : {dns_res['supporting_features'][:2]}")

# 2. C2 detector alone
c2_payload = VERIFIED_SCENARIOS["c2"]["c2_features"]
c2_res = run_detector("C2", c2_payload)
print(f"\n[1.2] C2 Detector Result (Isolated):")
print(f"      Prediction : {c2_res['prediction']}")
print(f"      Model Score: {c2_res['score']:.4f}")
print(f"      Severity   : {c2_res['severity']}")
print(f"      Supporting : {c2_res['supporting_features'][:2]}")

# 3. Encrypted Traffic detector alone
enc_payload = VERIFIED_SCENARIOS["encrypted"]["encrypted_features"]
enc_res = run_detector("ENCRYPTED_TRAFFIC", enc_payload)
print(f"\n[1.3] Encrypted Detector Result (Isolated):")
print(f"      Prediction : {enc_res['prediction']}")
print(f"      Model Score: {enc_res['score']:.4f}")
print(f"      Severity   : {enc_res['severity']}")
print(f"      Supporting : {enc_res['supporting_features'][:2]}")

# What if each of these ran isolated through alert_service?
isolated_req = DetectionRequest(
    source="147.32.84.165",
    destination="8.8.8.8",
    domain="tunnel.apt29-data.net",
    dns_features=dns_payload
)
isolated_alert = analyze_request(isolated_req)
print(f"\n[Isolated Alert Check]")
print(f"  If DNS ran completely alone:")
print(f"  -> Threat Class: {isolated_alert['threat_class']}")
print(f"  -> Correlated: {isolated_alert['correlated']}")
print(f"  -> Correlated Count: {isolated_alert['detector_count']}")
print(f"  -> Risk Score: {isolated_alert['risk_score']}/100")
print(f"  -> Severity: {isolated_alert['severity']}")

# -------------------------------------------------------------
# STEP 2: CORRELATED SCENARIO (MULTI-INDICATOR FUSION)
# -------------------------------------------------------------
print("\n" + "=" * 80)
print("--- STEP 2: MULTI-DETECTOR CORRELATION (FUSING WEAK INDICATORS) ---")
print("=" * 80)

# Build unified request fusing DNS + C2 + Encrypted for the same host
correlated_payload = VERIFIED_SCENARIOS["correlated"]
correlated_req = DetectionRequest(**correlated_payload)

correlated_alert = analyze_request(correlated_req)

print(f"\n[Correlated Alert Output]")
print(f"  Alert ID        : {correlated_alert['id']}")
print(f"  Timestamp       : {correlated_alert['timestamp']}")
print(f"  Source          : {correlated_alert['source']}")
print(f"  Destination     : {correlated_alert['destination']}")
print(f"  Primary Threat  : {correlated_alert['primary_threat']}")
print(f"  Detectors Fired : {correlated_alert['detector_count']} ({[t['threat_class'] for t in correlated_alert['threats']]})")
print(f"  Confidence      : {correlated_alert['confidence']}")
print(f"  Correlated Flag : {correlated_alert['correlated']}")
print(f"  Pattern Name    : {correlated_alert['correlation_pattern']}")
print(f"  Correlation Score: {correlated_alert['correlation_score']}")
print(f"  Current State   : {correlated_alert['current_state']}")
print(f"  Predicted State : {correlated_alert['predicted_next_state']} (conf: {correlated_alert['prediction_confidence']})")
print(f"  Risk Score      : {correlated_alert['risk_score']}/100")
print(f"  Severity        : {correlated_alert['severity']}")

print("\n--- RISK SCORE BREAKDOWN COMPARISON ---")
print(f"Isolated Single Detector Risk Score : {isolated_alert['risk_score']}/100 ({isolated_alert['severity']})")
print(f"Correlated Multi-Detector Risk Score: {correlated_alert['risk_score']}/100 ({correlated_alert['severity']})")
print("\nRisk Breakdown for Correlated Alert:")
for k, v in correlated_alert['risk_breakdown'].items():
    print(f"  - {k:22s}: {v}")

print("\n--- UNIFIED EVIDENCE CHAIN ---")
for idx, ev in enumerate(correlated_alert['evidence'][:6], 1):
    print(f"  [{idx}] Detector: {ev.get('threat_class', 'N/A'):18s} | Feature: {ev.get('feature', 'N/A'):25s} = {ev.get('value', ev.get('feature_value', 'N/A'))}")
