import pandas as pd
import json
from backend.app.services.alert_service import analyze_request
from backend.app.schemas import DetectionRequest

attack_df = pd.read_csv('evaluation/packaging/verified_attack_input.csv')
req_data = {
    'source': '192.168.1.105',
    'destination': '10.0.0.1',
    'protocol': 'TCP',
    'ddos_features': attack_df.iloc[0].to_dict()
}
req = DetectionRequest(**req_data)
alert = analyze_request(req)

print('=== GENERATED ALERT EVIDENCE ===')
print(json.dumps(alert['evidence'], indent=2))
print('\n=== GENERATED ALERT SUMMARY ===')
print('Alert ID:', alert['id'])
print('Threat Class:', alert['threat_class'])
print('Confidence:', alert['confidence'])
print('Risk Score:', alert['risk_score'])
print('Severity:', alert['severity'])
print('Current State:', alert['current_state'])
print('Predicted Next State:', alert['predicted_next_state'])
