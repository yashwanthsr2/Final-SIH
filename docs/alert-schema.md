# CyberSentinel Unified Alert Schema

## JSON Schema Example
```json
{
  "alert_id": "c1f7a4e2-...",
  "timestamp": 1773489201.5,
  "prediction": "THREAT",
  "severity": "HIGH",
  "score": 0.85,
  "confidence": 0.85,
  "risk_score": 88,
  "primary_threat": "C2",
  "threat_class": "C2",
  "source": "192.168.1.105",
  "destination": "198.51.100.24",
  "protocol": "TCP",
  "current_state": "C2",
  "predicted_next_state": "EXFILTRATION",
  "prediction_confidence": 0.60,
  "correlated": true,
  "correlated_threats": ["RECON", "C2"],
  "correlation_pattern": "RECON_TO_C2",
  "evidence": [
    {"feature": "iat_mean", "value": 9.60, "contribution": 0.35}
  ]
}
```
