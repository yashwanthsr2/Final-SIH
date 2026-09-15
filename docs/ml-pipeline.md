# CyberSentinel Machine Learning Pipeline

## Trained Models
1. **DDoS Model (`dos_hgb.joblib`):**
   - Architecture: `HistGradientBoostingClassifier`
   - Performance: Accuracy=100.0%, F1=100.0%, ROC-AUC=1.0000
   - Features: 62 temporal and flow volume statistics
2. **C2 Beaconing Model (`c2_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: ROC-AUC=0.7087, calibrated threshold 0.30
   - Features: Inter-arrival regularity, byte variance, duration
3. **DNS Threat Model (`dns_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: Accuracy=96.1%, F1=84.1%, ROC-AUC=0.9938
   - Features: Query rates, byte concentration, entropy
4. **Encrypted Anomaly Model (`encrypted_hgb.joblib`):**
   - Architecture: `RandomForestClassifier`
   - Performance: ROC-AUC=0.7296
   - Features: Flow duration, bytes-per-flow, port diversity
