import re

# Update C2 detector
with open('backend/app/detectors/beaconing/c2_detector.py', 'r', encoding='utf-8') as f:
    c = f.read()
c = re.sub(
    r'PROJECT_ROOT = Path\(__file__\)\.resolve\(\)\.parents\[\d+\]',
    'from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, MODELS_CLASSIFIER_DIR, MODELS_PREPROCESSING_DIR',
    c
)
c = re.sub(
    r'MODEL_PATH = \([^)]+\)',
    'MODEL_PATH = (MODELS_CLASSIFIER_DIR / "c2_hgb.joblib") if (MODELS_CLASSIFIER_DIR / "c2_hgb.joblib").exists() else (MODELS_DIR / "c2_hgb.joblib")',
    c
)
c = re.sub(
    r'SCHEMA_PATH = \([^)]+\)',
    'SCHEMA_PATH = (MODELS_PREPROCESSING_DIR / "c2_feature_schema.json") if (MODELS_PREPROCESSING_DIR / "c2_feature_schema.json").exists() else (MODELS_DIR / "c2_feature_schema.json")',
    c
)
with open('backend/app/detectors/beaconing/c2_detector.py', 'w', encoding='utf-8') as f:
    f.write(c)

# Update DNS detector
with open('backend/app/detectors/dga_dns/dns_detector.py', 'r', encoding='utf-8') as f:
    c = f.read()
c = re.sub(
    r'PROJECT_ROOT = Path\(__file__\)\.resolve\(\)\.parents\[\d+\]',
    'from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, MODELS_CLASSIFIER_DIR',
    c
)
c = re.sub(
    r'MODEL_PATH = \([^)]+\)',
    'MODEL_PATH = (MODELS_CLASSIFIER_DIR / "dns_hgb.joblib") if (MODELS_CLASSIFIER_DIR / "dns_hgb.joblib").exists() else (MODELS_DIR / "dns_hgb.joblib")',
    c
)
with open('backend/app/detectors/dga_dns/dns_detector.py', 'w', encoding='utf-8') as f:
    f.write(c)

# Update Encrypted detector
with open('backend/app/detectors/encrypted_malware/encrypted_detector.py', 'r', encoding='utf-8') as f:
    c = f.read()
c = re.sub(
    r'PROJECT_ROOT = Path\(__file__\)\.resolve\(\)\.parents\[\d+\]',
    'from backend.app.core.config import PROJECT_ROOT, MODELS_DIR, MODELS_ANOMALY_DIR',
    c
)
c = re.sub(
    r'MODEL_PATH = \([^)]+\)',
    'MODEL_PATH = (MODELS_ANOMALY_DIR / "encrypted_hgb.joblib") if (MODELS_ANOMALY_DIR / "encrypted_hgb.joblib").exists() else (MODELS_DIR / "encrypted_hgb.joblib")',
    c
)
with open('backend/app/detectors/encrypted_malware/encrypted_detector.py', 'w', encoding='utf-8') as f:
    f.write(c)

# Update DDoS detector
with open('backend/app/detectors/ddos/dos_detector.py', 'r', encoding='utf-8') as f:
    c = f.read()
c = c.replace(
    'from src.ml_predictor import predict',
    'try:\n    from backend.app.ml.inference import run_inference\n    def predict(df, top_k=5, **kwargs):\n        return run_inference("dos_hgb.joblib", df, threshold=0.5, top_k=top_k)\nexcept Exception:\n    from src.ml_predictor import predict'
)
with open('backend/app/detectors/ddos/dos_detector.py', 'w', encoding='utf-8') as f:
    f.write(c)

print('Detector paths and imports updated successfully.')
