import os

# ML Data Loaders
with open('ml/data/loaders/parquet_loader.py', 'w') as f:
    f.write('import pandas as pd\nfrom pathlib import Path\ndef load_parquet(path: Path) -> pd.DataFrame:\n    return pd.read_parquet(path)\n')

with open('ml/data/loaders/__init__.py', 'w') as f:
    f.write('from .parquet_loader import load_parquet\n')

# ML Validators
with open('ml/data/validators/validate_datasets.py', 'w') as f:
    f.write('import pandas as pd\nfrom pathlib import Path\ndef validate_dataset(df: pd.DataFrame, target_col: str) -> bool:\n    return target_col in df.columns and not df.empty\n')

with open('ml/data/validators/__init__.py', 'w') as f:
    f.write('from .validate_datasets import validate_dataset\n')

# ML Splitters
with open('ml/data/splitters/train_test_split.py', 'w') as f:
    f.write('from sklearn.model_selection import train_test_split\ndef split_data(X, y, test_size=0.25, random_state=42):\n    return train_test_split(X, y, test_size=test_size, random_state=random_state)\n')

with open('ml/data/splitters/__init__.py', 'w') as f:
    f.write('from .train_test_split import split_data\n')

# ML Preprocessing
for fname in ['clean.py', 'encode.py', 'scale.py', 'pipeline.py']:
    with open(f'ml/preprocessing/{fname}', 'w') as f:
        f.write(f'# CyberSentinel Preprocessing - {fname}\nimport pandas as pd\nimport numpy as np\n')

# ML Feature Engineering
for fname in ['network.py', 'dns.py', 'tls.py', 'temporal.py', 'features.py']:
    with open(f'ml/feature_engineering/{fname}', 'w') as f:
        f.write(f'# CyberSentinel Feature Engineering - {fname}\nimport pandas as pd\nimport numpy as np\n')

# ML Training scripts
for fname in ['train_classifier.py', 'train_anomaly.py', 'train_trajectory.py']:
    with open(f'ml/training/{fname}', 'w') as f:
        f.write(f'# CyberSentinel Training - {fname}\nimport joblib\n')

# ML Evaluation metrics & plots
with open('ml/evaluation/metrics.py', 'w') as f:
    f.write('from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score\n\ndef compute_metrics(y_true, y_pred, y_proba=None):\n    return {\n        "accuracy": accuracy_score(y_true, y_pred),\n        "precision": precision_score(y_true, y_pred, zero_division=0),\n        "recall": recall_score(y_true, y_pred, zero_division=0),\n        "f1": f1_score(y_true, y_pred, zero_division=0),\n    }\n')

with open('ml/evaluation/plots.py', 'w') as f:
    f.write('# Evaluation plotting utilities\n')

# ML Standalone Inference
with open('ml/inference/predict.py', 'w') as f:
    f.write('from backend.app.ml.inference import run_inference\ndef predict_flow(model_name: str, df):\n    return run_inference(model_name, df)\n')

# ML Config YAML
with open('ml/configs/model_config.yaml', 'w') as f:
    f.write('''models:
  ddos:
    type: HistGradientBoostingClassifier
    file: dos_hgb.joblib
    threshold: 0.50
  c2:
    type: RandomForestClassifier
    file: c2_hgb.joblib
    threshold: 0.30
  dns:
    type: RandomForestClassifier
    file: dns_hgb.joblib
    threshold: 0.50
  encrypted:
    type: RandomForestClassifier
    file: encrypted_hgb.joblib
    threshold: 0.35
''')

# ML README
with open('ml/README.md', 'w') as f:
    f.write('''# CyberSentinel Machine Learning Subsystem
Contains dataset loaders, feature extractors, model training pipelines, and offline evaluation harnesses.
''')

print('All ML modules created successfully.')
