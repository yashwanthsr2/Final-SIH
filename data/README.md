# CyberSentinel Datasets Repository

## Directory Organization
- `raw/`: Raw packet captures and raw Zeek log bundles (e.g. UWF-ZeekDataSum25-1).
- `processed/`: Curated Parquet feature datasets used for ML model training and evaluation:
  - `ddos_features.parquet`: Multi-feature temporal flow statistics for volumetric DDoS detection.
  - `c2_features.parquet`: Command & Control beaconing and periodic communication patterns.
  - `dns_source_features.parquet`: DNS query rate, volume concentration, and domain tunneling features.
  - `encrypted_source_features.parquet`: TLS/SSL connection duration, byte asymmetry, and flow metrics.
- `sample/`:
  - `small_demo_dataset.csv`: Standalone sample flow dataset for immediate offline verification and lightweight smoke tests.
