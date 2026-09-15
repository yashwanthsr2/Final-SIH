# CyberSentinel Team Development & Ownership Map
**Project**: CyberSentinel — AI-Based Cyber Threat Intelligence in Unidirectional IP Traffic  
**Hackathon**: Smart India Hackathon (SIH26-26145 / NTRO)  
**Architecture Goal**: Clean Architecture • Easy Parallel Development • Independent Testing • Stable Integration

---

## Team Ownership Matrix

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    MEMBER 3: TEAM LEAD                                      │
│                Architecture • Core Pipeline Orchestration • Correlation & Risk              │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
             ┌─────────────────────────────────┼─────────────────────────────────┐
             │                                 │                                 │
             ▼                                 ▼                                 ▼
   ┌────────────────────┐            ┌────────────────────┐            ┌────────────────────┐
   │ MEMBER 5: DATA/FEAT│            │ MEMBER 2: CYBERSEC │            │   MEMBER 1: ML/AI  │
   │ Ingestion & Flows  │───────────►│ 6 Detectors & Live │───────────►│ Models & Inference │
   │ Parquet Features   │            │ Security Boundary  │            │ Explainability     │
   └────────────────────┘            └────────────────────┘            └────────────────────┘
             │                                 │                                 │
             └─────────────────────────────────┼─────────────────────────────────┘
                                               │
             ┌─────────────────────────────────┴─────────────────────────────────┐
             │                                                                   │
             ▼                                                                   ▼
   ┌───────────────────────────────────┐               ┌───────────────────────────────────┐
   │      MEMBER 6: FRONTEND / UI      │               │       MEMBER 4: DEVOPS / QA       │
   │ SOC Dashboard • Network Graph     │               │ CI/CD • Docker • Test Automation  │
   │ MITRE Trajectory Visualization    │               │ Regression Benchmark & Hygiene    │
   └───────────────────────────────────┘               └───────────────────────────────────┘
```

---

## Role 1: Member 1 — AI / ML

### Focus
Machine learning model development, offline training pipelines, hyperparameter optimization, model serialization, model card documentation, decision tree attribution (Saabas decomposition) for explainability, and inference throughput.

### Exact Folders
- [`ml/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/) (entire ML subsystem: `training/`, `evaluation/`, `inference/`, `configs/`, `preprocessing/`)
- [`backend/app/ml/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ml/) (production inference runtime)
- [`backend/app/explainability/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/explainability/)
- [`models/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/models/) (`classifier/`, `anomaly/`, `preprocessing/`, `trajectory/`)

### Exact Files
- [`ml/training/train_classifier.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/training/train_classifier.py)
- [`ml/training/train_anomaly.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/training/train_anomaly.py)
- [`ml/training/train_trajectory.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/training/train_trajectory.py)
- [`ml/evaluation/evaluate.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/evaluation/evaluate.py)
- [`ml/evaluation/metrics.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/evaluation/metrics.py)
- [`ml/evaluation/plots.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/evaluation/plots.py)
- [`ml/configs/model_config.yaml`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/configs/model_config.yaml)
- [`backend/app/ml/inference.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ml/inference.py)
- [`backend/app/ml/model_loader.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ml/model_loader.py)
- [`backend/app/ml/preprocessing.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ml/preprocessing.py)
- [`backend/app/explainability/explainer.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/explainability/explainer.py)
- [`evaluate_ml_models.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/evaluate_ml_models.py)
- Model cards: [`models/DDoS_MODEL_CARD.md`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/models/DDoS_MODEL_CARD.md)

### Responsibilities
1. Train and tune the four core ML models:
   - `dos_hgb.joblib` (HistGradientBoosting / Temporal flow rates)
   - `c2_hgb.joblib` (RandomForest/HGB / Periodic beaconing intervals & byte regularity)
   - `dns_hgb.joblib` (RandomForest/HGB / DGA character entropy & query frequency)
   - `encrypted_hgb.joblib` (IsolationForest/HGB / Unseen TLS cipher/extension anomalies)
2. Generate Saabas decision-tree attributions without slow external SHAP dependencies.
3. Keep models loaded cleanly via `model_loader.py` with feature alignment and fallback paths.
4. Guarantee zero mock/fake model accuracy numbers in evaluation reports.

### Dependencies on Other Members
- **From Member 5 (Data/Features)**: Requires clean parquet datasets in `data/processed/` with standardized column schemas.
- **From Member 2 (Network/Cybersecurity)**: Requires domain feature requests (e.g. DNS entropy metrics, beaconing delta times).

### What They Can Work on Independently
- Experimenting with new ML algorithms in `ml/training/`.
- Optimizing model hyperparameters in `ml/configs/model_config.yaml`.
- Generating evaluation plots, confusion matrices, and ROC curves in `ml/evaluation/`.
- Benchmarking model inference latency with `python evaluate_ml_models.py`.

### Must Be Reviewed Before Merging
- Any changes to `models/preprocessing/*_feature_schema.json` (breaking for Member 5 & Member 2).
- Updating production binary weights (`models/*.joblib`) requires validation by Member 4 (QA).

---

## Role 2: Member 2 — Network / Cybersecurity

### Focus
Threat detection heuristics, passive sensor integration (Zeek & Scapy live capture), strict read-only compliance (no injection/decryption), normal traffic baseline profiling, attack simulation scenarios.

### Exact Folders
- [`backend/app/detectors/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/) (`ddos/`, `beaconing/`, `dga_dns/`, `encrypted_malware/`, `reconnaissance/`, `exfiltration/`)
- [`sensor/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/sensor/) (`live_capture/`, `zeek/`)
- [`simulator/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/simulator/) (`scenarios/`)
- [`src/detectors/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/src/detectors/) (backward-compatibility shims)

### Exact Files
- [`backend/app/detectors/ddos/dos_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/ddos/dos_detector.py)
- [`backend/app/detectors/beaconing/c2_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/beaconing/c2_detector.py)
- [`backend/app/detectors/dga_dns/dns_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/dga_dns/dns_detector.py)
- [`backend/app/detectors/encrypted_malware/encrypted_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/encrypted_malware/encrypted_detector.py)
- [`backend/app/detectors/reconnaissance/recon_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/reconnaissance/recon_detector.py)
- [`backend/app/detectors/exfiltration/exfil_detector.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/detectors/exfiltration/exfil_detector.py)
- [`backend/app/core/baseline_engine.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/core/baseline_engine.py)
- [`backend/app/core/security.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/core/security.py)
- [`sensor/live_capture/interface_manager.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/sensor/live_capture/interface_manager.py)
- [`sensor/live_capture/sensor_manager.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/sensor/live_capture/sensor_manager.py)
- [`sensor/zeek/parsers/conn_parser.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/sensor/zeek/parsers/conn_parser.py)
- [`run_kali_sensor.sh`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/run_kali_sensor.sh)
- [`simulator/replay.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/simulator/replay.py)
- [`simulate_wifi_attack.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/simulate_wifi_attack.py)

### Responsibilities
1. Implement heuristic logic for Reconnaissance (SYN-to-total ratio, destination port entropy) and Exfiltration (volume asymmetry ratio, destination concentration).
2. Tune detector confidence thresholds to maintain low false positive rates.
3. Maintain the `BaselineEngine` to profile legitimate browsing (YouTube, Netflix, Zoom, Google CDN) and suppress false positives.
4. Enforce SIH26-26145 passive compliance: ZERO packet transmission, ZERO endpoint probing, ZERO payload decryption.
5. Create realistic attack replay scenarios (`simulator/scenarios/*.json`).

### Dependencies on Other Members
- **From Member 1 (AI/ML)**: ML prediction functions from `backend.app.ml.inference`.
- **From Member 5 (Data/Features)**: `NormalizedFlow` representations and extracted behavioral features.

### What They Can Work on Independently
- Writing detector heuristic algorithms and threshold tuners.
- Creating and curating attack scenario JSON files in `simulator/scenarios/`.
- Testing Zeek live tailing and Scapy passive sniffing on Kali/Linux environments.
- Running `python test_six_detectors.py`.

### Must Be Reviewed Before Merging
- Changes to `backend/app/core/security.py` (passive compliance cannot be bypassed).
- Modifications to detector return dictionaries (must match `backend.app.schemas.threat`).

---

## Role 3: Member 3 — Team Lead / Integration

### Focus
Overall architecture convergence, core pipeline orchestration, multi-signal threat correlation, 4-part transparent risk scoring, Markov attack trajectory prediction, digital twin topology graph, API contract governance.

### Exact Folders
- [`backend/app/correlation/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/correlation/)
- [`backend/app/risk/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/risk/)
- [`backend/app/prediction/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/prediction/)
- [`backend/app/digital_twin/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/digital_twin/)
- [`backend/app/api/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/) (all REST & WebSocket routers)
- [`backend/app/services/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/)
- [`docs/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docs/) (`architecture.md`, `api.md`, `detectors.md`, `data-pipeline.md`)

### Exact Files
- [`backend/app/main.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/main.py)
- [`backend/app/core/config.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/core/config.py)
- [`backend/app/correlation/engine.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/correlation/engine.py)
- [`backend/app/risk/scoring.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/risk/scoring.py)
- [`backend/app/prediction/trajectory_engine.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/prediction/trajectory_engine.py)
- [`backend/app/digital_twin/graph.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/digital_twin/graph.py)
- [`backend/app/services/alert_service.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/alert_service.py)
- [`backend/app/services/replay_service.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/replay_service.py)
- [`backend/app/services/broadcast_service.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/broadcast_service.py)
- [`backend/app/api/alerts.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/alerts.py)
- [`backend/app/api/flows.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/flows.py)
- [`backend/app/api/health.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/health.py)
- [`backend/app/api/metrics.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/metrics.py)
- [`backend/app/api/network.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/network.py)
- [`backend/app/api/replay.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/replay.py)
- [`backend/app/api/threats.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/threats.py)
- [`backend/app/api/trajectory.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/trajectory.py)
- [`backend/app/api/websocket.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/api/websocket.py)
- [`docs/architecture.md`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docs/architecture.md)
- [`docs/api.md`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docs/api.md)

### Responsibilities
1. Oversee the complete 10-stage pipeline convergence:
   `INPUT ➔ INGESTION ➔ NORMALIZATION ➔ FEATURES ➔ DETECTORS ➔ ML ➔ CORRELATION ➔ RISK ➔ EXPLAINABILITY ➔ TRAJECTORY ➔ ALERT ➔ DB ➔ WEBSOCKET`
2. Maintain the Threat Correlation Engine (kill chain state matching across time windows).
3. Calibrate the 4-part transparent Risk Formula (Confidence 40%, Severity 30%, Correlation 20%, Persistence 10%).
4. Maintain the Markov predictive state machine and MITRE ATT&CK next-technique forecast.
5. Govern API endpoint contracts and review all pull requests before merging to `main`.

### Dependencies on Other Members
- Consumes components from Member 1 (ML), Member 2 (Detectors), and Member 5 (Flows/Features).
- Supplies API contracts and real-time WebSocket feeds to Member 6 (Frontend).
- Coordinates with Member 4 (DevOps) for CI/CD gates and deployment environments.

### What They Can Work on Independently
- Tuning correlation kill-chain rules and time windows.
- Refining Markov state transitions and trajectory prediction matrices.
- Updating digital twin topology scoring logic.
- Reviewing PRs and maintaining architectural documentation.

### Shared Integration Files (Sole Modifier)
- See dedicated section at the bottom of this document.

---

## Role 4: Member 4 — DevOps / Git / QA

### Focus
Continuous integration & testing automation, Docker containerization, multi-platform runtime verification (Windows/Linux/Docker), security auditing, performance benchmarking, clean installation validation, git hygiene.

### Exact Folders
- [`.github/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.github/) (`workflows/`, `ISSUE_TEMPLATE/`)
- [`tests/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/) (`unit/`, `integration/`, `e2e/`, `performance/`)
- Root build, environment, and launch scripts

### Exact Files
- [`.github/workflows/ci.yml`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.github/workflows/ci.yml)
- [`.github/pull_request_template.md`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.github/pull_request_template.md)
- [`Dockerfile`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/Dockerfile) & [`backend/Dockerfile`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/Dockerfile) & [`frontend/Dockerfile`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/frontend/Dockerfile)
- [`docker-compose.yml`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docker-compose.yml)
- [`.dockerignore`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.dockerignore)
- [`.gitignore`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.gitignore)
- [`.env.example`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/.env.example)
- [`requirements.txt`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/requirements.txt) & [`backend/requirements.txt`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/requirements.txt)
- [`Makefile`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/Makefile)
- [`run_server.ps1`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/run_server.ps1)
- [`scripts/start.sh`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/scripts/start.sh), [`scripts/stop.sh`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/scripts/stop.sh), [`scripts/setup.sh`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/scripts/setup.sh), [`scripts/test.sh`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/scripts/test.sh)
- [`scripts/verify_clean_installation.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/scripts/verify_clean_installation.py)
- [`tests/unit/test_security_audit.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/unit/test_security_audit.py)
- [`tests/unit/test_schemas.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/unit/test_schemas.py)
- [`tests/integration/test_six_detectors.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/integration/test_six_detectors.py)
- [`tests/integration/test_integration.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/integration/test_integration.py)
- [`tests/integration/test_canonical_pipeline_convergence.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/integration/test_canonical_pipeline_convergence.py)
- [`tests/integration/test_live_pipeline.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/integration/test_live_pipeline.py)
- [`tests/e2e/test_all_apis.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/e2e/test_all_apis.py)
- [`tests/e2e/test_live_replay.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/e2e/test_live_replay.py)
- [`tests/e2e/test_e2e.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/e2e/test_e2e.py)
- [`tests/performance/benchmark_performance.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/tests/performance/benchmark_performance.py)

### Responsibilities
1. Maintain the automated CI/CD pipeline in GitHub Actions (`.github/workflows/ci.yml`).
2. Maintain Docker multi-container builds (`docker-compose.yml`) ensuring both backend and frontend reverse proxy spin up cleanly.
3. Enforce strict repository hygiene (zero committed `.env`, zero private keys, zero `.pyc` or scratch dumps).
4. Run regression performance benchmarks and ensure clean installation (`verify_clean_installation.py`) passes 100% across all 9 phases.
5. Maintain shell and PowerShell launchers.

### Dependencies on Other Members
- **From Member 3 (Team Lead)**: Stable API endpoint definitions for E2E testing.
- **From Member 6 (Frontend)**: Static asset build outputs and `nginx.conf` routing rules.

### What They Can Work on Independently
- Writing additional unit, integration, and fuzz test suites in `tests/`.
- Optimizing Docker multi-stage build caching and image size.
- Updating CI/CD matrix runners and test reporting.
- Running load and latency stress benchmarks.

### Must Be Reviewed Before Merging
- Modifications to `requirements.txt` or Docker base images (affects everyone's environments).
- Alterations to CI gate pass criteria or disabled test assertions.

---

## Role 5: Member 5 — Data / Features

### Focus
Network traffic ingestion, metadata normalization (`NormalizedFlow`), behavioral feature extraction pipeline (flow, timing, DNS, TLS, statistical), batch Parquet loaders, dataset validation.

### Exact Folders
- [`backend/app/features/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/)
- [`backend/app/ingestion/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/)
- [`backend/app/schemas/flow.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/schemas/flow.py)
- [`data/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/data/) (`processed/`, `sample/`, `modern_2025/`, `raw/`)
- [`ml/data/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/data/) (`loaders/`, `splitters/`, `validators/`)

### Exact Files
- [`backend/app/schemas/flow.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/schemas/flow.py) (`NormalizedFlow`)
- [`backend/app/features/feature_pipeline.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/feature_pipeline.py)
- [`backend/app/features/flow_features.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/flow_features.py)
- [`backend/app/features/timing_features.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/timing_features.py)
- [`backend/app/features/dns_features.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/dns_features.py)
- [`backend/app/features/tls_features.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/tls_features.py)
- [`backend/app/features/statistical_features.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/features/statistical_features.py)
- [`backend/app/ingestion/base.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/base.py)
- [`backend/app/ingestion/live_interface.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/live_interface.py)
- [`backend/app/ingestion/zeek_ingest.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/zeek_ingest.py)
- [`backend/app/ingestion/pcap_ingest.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/pcap_ingest.py)
- [`backend/app/ingestion/csv_ingest.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/ingestion/csv_ingest.py)
- [`ml/data/validators/validate_datasets.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/data/validators/validate_datasets.py)
- [`ml/data/loaders/parquet_loader.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/data/loaders/parquet_loader.py)
- [`ml/data/splitters/train_test_split.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/ml/data/splitters/train_test_split.py)
- [`validate_datasets_full.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/validate_datasets_full.py)

### Responsibilities
1. Maintain `NormalizedFlow` as the single universal metadata contract for all four traffic inputs (Dataset Parquet, CSV Replay, PCAP Replay, Live Wi-Fi).
2. Extract L3/L4, timing, DNS, TLS, and statistical features without inspecting decrypted packet payloads.
3. Compute packet length entropy, inter-arrival variance, and DNS Shannon entropy.
4. Curate modern 2025 datasets (`data/modern_2025/`, CTU-13, CIC-IDS) and maintain preprocessed Parquet files in `data/processed/`.
5. Ensure zero target leakage in feature extraction.

### Dependencies on Other Members
- **From Member 2 (Network/Cybersecurity)**: Protocol field formats from Zeek (`conn.log`, `dns.log`, `ssl.log`) and Scapy.
- **From Member 1 (AI/ML)**: Model training feature sets and expected column names.

### What They Can Work on Independently
- Adding new feature engineering algorithms (e.g. wavelet timing entropy, burst ratios).
- Curating and converting raw network captures into Parquet feature sets.
- Running dataset validation via `python validate_datasets_full.py`.
- Improving Scapy and Zeek normalization performance.

### Must Be Reviewed Before Merging
- Changing `NormalizedFlow` schema fields in `flow.py`.
- Renaming feature keys in `feature_pipeline.py` (affects Member 1's models and Member 2's detectors).

---

## Role 6: Member 6 — Frontend / Visualization

### Focus
Unified SOC Dashboard, real-time WebSocket alert streaming, dynamic Digital Twin network graph visualization, MITRE ATT&CK attack trajectory timeline, interactive controls (replay, baseline learning, export), premium visual styling.

### Exact Folders
- [`frontend/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/frontend/) (`public/`, `nginx.conf`, `Dockerfile`)
- [`app/static/`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/app/static/) (compatibility static directory)

### Exact Files
- [`frontend/public/index.html`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/frontend/public/index.html) (single-page dashboard application)
- [`frontend/nginx.conf`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/frontend/nginx.conf)
- [`frontend/Dockerfile`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/frontend/Dockerfile)
- [`docs/demo.md`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docs/demo.md) (SOC demo walkthrough guide)

### Responsibilities
1. Present real-time telemetry from the backend with ZERO mock or hardcoded production data.
2. Render the interactive Digital Twin network graph (interactive canvas/DOM with force-directed physics, node risk coloring, and edge traffic counters).
3. Display the 7-stage attack trajectory stepper (NORMAL ➔ RECON ➔ WEAPONIZATION ➔ DELIVERY ➔ EXPLOITATION ➔ C2 ➔ EXFILTRATION).
4. Provide interactive controls: Replay start/stop, speed multiplier (1x-50x), scenario selector, baseline learning toggle, alert filters (Severity, Threat Class), and CSV/JSON export.
5. Handle real-time WebSocket updates (`/ws/alerts`) with automatic reconnection and status pill indicators.

### Dependencies on Other Members
- **From Member 3 (Team Lead)**: REST API endpoint schemas (`/api/alerts`, `/api/flows`, `/api/network`, `/api/trajectory`, `/api/metrics`) and WebSocket schema.
- **From Member 4 (DevOps)**: Nginx reverse-proxy setup and host port mapping.

### What They Can Work on Independently
- Enhancing dashboard UI, layout responsiveness, glassmorphism styling, and chart animations.
- Adding frontend filters, search inputs, sorting, and tabular views.
- Improving canvas/graph performance and touch/mouse interaction.
- Adding UI audio/visual toast notifications for CRITICAL alerts.

### Must Be Reviewed Before Merging
- Changes to API endpoint URLs, query parameters, or payload formatting.
- Changes to Nginx reverse-proxy routing rules in `frontend/nginx.conf`.

---

## Shared Integration Files (Team Lead Only Modification)

> [!CAUTION]
> The following files define core cross-system boundaries. Any uncoordinated modification can break multiple team members' builds simultaneously. **Only Member 3 (Team Lead) may commit direct changes to these files, following consensus review with affected members.**

| File | Subsystems Impacted | Why It Is Guarded |
|---|---|---|
| [`backend/app/schemas/alert.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/schemas/alert.py) | ML, Detectors, Risk, Trajectory, API, Frontend | Defines `UnifiedAlert`. Every detector, DB record, WebSocket packet, and frontend card parses this schema. |
| [`backend/app/schemas/flow.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/schemas/flow.py) | Ingestion, Features, Detectors, ML, DB | Defines `NormalizedFlow`. Changes here cascade into all feature extraction functions. |
| [`backend/app/core/config.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/core/config.py) | All 6 Members | Centralizes environment variables, directory paths, ports, and model paths. |
| [`backend/app/main.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/main.py) | API, Frontend, DevOps | The FastAPI application entrypoint mounting all routers, CORS middleware, and static assets. |
| [`backend/app/services/alert_service.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/alert_service.py) | All Backend Subsystems | Orchestrates the entire 10-stage execution pipeline for every flow. |
| [`backend/app/services/broadcast_service.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/services/broadcast_service.py) | Services, API, Frontend | Manages WebSocket connections and thread-safe cross-subsystem event broadcasting. |
| [`backend/app/database/connection.py`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/backend/app/database/connection.py) | Services, API, DevOps | SQLite schema definition, table creation, and connection pooling. |
| [`docker-compose.yml`](file:///c:/Users/sryas/OneDrive/Desktop/SIH%20CYBER/CODEZILLA-SIH26145/docker-compose.yml) | DevOps, Frontend, Team Lead | Defines the multi-container topology, port bindings, networks, and persistent volumes. |

---

## Git Workflow & Merge Protocol

1. **Branch Naming**:
   - `member1/ml-...`
   - `member2/cybersec-...`
   - `member3/integration-...`
   - `member4/devops-...`
   - `member5/data-...`
   - `member6/frontend-...`
2. **Local Pre-Commit Verification**:
   Before opening a pull request, run:
   ```bash
   python tests/unit/test_schemas.py
   python tests/unit/test_security_audit.py
   python tests/integration/test_six_detectors.py
   python tests/integration/test_integration.py
   ```
3. **PR Merge Requirement**:
   - GitHub Actions CI must pass 100%.
   - At least 1 review approval from Member 3 (Team Lead).
   - Zero hardcoded mock data in production files.
