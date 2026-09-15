# Changelog

All notable changes to CyberSentinel will be documented in this file.

## [1.2.0] - 2026-09-13
### Added
- Enterprise GitHub repository architecture reorganization.
- Modularized FastAPI backend into `backend/app/api/`, `core/`, `schemas/`, `services/`, `detectors/`, `ml/`, `ingestion/`.
- Modular frontend architecture under `frontend/src/` with React/TypeScript components, pages, services, and hooks.
- Dedicated `ml/` subsystem with data loaders, preprocessing, feature engineering, and evaluation scripts.
- Dedicated `sensor/` subsystem with Zeek parsers and Wi-Fi interface management.
- Dedicated `simulator/` subsystem with verified attack scenario JSON payloads.
- Automated GitHub Actions workflows for CI, backend tests, frontend tests, and passive security scanning.
- Complete 10-document technical manual under `docs/`.

### Fixed
- Console Unicode arrow encoding crash on Windows consoles.
- Multi-signal pattern matching priority in threat correlation engine.
- Missing feature importances evidence for HistGradientBoosting models.
- Duplicate page layout container in static dashboard.

## [1.1.0] - 2026-09-12
### Added
- Real-time passive Wi-Fi monitoring support via Scapy and Zeek.
- Dynamic false positive suppression baseline engine for YouTube/Google streaming.

## [1.0.0] - 2026-09-10
### Added
- Initial release for Smart India Hackathon (SIH26-26145 / NTRO).
- Six threat detectors (DDoS, C2, DNS, Encrypted, Recon, Exfil).
- Predictive Markov attack trajectory and Digital Twin graph.
