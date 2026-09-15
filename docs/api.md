# CyberSentinel REST API Documentation

## Core Endpoints
- `GET /health` or `GET /api/health`: System health and passive verification
- `GET /api/metrics`: Performance telemetry, flows count, alert count
- `GET /api/alerts`: Historical alerts with filtering
- `POST /detect`: Synchronous flow analysis through all 6 detectors
- `GET /api/flows`: Flow metadata query
- `GET /api/network`: Digital twin graph topology
- `GET /api/trajectory`: Probabilistic attack predictions
- `GET /api/models`: Model registry status
- `POST /demo/run-all`: Replay full multi-scenario attack suite
