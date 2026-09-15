# CyberSentinel Automated Testing Guide

## Running Tests
```bash
# Unit & Security tests
python backend/tests/unit/test_schemas.py
python tests/unit/test_security_audit.py

# Detector tests
python tests/integration/test_six_detectors.py

# Integration & E2E tests
python tests/integration/test_integration.py
python tests/e2e/test_e2e.py

# Benchmark
python tests/performance/benchmark_performance.py
```
