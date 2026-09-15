#!/usr/bin/env bash
# CyberSentinel Test Suite Runner
export PYTHONPATH=.
echo "=== Running Unit Tests ==="
python backend/tests/unit/test_schemas.py
python tests/unit/test_security_audit.py

echo "=== Running Detector Tests ==="
python tests/integration/test_six_detectors.py

echo "=== Running Integration Tests ==="
python tests/integration/test_integration.py

echo "=== Running Live Pipeline Tests ==="
python tests/integration/test_live_pipeline.py

echo "=== Running E2E Tests ==="
python tests/e2e/test_e2e.py

echo "=== All Tests Complete! ==="
