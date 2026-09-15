#!/usr/bin/env bash
# CyberSentinel Server Launch Script
export PYTHONPATH=.
echo "Starting CyberSentinel Unified SOC Platform on http://127.0.0.1:8000..."
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
