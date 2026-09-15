#!/usr/bin/env bash
# CyberSentinel Environment Setup Script
set -e

echo "=== CyberSentinel Environment Setup ==="
python -m pip install --upgrade pip
pip install -r backend/requirements.txt

echo "Creating runtime directories..."
mkdir -p db models/classifier models/anomaly models/trajectory models/preprocessing data/raw data/processed data/sample zeek_logs

echo "Setup complete! Run ./scripts/start.sh to launch."
