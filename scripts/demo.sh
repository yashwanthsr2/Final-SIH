#!/usr/bin/env bash
# CyberSentinel Demo Replay Runner
URL=${1:-"http://127.0.0.1:8000"}
echo "Triggering all verified attack scenarios against $URL..."
curl -X POST "$URL/demo/run-all" -H "Content-Type: application/json"
echo ""
echo "Demo completed! Check the dashboard at $URL/"
