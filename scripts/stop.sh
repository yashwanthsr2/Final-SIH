#!/usr/bin/env bash
# CyberSentinel Server Stop Script
echo "Stopping CyberSentinel server..."
pkill -f "uvicorn.*backend.app.main:app" || echo "No active server process found."
