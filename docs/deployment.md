# CyberSentinel Deployment Guide

## Standalone Host
```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

## Docker Compose
```bash
docker compose up --build
```
