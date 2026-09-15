"""
CyberSentinel FastAPI Backend Entrypoint.
SIH26-26145 — NTRO AI-Based Threat Detection in Unidirectional IP Traffic.

Modularized architecture.
Assembles all routers, static files, and security middleware.
Strictly passive: no packet transmission or payload decryption.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.config import APP_VERSION, CORS_ORIGINS
from backend.app.core.security import assert_passive_compliance
import backend.app.database as db

from backend.app.api import (
    health_router,
    alerts_router,
    flows_router,
    threats_router,
    network_router,
    trajectory_router,
    models_router,
    replay_router,
    websocket_router,
)

# Enforce passive compliance & initialize database
assert_passive_compliance()
db.init_db()

app = FastAPI(
    title="CyberSentinel Threat Detection API",
    description=(
        "SIH26-26145 — Passive AI-powered network threat detection platform. "
        "Detects, explains, correlates, and predicts cyber threats "
        "from unidirectional IP traffic metadata. "
        "No payloads decrypted. No packets transmitted."
    ),
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register modular API routers
app.include_router(health_router)
app.include_router(alerts_router)
app.include_router(flows_router)
app.include_router(threats_router)
app.include_router(network_router)
app.include_router(trajectory_router)
app.include_router(models_router)
app.include_router(replay_router)
app.include_router(websocket_router)

# Mount Frontend static files
FRONTEND_DIR = PROJECT_ROOT / "frontend" / "public"
LEGACY_STATIC_DIR = PROJECT_ROOT / "app" / "static"

static_dir = FRONTEND_DIR if FRONTEND_DIR.exists() else LEGACY_STATIC_DIR
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/", include_in_schema=False)
def serve_root():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"status": "ok", "message": "CyberSentinel Backend Active"}

@app.get("/judge", include_in_schema=False)
def serve_judge():
    judge_path = static_dir / "judge.html"
    if judge_path.exists():
        return FileResponse(str(judge_path))
    legacy_path = LEGACY_STATIC_DIR / "judge.html"
    if legacy_path.exists():
        return FileResponse(str(legacy_path))
    return {"status": "error", "message": "judge.html not found"}
