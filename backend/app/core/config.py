"""
CyberSentinel Application Configuration.

Reads from environment variables and configuration files.
Centralizes all directories, ports, and operational modes.
Strictly passive: no packet transmission or payload decryption allowed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

# ============================================================
# PROJECT PATHS
# ============================================================

# backend/app/core -> backend/app -> backend -> CyberSentinel root
PROJECT_ROOT = Path(__file__).resolve().parents[3]

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_CLASSIFIER_DIR = MODELS_DIR / "classifier"
MODELS_ANOMALY_DIR = MODELS_DIR / "anomaly"
MODELS_TRAJECTORY_DIR = MODELS_DIR / "trajectory"
MODELS_PREPROCESSING_DIR = MODELS_DIR / "preprocessing"

DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
DATA_SAMPLE_DIR = DATA_DIR / "sample"

EVALUATION_DIR = PROJECT_ROOT / "evaluation"
CONFIGS_DIR = PROJECT_ROOT / "configs"

# ============================================================
# DATABASE
# ============================================================

DB_PATH = Path(os.getenv("CYBERSENTINEL_DB", os.getenv("CYBERSENTINEL_DB_PATH", str(PROJECT_ROOT / "db" / "cybersentinel.db"))))

# Ensure DB directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ============================================================
# API & SERVER
# ============================================================

API_HOST = os.getenv("CYBERSENTINEL_HOST", os.getenv("API_HOST", "127.0.0.1"))
API_PORT = int(os.getenv("CYBERSENTINEL_PORT", os.getenv("API_PORT", "8000")))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# ============================================================
# PASSIVE SENSOR & LIVE MONITORING
# ============================================================

LIVE_INTERFACE = os.getenv("LIVE_INTERFACE", "")
PASSIVE_ONLY = os.getenv("PASSIVE_ONLY", "true").lower() in ("true", "1", "yes")
NO_PAYLOAD_DECRYPTION = os.getenv("NO_PAYLOAD_DECRYPTION", "true").lower() in ("true", "1", "yes")
DEFAULT_WINDOW_SECONDS = int(os.getenv("DEFAULT_WINDOW_SECONDS", "5"))

# ============================================================
# REPLAY & BUFFERS
# ============================================================

REPLAY_BASE_INTERVAL = float(os.getenv("REPLAY_BASE_INTERVAL", "0.5"))
MAX_ALERTS_MEMORY = int(os.getenv("MAX_ALERTS_MEMORY", "500"))
TWIN_MAX_NODES = int(os.getenv("TWIN_MAX_NODES", "2000"))
TWIN_NODE_TTL = int(os.getenv("TWIN_NODE_TTL", "600"))

# ============================================================
# VERSIONING
# ============================================================

APP_VERSION = "1.2.0"
MODEL_VERSION = "v1.0"
