"""
CyberSentinel application configuration.

Reads from environment variables (.env file or system env).
No secrets are committed. Copy .env.example to .env to customise.
"""

from __future__ import annotations

import os
from pathlib import Path

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
EVALUATION_DIR = PROJECT_ROOT / "evaluation"

# ============================================================
# DATABASE
# ============================================================

DB_PATH = Path(os.getenv("CYBERSENTINEL_DB", str(PROJECT_ROOT / "db" / "cybersentinel.db")))

# ============================================================
# API
# ============================================================

API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# ============================================================
# REPLAY
# ============================================================

# Seconds per event at 1x replay speed
REPLAY_BASE_INTERVAL = float(os.getenv("REPLAY_BASE_INTERVAL", "0.5"))

# ============================================================
# ALERT STORE
# ============================================================

MAX_ALERTS_MEMORY = int(os.getenv("MAX_ALERTS_MEMORY", "500"))

# ============================================================
# DIGITAL TWIN
# ============================================================

# Maximum nodes to keep in memory (oldest evicted first)
TWIN_MAX_NODES = int(os.getenv("TWIN_MAX_NODES", "2000"))

# Seconds before a node is considered stale
TWIN_NODE_TTL = int(os.getenv("TWIN_NODE_TTL", "600"))

# ============================================================
# VERSIONING
# ============================================================

APP_VERSION = "1.2.0"
MODEL_VERSION = "v1.0"
