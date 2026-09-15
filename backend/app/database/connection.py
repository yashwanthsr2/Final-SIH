"""
CyberSentinel Database Connection & Lifecycle Manager.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from backend.app.core.config import DB_PATH
from backend.app.database.models import SCHEMA_SQL

_local = threading.local()

def get_connection() -> sqlite3.Connection:
    """Return a thread-local SQLite connection, creating it if needed."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn

def init_db() -> None:
    """Create all tables and indices if they do not exist."""
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.commit()
