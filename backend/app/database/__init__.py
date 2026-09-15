"""
CyberSentinel Database Package.
Exposes connection management, schema initialization, and repository functions.
"""

from backend.app.database.connection import get_connection, init_db
from backend.app.database.models import SCHEMA_SQL
from backend.app.database.repositories.alert_repo import (
    insert_alert,
    get_alerts,
    get_alert_by_id,
    count_alerts,
    clear_alerts,
    get_threat_summary,
)
from backend.app.database.repositories.flow_repo import (
    insert_flow,
    get_flows,
    count_flows,
    get_timeline,
)
from backend.app.database.repositories.system_repo import (
    upsert_threat_state,
    get_threat_state,
    upsert_model_metadata,
    get_all_models,
    insert_metric,
    get_recent_metrics,
)

__all__ = [
    "get_connection",
    "init_db",
    "SCHEMA_SQL",
    "insert_alert",
    "get_alerts",
    "get_alert_by_id",
    "count_alerts",
    "clear_alerts",
    "get_threat_summary",
    "insert_flow",
    "get_flows",
    "count_flows",
    "get_timeline",
    "upsert_threat_state",
    "get_threat_state",
    "upsert_model_metadata",
    "get_all_models",
    "insert_metric",
    "get_recent_metrics",
]
