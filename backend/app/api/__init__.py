"""
CyberSentinel API Package.
Exports all modular FastAPI routers.
"""

from backend.app.api.health import router as health_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.flows import router as flows_router
from backend.app.api.threats import router as threats_router
from backend.app.api.network import router as network_router
from backend.app.api.trajectory import router as trajectory_router
from backend.app.api.models import router as models_router
from backend.app.api.replay import router as replay_router
from backend.app.api.websocket import router as websocket_router, ws_manager

__all__ = [
    "health_router",
    "alerts_router",
    "flows_router",
    "threats_router",
    "network_router",
    "trajectory_router",
    "models_router",
    "replay_router",
    "websocket_router",
    "ws_manager",
]
