"""
CyberSentinel WebSocket Manager & Endpoint.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["WebSocket"])

from backend.app.services.broadcast_service import (
    ConnectionManager,
    ws_manager,
    broadcast_sync,
)


@router.websocket("/ws/alerts")
@router.websocket("/ws/live")
async def websocket_alerts_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except (WebSocketDisconnect, Exception):
        await ws_manager.disconnect(ws)
