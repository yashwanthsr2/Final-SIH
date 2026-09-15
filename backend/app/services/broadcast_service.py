"""
CyberSentinel WebSocket Broadcast Service.
Centralizes connection state management and cross-thread sync/async broadcasting
without coupling application services to the HTTP/WebSocket API routing layer.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from fastapi import WebSocket


class ConnectionManager:
    """
    Manages active WebSocket connections across SOC dashboard clients.
    """

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def connect(self, ws: WebSocket) -> None:
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        await ws.accept()
        async with self._get_lock():
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._get_lock():
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        async with self._get_lock():
            dead = []
            for ws in list(self._connections):
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                if ws in self._connections:
                    self._connections.remove(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Singleton manager instance
ws_manager = ConnectionManager()


def broadcast_sync(message: Dict[str, Any]) -> None:
    """
    Safely dispatches a JSON message to all connected WebSocket clients from any thread.
    """
    # 1. Attempt using recorded event loop from ConnectionManager
    if ws_manager._loop and ws_manager._loop.is_running():
        try:
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), ws_manager._loop)
            return
        except Exception:
            pass

    # 2. Attempt using current running loop
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), loop)
            return
    except Exception:
        pass

    # 3. Fallback to get_event_loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), loop)
        else:
            loop.run_until_complete(ws_manager.broadcast(message))
    except Exception:
        pass
