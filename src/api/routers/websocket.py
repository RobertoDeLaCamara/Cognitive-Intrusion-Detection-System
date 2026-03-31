"""WebSocket endpoint for real-time alert streaming (Phase 6).

When JWT auth is enabled, clients must connect with a token query parameter:
    ws://host:8000/ws/alerts?token=<JWT>
"""

import asyncio
import json
import logging
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette.websockets import WebSocketState

from ..auth import is_enabled as jwt_enabled, decode_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# Connected clients
_clients: Set[WebSocket] = set()
_lock = asyncio.Lock()
_MAX_WS_CLIENTS = 100


async def broadcast_alert(alert_data: dict) -> None:
    """Broadcast an alert to all connected WebSocket clients."""
    if not _clients:
        return
    message = json.dumps(alert_data, default=str)
    async with _lock:
        disconnected = set()
        for ws in _clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.add(ws)
        _clients.difference_update(disconnected)


@router.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket, token: str = Query(default=None)):
    """WebSocket endpoint — clients receive real-time alert JSON messages.

    When JWT_SECRET is set, requires ?token=<JWT> query parameter.
    Max concurrent connections: 100.
    """
    # Authenticate if JWT is enabled
    if jwt_enabled():
        if not token:
            await websocket.close(code=4001, reason="Missing token")
            return
        try:
            decode_token(token)
        except Exception:
            await websocket.close(code=4003, reason="Invalid or expired token")
            return

    # Connection limit
    async with _lock:
        if len(_clients) >= _MAX_WS_CLIENTS:
            await websocket.close(code=4029, reason="Too many connections")
            return

    await websocket.accept()
    async with _lock:
        _clients.add(websocket)
    logger.info("WebSocket client connected (%d total)", len(_clients))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with _lock:
            _clients.discard(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_clients))
