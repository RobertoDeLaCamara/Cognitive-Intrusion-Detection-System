"""WebSocket endpoint for real-time alert streaming (Phase 6).

Authentication follows what the deployment configures:

* JWT (``JWT_SECRET``): connect with ``?token=<JWT>``. When JWT is enabled it is
  the only accepted credential, even if ``API_KEY`` is also set: the REST layer
  enforces roles from the JWT, and the legacy key must not be a way around them.
* API key only (``API_KEY``, no JWT): connect with the ``X-API-Key`` header, or
  ``?key=<API_KEY>`` for clients that cannot set headers (browsers). Query strings
  end up in proxy logs, so prefer the header where possible.
* Neither (``AUTH_DISABLED=true``): open.

The HTTP API-key middleware does not run for WebSocket connections, so this
handler has to check the credentials itself.
"""

import asyncio
import hmac
import json
import logging
from typing import Optional, Set, Tuple

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette.websockets import WebSocketState

from ..auth import is_enabled as jwt_enabled, decode_token
from ...config import API_KEY

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


def _authorize(token: Optional[str], key: Optional[str]) -> Optional[Tuple[int, str]]:
    """Return None when the connection is allowed, else (close_code, reason)."""
    if jwt_enabled():
        # JWT supersedes the legacy API key (see the module docstring).
        if not token:
            return 4001, "Missing token"
        try:
            decode_token(token)
            return None
        except Exception:
            return 4003, "Invalid or expired token"

    if API_KEY:
        if not key:
            return 4001, "Missing API key"
        if hmac.compare_digest(key.encode(), API_KEY.encode()):
            return None
        return 4003, "Invalid API key"

    return None  # authentication is disabled (AUTH_DISABLED=true)


@router.websocket("/ws/alerts")
async def alerts_ws(
    websocket: WebSocket,
    token: str = Query(default=None),
    key: str = Query(default=None),
):
    """WebSocket endpoint — clients receive real-time alert JSON messages.

    Requires a JWT (?token=) when JWT is enabled, otherwise the API key
    (X-API-Key header or ?key=) when one is configured. Max concurrent connections: 100.
    """
    denied = _authorize(token, websocket.headers.get("x-api-key") or key)
    if denied:
        code, reason = denied
        await websocket.close(code=code, reason=reason)
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
