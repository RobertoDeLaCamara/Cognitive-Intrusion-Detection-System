"""WebSocket /ws/alerts consumer for the CNDS sandbox.

Connects to the real-time alert stream and collects messages for
validation by the orchestrator.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import websockets

logger = logging.getLogger(__name__)


@dataclass
class WSClientStats:
    messages_received: int = 0
    alerts: List[dict] = field(default_factory=list)
    errors: int = 0
    connected: bool = False


class AlertWSClient:
    """Async WebSocket client that consumes /ws/alerts."""

    def __init__(self, base_url: str = "ws://localhost:8000", token: Optional[str] = None):
        self.url = f"{base_url}/ws/alerts"
        if token:
            self.url += f"?token={token}"
        self.stats = WSClientStats()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        """Start consuming alerts in background."""
        self._stop.clear()
        self._task = asyncio.create_task(self._consume())

    async def stop(self) -> WSClientStats:
        """Stop the consumer and return collected stats."""
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        return self.stats

    async def _consume(self) -> None:
        try:
            async with websockets.connect(self.url) as ws:
                self.stats.connected = True
                logger.info("WebSocket client connected to %s", self.url)
                while not self._stop.is_set():
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        data = json.loads(msg)
                        self.stats.messages_received += 1
                        self.stats.alerts.append(data)
                        logger.debug("WS alert: %s", data.get("attack_type", "unknown"))
                    except asyncio.TimeoutError:
                        continue
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.stats.errors += 1
            logger.warning("WebSocket client error: %s", e)
