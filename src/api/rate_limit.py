"""Simple in-memory rate limiter middleware (Phase 8)."""

import asyncio
import time
import logging
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

logger = logging.getLogger(__name__)

# Module-level state so cleanup task can access it
_hits: dict = defaultdict(list)
_lock = asyncio.Lock()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter."""

    def __init__(self, app, requests: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW):
        super().__init__(app)
        self._requests = requests
        self._window = window

    async def dispatch(self, request: Request, call_next):
        if request.url.path in ("/health", "/docs", "/openapi.json", "/metrics"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - self._window

        async with _lock:
            _hits[client_ip] = [t for t in _hits[client_ip] if t > cutoff]

            if len(_hits[client_ip]) >= self._requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(self._window)},
                )

            _hits[client_ip].append(now)

        return await call_next(request)


async def prune_inactive():
    """Remove IPs with no recent hits. Called by periodic cleanup."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    async with _lock:
        stale = [ip for ip, ts in _hits.items() if not ts or ts[-1] < cutoff]
        for ip in stale:
            del _hits[ip]
        return len(stale)
