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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter."""

    def __init__(self, app, requests: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW):
        super().__init__(app)
        self._requests = requests
        self._window = window
        self._hits: dict = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health/docs/metrics
        if request.url.path in ("/health", "/docs", "/openapi.json", "/metrics"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        cutoff = now - self._window

        async with self._lock:
            # Prune old entries
            self._hits[client_ip] = [t for t in self._hits[client_ip] if t > cutoff]

            if len(self._hits[client_ip]) >= self._requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(self._window)},
                )

            self._hits[client_ip].append(now)

        return await call_next(request)
