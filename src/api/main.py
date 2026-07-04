"""FastAPI application — unified network defense orchestration API."""

import hmac
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .database import init_db
from .routers import alerts, predict
from .routers.websocket import router as ws_router
from .routers.auth import router as auth_router
from .routers.baseline import router as baseline_router
from .metrics import setup_prometheus, setup_otel
from .rate_limit import RateLimitMiddleware
from ..config import API_KEY, CORS_ORIGINS, RATE_LIMIT_REQUESTS, GUARDIAN_ENABLED, TELEGRAM_BOT_TOKEN
from ..engines.registry import supervised, iforest, lstm

from ..config import setup_logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initialising database…")
    await init_db()

    # Start the baseline observability scrape thread if the collector is active.
    from ..pipeline import get_baseline_collector, get_window_trainer
    from ..engines.registry import baseline as _baseline_engine
    from .metrics import start_baseline_scrape
    if get_baseline_collector() is not None:
        start_baseline_scrape(
            collector_getter=get_baseline_collector,
            engine_getter=lambda: _baseline_engine,
            history_getter=lambda: (get_window_trainer().get_history() if get_window_trainer() else []),
            windows_total_getter=lambda: (get_window_trainer().get_windows_trained_total() if get_window_trainer() else 0),
        )

    logger.info("Cognitive Network Defense System API ready")

    # Start periodic cleanup task
    import asyncio
    cleanup_task = asyncio.create_task(_periodic_cleanup())

    # Guardian auto-response (Phase 10) — opt-in, off by default
    background_tasks = [cleanup_task]
    if GUARDIAN_ENABLED:
        from ..guardian.engine import guardian_loop, guardian_expiry_loop
        background_tasks.append(asyncio.create_task(guardian_loop()))
        background_tasks.append(asyncio.create_task(guardian_expiry_loop()))
        logger.info("Guardian auto-response enabled")
        if TELEGRAM_BOT_TOKEN:
            from ..guardian.telegram_listener import telegram_listener_loop
            background_tasks.append(asyncio.create_task(telegram_listener_loop()))

    yield

    for task in background_tasks:
        task.cancel()
    logger.info("Shutdown")


async def _periodic_cleanup(interval: int = 300):
    """Periodic background task: clean expired suppression rules and prune rate limiter."""
    import asyncio
    from .database import AsyncSessionLocal
    from ..enrichment.suppression import cleanup_expired
    while True:
        await asyncio.sleep(interval)
        try:
            async with AsyncSessionLocal() as session:
                deleted = await cleanup_expired(session)
                if deleted:
                    logger.info("Cleaned %d expired suppression rules", deleted)
        except Exception as e:
            logger.debug("Suppression cleanup error: %s", e)
        try:
            from .rate_limit import prune_inactive
            await prune_inactive()
        except Exception:
            pass


app = FastAPI(
    title="Cognitive Network Defense System API",
    description="Multi-engine network defense: supervised + unsupervised anomaly detection + rule-based heuristics",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["http://localhost:3000"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

# Optional API-key auth middleware (legacy — use JWT for new deployments)
if API_KEY:
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if request.url.path in ("/health", "/docs", "/openapi.json", "/metrics", "/ws/alerts"):
            return await call_next(request)
        if request.url.path.startswith("/api/auth"):
            return await call_next(request)
        key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(key, API_KEY):
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
        return await call_next(request)

# Observability (Phase 7)
setup_prometheus(app)
setup_otel(app)

# Rate limiting (Phase 8)
if RATE_LIMIT_REQUESTS > 0:
    app.add_middleware(RateLimitMiddleware)

app.include_router(alerts.router)
app.include_router(predict.router)
app.include_router(ws_router)
app.include_router(auth_router)
app.include_router(baseline_router)


@app.get("/health")
async def health():
    from ..capture.packet_capture import PacketProcessor
    capture_stats = getattr(app.state, "capture_stats", None)
    return {
        "status": "ok",
        "engines": {
            "supervised":       supervised.is_available,
            "isolation_forest": iforest.is_available,
            "lstm":             lstm.is_available,
            "rules":            True,
        },
        "capture_stats": capture_stats,
    }
