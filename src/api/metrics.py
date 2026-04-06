"""Prometheus metrics and OpenTelemetry tracing (Phase 7).

Metrics are exposed at /metrics when PROMETHEUS_ENABLED=true.
OTEL tracing is initialized when OTEL_EXPORTER_OTLP_ENDPOINT is set.
"""

import logging
import time
from typing import Optional

from fastapi import FastAPI, Request, Response

from ..config import PROMETHEUS_ENABLED, OTEL_EXPORTER_ENDPOINT

logger = logging.getLogger(__name__)

# ── Prometheus ─────────────────────────────────────────────────────────────────
_prom = None


def _get_prometheus():
    global _prom
    if _prom is None:
        try:
            import prometheus_client
            _prom = prometheus_client
        except ImportError:
            _prom = False
    return _prom if _prom else None


# Metric objects (created lazily)
_request_count = None
_request_latency = None
_alert_count = None
_alert_suppressed_count = None
_ensemble_score_histogram = None


def _init_metrics():
    global _request_count, _request_latency, _alert_count, _alert_suppressed_count, _ensemble_score_histogram
    prom = _get_prometheus()
    if prom is None:
        return
    _request_count = prom.Counter(
        "cnds_http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
    )
    _request_latency = prom.Histogram(
        "cnds_http_request_duration_seconds", "Request latency", ["method", "endpoint"]
    )
    _alert_count = prom.Counter(
        "cnds_alerts_total", "Total alerts fired", ["severity", "engine"]
    )
    _alert_suppressed_count = prom.Counter(
        "cnds_alerts_suppressed_total", "Total alerts suppressed by dedup or suppression rules",
        ["reason"],
    )
    _ensemble_score_histogram = prom.Histogram(
        "cnds_ensemble_score",
        "Distribution of ensemble confidence scores",
        ["is_anomaly"],
        buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0],
    )


def inc_alert(severity: str, engine: str = "ensemble"):
    """Increment the alert counter."""
    if _alert_count is not None:
        _alert_count.labels(severity=severity, engine=engine).inc()


def inc_suppressed(reason: str = "suppression_rule"):
    """Increment the suppressed-alert counter. reason: 'dedup' | 'suppression_rule'"""
    if _alert_suppressed_count is not None:
        _alert_suppressed_count.labels(reason=reason).inc()


def observe_ensemble_score(score: float, is_anomaly: bool):
    """Record an ensemble score observation."""
    if _ensemble_score_histogram is not None:
        _ensemble_score_histogram.labels(is_anomaly=str(is_anomaly)).observe(score)


def setup_prometheus(app: FastAPI):
    """Add Prometheus middleware and /metrics endpoint."""
    if not PROMETHEUS_ENABLED:
        return
    prom = _get_prometheus()
    if prom is None:
        logger.warning("PROMETHEUS_ENABLED=true but prometheus_client not installed")
        return

    _init_metrics()

    @app.middleware("http")
    async def prometheus_middleware(request: Request, call_next):
        start = time.time()
        response: Response = await call_next(request)
        duration = time.time() - start
        endpoint = request.url.path
        if _request_count:
            _request_count.labels(
                method=request.method, endpoint=endpoint, status=response.status_code
            ).inc()
        if _request_latency:
            _request_latency.labels(method=request.method, endpoint=endpoint).observe(duration)
        return response

    @app.get("/metrics")
    async def metrics():
        from starlette.responses import PlainTextResponse
        return PlainTextResponse(
            prom.generate_latest().decode(), media_type=prom.CONTENT_TYPE_LATEST
        )

    logger.info("Prometheus metrics enabled at /metrics")


# ── OpenTelemetry ──────────────────────────────────────────────────────────────

def setup_otel(app: FastAPI):
    """Initialize OpenTelemetry tracing if configured."""
    if not OTEL_EXPORTER_ENDPOINT:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        provider = TracerProvider()
        exporter = OTLPSpanExporter(endpoint=OTEL_EXPORTER_ENDPOINT)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        logger.info("OpenTelemetry tracing enabled → %s", OTEL_EXPORTER_ENDPOINT)
    except ImportError:
        logger.warning("OTEL endpoint set but opentelemetry packages not installed")
    except Exception as e:
        logger.error("Failed to initialize OpenTelemetry: %s", e)
