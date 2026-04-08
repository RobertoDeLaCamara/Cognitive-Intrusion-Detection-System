"""Prometheus metrics and OpenTelemetry tracing (Phase 7).

Metrics are exposed at /metrics when PROMETHEUS_ENABLED=true.
OTEL tracing is initialized when OTEL_EXPORTER_OTLP_ENDPOINT is set.
"""

import logging
import threading
import time
from typing import Callable, Optional

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

# ── Unsupervised baseline metrics ─────────────────────────────────────────────
_baseline_buffer_vectors = None
_baseline_distinct_src_ips = None
_baseline_window_elapsed_seconds = None
_baseline_dst_port_entropy_bits = None
_baseline_trigger_progress = None   # GaugeVec, label: condition
_baseline_training_in_flight = None
_baseline_dropped_while_training = None
_baseline_windows_trained_total = None
_baseline_engine_available = None
_baseline_engine_version = None
_baseline_last_reload_ts = None
_baseline_drift_score = None


def _init_metrics():
    global _request_count, _request_latency, _alert_count
    global _alert_suppressed_count, _ensemble_score_histogram
    global _baseline_buffer_vectors, _baseline_distinct_src_ips
    global _baseline_window_elapsed_seconds, _baseline_dst_port_entropy_bits
    global _baseline_trigger_progress, _baseline_training_in_flight
    global _baseline_dropped_while_training, _baseline_windows_trained_total
    global _baseline_engine_available, _baseline_engine_version
    global _baseline_last_reload_ts, _baseline_drift_score
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
    # Baseline subsystem
    _baseline_buffer_vectors = prom.Gauge(
        "cnds_baseline_buffer_vectors", "Vectors accumulated in the current baseline window"
    )
    _baseline_distinct_src_ips = prom.Gauge(
        "cnds_baseline_distinct_src_ips", "Distinct source IPs seen in the current window"
    )
    _baseline_window_elapsed_seconds = prom.Gauge(
        "cnds_baseline_window_elapsed_seconds", "Seconds elapsed since the current window started"
    )
    _baseline_dst_port_entropy_bits = prom.Gauge(
        "cnds_baseline_dst_port_entropy_bits", "Shannon entropy of destination ports in current window"
    )
    _baseline_trigger_progress = prom.Gauge(
        "cnds_baseline_trigger_progress_ratio",
        "Progress toward each trigger condition (0–1)",
        ["condition"],
    )
    _baseline_training_in_flight = prom.Gauge(
        "cnds_baseline_training_in_flight", "1 while a training run is in progress, else 0"
    )
    _baseline_dropped_while_training = prom.Gauge(
        "cnds_baseline_dropped_while_training",
        "Samples dropped in the current training run (resets to 0 when training completes)"
    )
    _baseline_windows_trained_total = prom.Gauge(
        "cnds_baseline_windows_trained_total", "Total baseline windows trained since process start"
    )
    _baseline_engine_available = prom.Gauge(
        "cnds_baseline_engine_available", "1 when the BaselineEngine has a loaded model, else 0"
    )
    _baseline_engine_version = prom.Gauge(
        "cnds_baseline_engine_version", "MLflow model version currently loaded (0 if none)"
    )
    _baseline_last_reload_ts = prom.Gauge(
        "cnds_baseline_last_reload_timestamp_seconds",
        "Unix timestamp of the last successful BaselineEngine reload"
    )
    _baseline_drift_score = prom.Gauge(
        "cnds_baseline_drift_score",
        "Distributional drift score between current window and last trained baseline (0–1)"
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


def update_baseline_metrics(snapshot, engine_info: dict, drift_score: Optional[float] = None,
                            windows_trained: int = 0) -> None:
    """Push a CollectorSnapshot + engine_info dict into Prometheus gauges.

    Called from the scrape thread every SCRAPE_INTERVAL seconds.
    All guards are no-ops when Prometheus is disabled.
    """
    if _baseline_buffer_vectors is None:
        return
    _baseline_buffer_vectors.set(snapshot.n_total)
    _baseline_distinct_src_ips.set(snapshot.n_distinct_src_ips)
    _baseline_window_elapsed_seconds.set(snapshot.elapsed_sec)
    _baseline_dst_port_entropy_bits.set(snapshot.dst_port_entropy_bits)
    for condition, ratio in snapshot.progress_ratios.items():
        _baseline_trigger_progress.labels(condition=condition).set(ratio)
    _baseline_training_in_flight.set(1 if snapshot.training_in_flight else 0)
    _baseline_dropped_while_training.set(snapshot.dropped_while_training)
    _baseline_windows_trained_total.set(windows_trained)
    _baseline_engine_available.set(1 if engine_info.get("available") else 0)
    try:
        ver = int(engine_info.get("version") or 0)
    except (TypeError, ValueError):
        ver = 0
    _baseline_engine_version.set(ver)
    if engine_info.get("last_reload_iso"):
        import datetime
        try:
            ts = datetime.datetime.fromisoformat(engine_info["last_reload_iso"]).timestamp()
            _baseline_last_reload_ts.set(ts)
        except Exception:
            pass
    if drift_score is not None and _baseline_drift_score is not None:
        _baseline_drift_score.set(drift_score)


def start_baseline_scrape(
    collector_getter: Callable,
    engine_getter: Callable,
    history_getter: Callable,
    scrape_interval: int = 5,
    log_interval: int = 30,
) -> None:
    """Start a daemon thread that scrapes the baseline collector every scrape_interval seconds.

    Also emits a structured INFO log every log_interval seconds showing trigger progress.
    Safe to call when Prometheus is disabled — logging still works.

    Args:
        collector_getter: callable returning Optional[BaselineCollector]
        engine_getter:    callable returning BaselineEngine
        history_getter:   callable returning list of window history dicts
        scrape_interval:  seconds between Prometheus gauge updates (default 5)
        log_interval:     seconds between structured progress logs (default 30)
    """
    def _loop():
        last_log_ts = 0.0
        while True:
            time.sleep(scrape_interval)
            try:
                collector = collector_getter()
                if collector is None:
                    continue
                snapshot = collector.snapshot()
                engine = engine_getter()
                engine_info = engine.get_info() if engine is not None else {}
                history = history_getter() or []
                windows_trained = len(history)

                # Drift score against last trained window
                drift_score = None
                if history:
                    try:
                        from ..unsupervised.drift import compute_drift
                        last_prov = history[-1].get("provenance")
                        report = compute_drift(snapshot, last_prov)
                        drift_score = report.drift_score if report is not None else None
                    except Exception:
                        pass

                update_baseline_metrics(snapshot, engine_info, drift_score, windows_trained)

                # Structured progress log every log_interval seconds
                now = time.time()
                if now - last_log_ts >= log_interval:
                    last_log_ts = now
                    if snapshot.training_in_flight:
                        logger.info(
                            "baseline_progress training_in_flight=True dropped=%d",
                            snapshot.dropped_while_training,
                        )
                    else:
                        ratios = snapshot.progress_ratios
                        worst = min(ratios, key=lambda k: ratios[k])
                        thresholds = snapshot.trigger_thresholds
                        logger.info(
                            "baseline_progress n=%d/%d ips=%d/%d "
                            "elapsed=%.0f/%.0f entropy=%.2f/%.2f "
                            "bottleneck=%s drift=%s",
                            snapshot.n_total, thresholds["vectors"],
                            snapshot.n_distinct_src_ips, thresholds["ips"],
                            snapshot.elapsed_sec, thresholds["time"],
                            snapshot.dst_port_entropy_bits, thresholds["entropy"],
                            worst,
                            f"{drift_score:.3f}" if drift_score is not None else "n/a",
                        )
            except Exception as exc:
                logger.debug("baseline_scrape error: %s", exc)

    t = threading.Thread(target=_loop, name="baseline-scrape", daemon=True)
    t.start()
    logger.info("Baseline scrape thread started (interval=%ds log=%ds)", scrape_interval, log_interval)


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
