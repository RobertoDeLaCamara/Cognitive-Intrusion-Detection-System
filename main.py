"""Entry point: start packet capture and run the full detection pipeline.

Usage:
    sudo venv/bin/python main.py [--iface eth0] [--api] [--duration 60]

    --iface IFACE   Network interface to capture on (default: auto)
    --api           Also start the FastAPI server (port 8000)
    --duration N    Stop after N seconds (default: run until Ctrl+C)
"""

import argparse
import logging
import queue
import signal
import sys
import time
import threading
import numpy as np
from typing import List, Optional

from src.config import CAPTURE_INTERFACE, MIN_PACKETS_FOR_ML, DATABASE_URL, DEDUP_WINDOW_SECS
from src.capture.packet_capture import PacketCapture, PacketProcessor
from src.capture.dispatcher import Dispatcher
from src.engines.registry import supervised, iforest, lstm, rules, ensemble
from src.ensemble.scorer import EngineScores, severity_from_score
from src.features.flow_extractor import FlowRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("cnds")

# ── Alert persistence (async writer thread for the capture pipeline) ───────
_db_engine = None
_SessionLocal = None
_alert_queue: queue.Queue = queue.Queue(maxsize=1000)
_writer_thread: Optional[threading.Thread] = None
_writer_stop = threading.Event()


def _init_db():
    """Lazy-init a sync-compatible DB session for the capture pipeline."""
    global _db_engine, _SessionLocal
    if _SessionLocal is not None:
        return
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from src.api.models import Base
    # Convert async URL to sync (aiosqlite → pysqlite)
    sync_url = DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")
    _db_engine = create_engine(sync_url, echo=False)
    Base.metadata.create_all(_db_engine)
    _SessionLocal = sessionmaker(bind=_db_engine)


def _writer_loop():
    """Dedicated thread that drains the alert queue and writes to DB."""
    while not _writer_stop.is_set():
        try:
            item = _alert_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            _init_db()
            from datetime import datetime, timezone
            from src.api.models import Alert
            record, scores, result, severity, triggered = item
            session = _SessionLocal()
            try:
                alert = Alert(
                    timestamp=datetime.now(timezone.utc),
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    attack_type=scores.attack_type,
                    severity=severity,
                    ensemble_score=result.score,
                    engine_scores={
                        "supervised": scores.supervised,
                        "isolation_forest": scores.isolation_forest,
                        "lstm": scores.lstm,
                        "rules": scores.rules,
                    },
                    triggered_rules=triggered,
                )
                session.add(alert)
                session.commit()
            finally:
                session.close()
        except Exception as e:
            logger.error("Failed to persist alert: %s", e)
        finally:
            _alert_queue.task_done()


def _start_writer():
    global _writer_thread
    if _writer_thread is not None:
        return
    _writer_stop.clear()
    _writer_thread = threading.Thread(target=_writer_loop, daemon=True, name="alert-writer")
    _writer_thread.start()


def _persist_alert(record, scores, result, severity, triggered):
    """Enqueue alert for async DB write. Non-blocking."""
    _start_writer()
    try:
        _alert_queue.put_nowait((record, scores, result, severity, triggered))
    except queue.Full:
        logger.warning("Alert queue full — dropping alert for %s", record.src_ip)


# ── Alert deduplication ────────────────────────────────────────────────────────
_dedup_cache: dict = {}  # (src_ip, attack_type) -> last_fired_timestamp
_dedup_lock = threading.Lock()


def on_flow_complete(
    record: FlowRecord,
    flow_vec: np.ndarray,
    host_vec: Optional[np.ndarray],
    payload_matches: List[str],
    payload_features: Optional[np.ndarray] = None,
) -> None:
    """Called by the Dispatcher when a flow expires."""
    scores = EngineScores()

    if supervised.is_available:
        result = supervised.predict(flow_vec, payload_features)
        if result:
            label, conf = result
            scores.supervised = 0.0 if label == "BENIGN" else conf
            scores.attack_type = label
            scores.supervised_confidence = conf

    if host_vec is not None:
        if iforest.is_available:
            scores.isolation_forest = iforest.anomaly_score(host_vec)
        if lstm.is_available:
            lstm.update(record.src_ip, host_vec)
            scores.lstm = lstm.anomaly_score(record.src_ip)

    rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches)
    scores.rules = rule_score
    scores.triggered_rules = triggered

    result = ensemble.score(scores)

    if result.is_anomaly:
        severity = severity_from_score(result.score, scores.attack_type)

        # Deduplication: skip if same (src_ip, attack_type) fired recently
        dedup_key = (record.src_ip, scores.attack_type or "unknown")
        now = time.time()
        with _dedup_lock:
            last_fired = _dedup_cache.get(dedup_key, 0.0)
            if now - last_fired < DEDUP_WINDOW_SECS:
                return
            _dedup_cache[dedup_key] = now
            # Prune stale entries periodically
            if len(_dedup_cache) > 10000:
                cutoff = now - DEDUP_WINDOW_SECS
                stale = [k for k, t in _dedup_cache.items() if t < cutoff]
                for k in stale:
                    del _dedup_cache[k]

        parts = [
            f"src={record.src_ip}",
            f"dst={record.dst_ip}",
            f"score={result.score:.3f}",
            f"engines={result.active_engines}",
        ]
        if scores.attack_type and scores.attack_type != "BENIGN":
            parts.append(f"type={scores.attack_type}")
        if triggered:
            parts.append(f"rules={triggered}")

        logger.warning("[ALERT] %s", " | ".join(parts))
        _persist_alert(record, scores, result, severity, triggered)


def main():
    parser = argparse.ArgumentParser(description="Cognitive Network Defense System — packet capture")
    parser.add_argument("--iface", default=CAPTURE_INTERFACE)
    parser.add_argument("--api", action="store_true", help="Also start FastAPI server")
    parser.add_argument("--duration", type=int, default=0, help="Run for N seconds (0 = forever)")
    args = parser.parse_args()

    logger.info("Engines: supervised=%s  iforest=%s  lstm=%s  rules=True",
                supervised.is_available, iforest.is_available, lstm.is_available)

    # Optional API server
    if args.api:
        import uvicorn
        from src.api.main import app as api_app
        api_thread = threading.Thread(
            target=lambda: uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, log_level="warning"),
            daemon=True,
            name="api-server",
        )
        api_thread.start()
        logger.info("API server starting on http://0.0.0.0:8000")

    dispatcher = Dispatcher(flow_callback=on_flow_complete, flush_interval=10.0)
    processor  = PacketProcessor(callback=dispatcher.dispatch)
    capture    = PacketCapture(processor=processor, iface=args.iface)

    # Expose capture stats to API /health endpoint
    if args.api:
        _api_app = api_app  # captured from import above
        def _update_stats():
            while not capture._stop.is_set():
                _api_app.state.capture_stats = {**processor.stats, **dispatcher.stats}
                time.sleep(5)
        threading.Thread(target=_update_stats, daemon=True, name="stats-updater").start()

    def _shutdown(sig, frame):
        logger.info("Shutting down…")
        capture.stop()
        processor.stop()
        dispatcher.stop()
        stats = processor.stats
        logger.info("Final stats: %s | dispatcher: %s", stats, dispatcher.stats)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    dispatcher.start()
    processor.start()
    capture.start()

    logger.info("Capture started. Press Ctrl+C to stop.")

    if args.duration > 0:
        time.sleep(args.duration)
        _shutdown(None, None)
    else:
        signal.pause()


if __name__ == "__main__":
    main()
