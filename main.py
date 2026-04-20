"""Entry point: start packet capture and run the full detection pipeline.

Usage:
    sudo venv/bin/python main.py [--iface eth0] [--api] [--duration 60]

    --iface IFACE   Network interface to capture on (default: auto)
    --api           Also start the FastAPI server (port 8000)
    --duration N    Stop after N seconds (default: run until Ctrl+C)
"""

import argparse
import logging
import signal
import sys
import time
import threading

import os

from src.config import CAPTURE_INTERFACE, DATABASE_URL, MALICIOUS_JA3_FILE, setup_logging
from src.capture.packet_capture import PacketCapture, PacketProcessor
from src.capture.dispatcher import Dispatcher
from src.engines.registry import supervised, iforest, lstm, baseline
from src import pipeline
from src.pipeline import on_flow_complete, drain_alert_queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("cnds")
setup_logging()


def main():
    parser = argparse.ArgumentParser(description="Cognitive Network Defense System — packet capture")
    parser.add_argument("--iface", default=CAPTURE_INTERFACE)
    parser.add_argument("--api", action="store_true", help="Also start FastAPI server")
    parser.add_argument("--duration", type=int, default=0, help="Run for N seconds (0 = forever)")
    args = parser.parse_args()

    logger.info(
        "Engines: supervised=%s  iforest=%s  lstm=%s  baseline=%s  rules=True",
        supervised.is_available, iforest.is_available, lstm.is_available, baseline.is_available,
    )

    # Initialise unsupervised baseline collector (enabled by default).
    baseline_enabled = os.environ.get("BASELINE_COLLECTION_ENABLED", "true").lower() != "false"
    pipeline.init_baseline_collector(enabled=baseline_enabled)

    # Load malicious JA3 hashes if configured
    if MALICIOUS_JA3_FILE:
        from src.features.ja3 import load_malicious_ja3
        load_malicious_ja3(MALICIOUS_JA3_FILE)

    # Optional API server
    api_app = None
    if args.api:
        if "sqlite" in DATABASE_URL:
            logger.warning(
                "SQLite does not support concurrent writers. "
                "Use PostgreSQL (DATABASE_URL=postgresql+asyncpg://...) for production --api mode."
            )
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
    if args.api and api_app is not None:
        def _update_stats():
            while not capture._stop.is_set():
                api_app.state.capture_stats = {**processor.stats, **dispatcher.stats}
                time.sleep(5)
        threading.Thread(target=_update_stats, daemon=True, name="stats-updater").start()

    def _shutdown(sig, frame):
        logger.info("Shutting down…")
        capture.stop()
        processor.stop()
        dispatcher.stop()
        drain_alert_queue(timeout=5.0)
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
