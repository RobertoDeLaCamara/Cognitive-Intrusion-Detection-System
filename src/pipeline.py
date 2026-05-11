"""Detection pipeline callback — processes completed flows through all engines.

Extracted from main.py to separate the detection logic from the CLI entry point.
Handles: trusted-outbound filtering, engine scoring, dedup, alert persistence.
"""

import logging
import queue
import socket
import threading
import time
import concurrent.futures
import numpy as np
from typing import List, Optional

from .config import (
    DATABASE_URL, DEDUP_WINDOW_SECS, TRUSTED_OUTBOUND,
)
from .engines.registry import supervised, iforest, lstm, baseline as baseline_engine, rules, ensemble
from .ensemble.scorer import EngineScores, severity_from_score
from .features.flow_extractor import FlowRecord
from .unsupervised.collector import BaselineCollector
from .unsupervised.triggers import CompositeTrigger
from .unsupervised.window_trainer import WindowTrainer
from .enrichment.threat_intel import check_ip as ti_check_ip, check_ja3 as ti_check_ja3, get_store as ti_get_store

logger = logging.getLogger(__name__)

# ── Unsupervised baseline collector (lazily initialised) ───────────────────
_baseline_collector: Optional[BaselineCollector] = None
_window_trainer: Optional[WindowTrainer] = None
_baseline_collector_lock = threading.Lock()


def get_baseline_collector() -> Optional[BaselineCollector]:
    """Return the global BaselineCollector, or None if not yet initialised."""
    return _baseline_collector


def get_window_trainer() -> Optional[WindowTrainer]:
    """Return the global WindowTrainer, or None if not yet initialised."""
    return _window_trainer


def init_baseline_collector(enabled: bool = True) -> None:
    """Initialise the global unsupervised baseline collector.

    Safe to call multiple times; subsequent calls are no-ops.
    Also starts the background Prometheus scrape / progress-log thread.
    """
    global _baseline_collector, _window_trainer
    with _baseline_collector_lock:
        if _baseline_collector is not None:
            return
        trainer = WindowTrainer(on_trained=baseline_engine.reload_from_mlflow_baseline)
        trigger = CompositeTrigger()
        _baseline_collector = BaselineCollector(
            trigger=trigger,
            on_window_ready=trainer.train_window,
            enabled=enabled,
        )
        _window_trainer = trainer

    logger.info("Unsupervised baseline collector initialised (enabled=%s)", enabled)

# ── Alert persistence (async writer thread) ────────────────────────────────
_db_engine = None
_SessionLocal = None
_alert_queue: queue.Queue = queue.Queue(maxsize=1000)
_writer_thread: Optional[threading.Thread] = None
_writer_stop = threading.Event()


def _init_db():
    global _db_engine, _SessionLocal
    if _SessionLocal is not None:
        return
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from .api.models import Base
    sync_url = DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")
    _db_engine = create_engine(sync_url, echo=False)
    Base.metadata.create_all(_db_engine)
    _SessionLocal = sessionmaker(bind=_db_engine)


def _writer_loop():
    while not _writer_stop.is_set():
        try:
            item = _alert_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            _init_db()
            from datetime import datetime, timezone
            from .api.models import Alert
            record, scores, result, severity, triggered, ja3_info = item
            session = _SessionLocal()
            try:
                from .enrichment.geoip import lookup as geoip_lookup
                from .enrichment.mitre import enrich as mitre_enrich
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
                        **({"baseline": scores.baseline} if scores.baseline is not None else {}),
                    },
                    triggered_rules=triggered,
                    src_geo=geoip_lookup(record.src_ip),
                    mitre_techniques=mitre_enrich(scores.attack_type, triggered),
                    ja3_hash=ja3_info["hash"] if ja3_info else None,
                    ja3_string=ja3_info["string"] if ja3_info else None,
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


def _persist_alert(record, scores, result, severity, triggered, ja3_info=None):
    _start_writer()
    try:
        _alert_queue.put_nowait((record, scores, result, severity, triggered, ja3_info))
    except queue.Full:
        logger.warning("Alert queue full — dropping alert for %s", record.src_ip)


def drain_alert_queue(timeout: float = 5.0) -> None:
    """Signal the writer to stop and wait for pending alerts to flush."""
    _writer_stop.set()
    if _writer_thread is not None and _writer_thread.is_alive():
        _writer_thread.join(timeout=timeout)
        if _writer_thread.is_alive():
            logger.warning("Alert writer did not finish within %.1fs — some alerts may be lost", timeout)


# ── Trusted outbound DNS cache ─────────────────────────────────────────────
_dns_cache: dict = {}
_DNS_CACHE_TTL = 3600
_dns_lock = threading.Lock()
_dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns-resolve")


def _resolve_hostname(ip: str) -> str:
    now = time.time()
    with _dns_lock:
        entry = _dns_cache.get(ip)
        if entry and now < entry[1]:
            return entry[0]
    try:
        fut = _dns_executor.submit(socket.gethostbyaddr, ip)
        hostname = fut.result(timeout=2.0)[0]
    except Exception:
        hostname = ""
    with _dns_lock:
        _dns_cache[ip] = (hostname, now + _DNS_CACHE_TTL)
    return hostname


def _is_trusted_outbound(src_ip: str, dst_ip: str) -> bool:
    if not TRUSTED_OUTBOUND:
        return False
    trusted_domains = TRUSTED_OUTBOUND.get(src_ip)
    if not trusted_domains:
        return False
    hostname = _resolve_hostname(dst_ip)
    return bool(hostname) and any(hostname.endswith(d) for d in trusted_domains)


# ── Alert deduplication ────────────────────────────────────────────────────
_dedup_cache: dict = {}
_dedup_lock = threading.Lock()
_dedup_last_cleanup: float = 0.0


def on_flow_complete(
    record: FlowRecord,
    flow_vec: np.ndarray,
    host_vec: Optional[np.ndarray],
    payload_matches: List[str],
    payload_features: Optional[np.ndarray] = None,
    ja3_info: Optional[dict] = None,
) -> None:
    """Called by the Dispatcher when a flow expires."""
    if _is_trusted_outbound(record.src_ip, record.dst_ip):
        return

    # ── Threat intelligence check ───────────────────────────────────────────────
    ti_malicious, ti_source = ti_check_ip(record.src_ip)
    if not ti_malicious:
        ti_malicious, ti_source = ti_check_ip(record.dst_ip)
    ti_ja3_malicious = False
    if ja3_info and ja3_info.get("hash"):
        ti_ja3_malicious, _ = ti_check_ja3(ja3_info["hash"])
    # Ensure threat intel refresh happens in background
    ti_get_store()

    scores = EngineScores()

    if supervised.is_available:
        result = supervised.predict(flow_vec, payload_features)
        if result:
            label, conf = result
            scores.supervised = 0.0 if label.upper() == "BENIGN" else conf
            scores.attack_type = label
            scores.supervised_confidence = conf

    if host_vec is not None:
        if iforest.is_available:
            scores.isolation_forest = iforest.anomaly_score(host_vec)
        if lstm.is_available:
            lstm.update(record.src_ip, host_vec)
            scores.lstm = lstm.anomaly_score(record.src_ip)
        # Baseline engine: update ring buffer and score before feeding the collector,
        # so the same host_vec contributes to both inference and the training window.
        if baseline_engine.is_available:
            baseline_engine.update(record.src_ip, host_vec)
            scores.baseline = baseline_engine.anomaly_score(record.src_ip, host_vec)
        if _baseline_collector is not None:
            _baseline_collector.observe(record, host_vec)

    rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches, ja3_info)
    scores.rules = rule_score
    scores.triggered_rules = triggered
    scores.ti_malicious_ip = ti_malicious
    scores.ti_malicious_ja3 = ti_ja3_malicious

    result = ensemble.score(scores)

    if result.is_anomaly:
        severity = severity_from_score(result.score, scores.attack_type)

        dedup_key = (record.src_ip, scores.attack_type or "unknown")
        now = time.time()
        with _dedup_lock:
            last_fired = _dedup_cache.get(dedup_key, 0.0)
            if now - last_fired < DEDUP_WINDOW_SECS:
                return
            _dedup_cache[dedup_key] = now
            global _dedup_last_cleanup
            if now - _dedup_last_cleanup > 300:
                cutoff = now - DEDUP_WINDOW_SECS
                stale = [k for k, t in _dedup_cache.items() if t < cutoff]
                for k in stale:
                    del _dedup_cache[k]
                _dedup_last_cleanup = now

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
        if ja3_info:
            parts.append(f"ja3={ja3_info['hash']}")

        logger.warning("[ALERT] %s", " | ".join(parts), extra={
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "ensemble_score": result.score,
            "attack_type": scores.attack_type,
            "triggered_rules": triggered,
            "active_engines": result.active_engines,
            "ja3_hash": ja3_info["hash"] if ja3_info else None,
        })
        _persist_alert(record, scores, result, severity, triggered, ja3_info)
