"""Baseline observability endpoints.

GET /api/baseline/status  — live snapshot of collector state, trigger progress,
                            engine info, and optional drift score.
GET /api/baseline/windows — rolling history of trained windows (last 20).
"""

import logging
from typing import Optional

from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/baseline", tags=["baseline"])


def _get_collector():
    from ...pipeline import get_baseline_collector
    return get_baseline_collector()


def _get_engine():
    from ...engines.registry import baseline as baseline_engine
    return baseline_engine


def _get_trainer():
    from ...pipeline import get_window_trainer
    return get_window_trainer()


@router.get("/status")
def baseline_status():
    """Live snapshot of the unsupervised baseline subsystem.

    Returns:
    - **collector**: buffer progress toward the training trigger
    - **trigger**: thresholds, per-condition ratios, and estimated time to fire
    - **engine**: loaded model info (available, version, threshold, last reload)
    - **drift**: distributional drift score vs last trained baseline (null if unavailable)
    """
    collector = _get_collector()
    engine = _get_engine()
    trainer = _get_trainer()

    # Collector snapshot
    if collector is not None:
        snap = collector.snapshot()
        ratios = snap.progress_ratios
        min_ratio = min(ratios.values()) if ratios else 0.0
        eta_sec = None
        if min_ratio > 0 and not snap.training_in_flight:
            eta_sec = round(snap.elapsed_sec * (1.0 / min_ratio - 1.0))
            eta_sec = max(0, eta_sec)

        collector_out = {
            "n_total": snap.n_total,
            "distinct_src_ips": snap.n_distinct_src_ips,
            "elapsed_sec": round(snap.elapsed_sec, 1),
            "dst_port_entropy_bits": round(snap.dst_port_entropy_bits, 4),
            "training_in_flight": snap.training_in_flight,
            "dropped_while_training": snap.dropped_while_training,
        }
        trigger_out = {
            "thresholds": snap.trigger_thresholds,
            "progress_ratios": {k: round(v, 4) for k, v in snap.progress_ratios.items()},
            "bottleneck": min(ratios, key=lambda k: ratios[k]) if ratios else None,
            "eta_estimate_sec": eta_sec,
        }
    else:
        snap = None
        collector_out = None
        trigger_out = None

    # Engine info
    engine_out = engine.get_info() if engine is not None else {"available": False}

    # Drift score
    drift_out = None
    if snap is not None and trainer is not None:
        history = trainer.get_history()
        if history:
            try:
                from ...unsupervised.drift import compute_drift
                report = compute_drift(snap, history[-1].get("provenance"))
                if report is not None:
                    drift_out = {
                        "drift_score": round(report.drift_score, 4),
                        "verdict": report.verdict,
                        "dst_port_entropy_delta_bits": round(report.dst_port_entropy_delta_bits, 4),
                        "distinct_src_ips_ratio": round(report.distinct_src_ips_ratio, 4),
                        "top_ports_jaccard": round(report.top_ports_jaccard, 4),
                    }
            except Exception as exc:
                logger.debug("Drift computation failed: %s", exc)

    return {
        "collector": collector_out,
        "trigger": trigger_out,
        "engine": engine_out,
        "drift": drift_out,
    }


@router.get("/windows")
def baseline_windows(limit: int = Query(default=20, ge=1, le=20)):
    """Rolling history of the last N trained baseline windows.

    Each entry includes provenance metadata (traffic characteristics of the
    training window) and training statistics (reconstruction threshold,
    val loss, etc.).
    """
    trainer = _get_trainer()
    if trainer is None:
        return {"windows": [], "total": 0}
    history = trainer.get_history()
    # Most recent first
    history = list(reversed(history))[:limit]
    return {"windows": history, "total": len(history)}
