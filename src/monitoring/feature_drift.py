"""Input-feature drift monitor for the supervised model (cnds#6).

The supervised model was fitted on a fixed dataset; its StandardScaler keeps the
per-feature training mean and standard deviation. This monitor accumulates the live
76 flow features in tumbling windows of DRIFT_WINDOW_FLOWS flows and compares each
feature's live mean with the training mean, in training standard deviations:

    shift_i = |live_mean_i - train_mean_i| / train_std_i

A feature counts as drifted when shift_i >= DRIFT_FEATURE_Z. The window verdict
comes from the fraction of drifted features (DRIFT_WARN_FRACTION / DRIFT_CRIT_FRACTION).

observe() is O(76) under a short lock, so it is safe on the capture workers. The
notification callback runs when a window closes with a worse verdict than before.
"""

import logging
import threading
from typing import Callable, Dict, List, Optional, Sequence

import numpy as np

logger = logging.getLogger(__name__)

_LEVEL = {"nominal": 0, "warning": 1, "critical": 2}


class FeatureDriftMonitor:
    def __init__(
        self,
        feature_names: Sequence[str],
        window_flows: int = 5000,
        feature_z: float = 1.0,
        warn_fraction: float = 0.10,
        crit_fraction: float = 0.25,
        min_flows: int = 200,
        baseline_loader: Optional[Callable[[], Optional[tuple]]] = None,
        on_verdict_worse: Optional[Callable[[dict], None]] = None,
    ):
        self._names = list(feature_names)
        self._n_features = len(self._names)
        self._window_flows = window_flows
        self._feature_z = feature_z
        self._warn_fraction = warn_fraction
        self._crit_fraction = crit_fraction
        self._min_flows = min_flows
        self._baseline_loader = baseline_loader
        self._on_verdict_worse = on_verdict_worse

        self._lock = threading.Lock()
        self._mean: Optional[np.ndarray] = None   # training mean
        self._std: Optional[np.ndarray] = None    # training std
        self._reset_window()
        self._last_closed: Optional[dict] = None
        self._last_level = 0

    # ── Baseline ──────────────────────────────────────────────────────────────
    def set_baseline(self, mean, std) -> None:
        mean = np.asarray(mean, dtype=np.float64)
        std = np.asarray(std, dtype=np.float64)
        if mean.shape != (self._n_features,) or std.shape != (self._n_features,):
            raise ValueError(f"baseline must have {self._n_features} features, got {mean.shape}/{std.shape}")
        with self._lock:
            self._mean = mean
            self._std = np.where(std > 0, std, 1.0)

    def _ensure_baseline(self) -> bool:
        if self._mean is not None:
            return True
        if self._baseline_loader is None:
            return False
        try:
            loaded = self._baseline_loader()
            if loaded is None:
                return False
            self.set_baseline(*loaded)
            return True
        except Exception as e:
            logger.debug("Drift baseline not available: %s", e)
            return False

    # ── Collection ────────────────────────────────────────────────────────────
    def _reset_window(self) -> None:
        self._n = 0
        self._sum = np.zeros(self._n_features)

    def observe(self, flow_vec) -> None:
        vec = np.nan_to_num(np.asarray(flow_vec, dtype=np.float64).ravel(), nan=0.0, posinf=0.0, neginf=0.0)
        if vec.shape[0] != self._n_features:
            return
        if not self._ensure_baseline():
            return
        closed = None
        with self._lock:
            self._sum += vec
            self._n += 1
            if self._n >= self._window_flows:
                closed = self._report_locked()
                self._last_closed = closed
                self._reset_window()
        if closed is not None:
            self._maybe_notify(closed)

    def _maybe_notify(self, report: dict) -> None:
        level = _LEVEL[report["verdict"]]
        worse = level > self._last_level
        self._last_level = level
        if worse and self._on_verdict_worse is not None:
            try:
                self._on_verdict_worse(report)
            except Exception as e:
                logger.error("Drift notification failed: %s", e)

    # ── Reporting ─────────────────────────────────────────────────────────────
    def _report_locked(self) -> dict:
        live_mean = self._sum / max(self._n, 1)
        shift = np.abs(live_mean - self._mean) / self._std
        drifted = shift >= self._feature_z
        fraction = float(drifted.mean())
        if fraction >= self._crit_fraction:
            verdict = "critical"
        elif fraction >= self._warn_fraction:
            verdict = "warning"
        else:
            verdict = "nominal"
        features: List[Dict] = [
            {
                "name": self._names[i],
                "train_mean": float(self._mean[i]),
                "live_mean": float(live_mean[i]),
                "shift_std": round(float(shift[i]), 4),
                "drifted": bool(drifted[i]),
            }
            for i in range(self._n_features)
        ]
        return {
            "flows_in_window": self._n,
            "drifted_features": int(drifted.sum()),
            "drifted_fraction": round(fraction, 4),
            "verdict": verdict,
            "features": features,
        }

    def status(self) -> dict:
        """Current drift state for GET /api/drift-status."""
        thresholds = {
            "window_flows": self._window_flows,
            "feature_z": self._feature_z,
            "warn_fraction": self._warn_fraction,
            "crit_fraction": self._crit_fraction,
            "min_flows": self._min_flows,
        }
        if not self._ensure_baseline():
            return {"status": "no_baseline", "thresholds": thresholds}
        with self._lock:
            if self._n >= self._min_flows:
                report, source = self._report_locked(), "current_window"
            elif self._last_closed is not None:
                report, source = self._last_closed, "last_closed_window"
            else:
                return {"status": "warming_up", "flows_in_window": self._n, "thresholds": thresholds}
        return {"status": "ok", "source": source, "thresholds": thresholds, **report}
