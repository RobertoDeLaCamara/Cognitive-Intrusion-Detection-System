"""Baseline inference engine — loads live-trained unsupervised models from MLflow.

Combines IsolationForest (point anomaly) and LSTM Autoencoder (temporal anomaly)
trained on the current environment's traffic baseline. Hot-reloads whenever
WindowTrainer fires the on_trained callback after a new window is registered.

Thread safety
-------------
- _swap_lock  : protects the artifact quartet (scaler, iforest, lstm, threshold).
                Held only for the atomic read/write of the four object references.
- _buf_lock   : protects per-IP ring buffers. Separate from _swap_lock so a
                reload never stalls the hot-path update() call.
- _reload_lock: serialises concurrent reload_from_mlflow_baseline() calls so a
                second window completing while a reload is in flight does not race.
"""

import datetime
import logging
import os
import tempfile
import threading
import time
from collections import defaultdict, deque
from typing import Optional

import joblib
import numpy as np

from .. import mlflow_registry
from ..config import MAX_TRACKED_IPS
from ..engines.lstm_model import LSTMAutoencoder
from ..unsupervised.artifact_schema import (
    ARTIFACT_ROOT,
    BASELINE_SEQ_LEN,
    IFOREST_FILE,
    LSTM_FILE,
    MODEL_NAME,
    SCALER_FILE,
    THRESHOLD_FILE,
)

logger = logging.getLogger(__name__)


class BaselineEngine:
    """Inference engine backed by live-trained per-environment baseline models.

    is_available is False until the first baseline window is trained and loaded.
    The ensemble redistributes weight away from this engine until it becomes
    available — returning None (not 0.0) is the correct "no opinion" signal.
    """

    def __init__(self, model_name: str = MODEL_NAME):
        self._model_name = model_name

        self._scaler = None
        self._iforest = None
        self._lstm: Optional[LSTMAutoencoder] = None
        self._threshold: float = 0.0
        self._n_features: int = 0
        self._seq_len: int = BASELINE_SEQ_LEN

        self._version: str = ""
        self._last_reload_ts: float = 0.0

        self._swap_lock = threading.Lock()
        self._buf_lock = threading.Lock()
        self._reload_lock = threading.Lock()

        # Capture seq_len by value so the lambda does not hold a reference to self
        # and buffer maxlen is immutable regardless of any future _seq_len mutation.
        _seq_len = self._seq_len
        self._buffers: dict = defaultdict(lambda: deque(maxlen=_seq_len))
        self._max_buffers: int = MAX_TRACKED_IPS

        # Attempt to load a pre-existing baseline from a previous run.
        self._load()

    # ── Artifact loading ──────────────────────────────────────────────────────

    def _load(self) -> bool:
        """Download and atomically swap in all four artifacts from MLflow.

        Returns True on success, False on any failure (engine stays as-is).
        """
        if not mlflow_registry.is_enabled():
            logger.debug("BaselineEngine: MLflow not enabled — skipping load")
            return False

        mlflow = mlflow_registry._get_mlflow()
        if mlflow is None:
            return False

        try:
            client = mlflow.tracking.MlflowClient()
            versions = client.search_model_versions(f"name='{self._model_name}'")
            if not versions:
                logger.info(
                    "BaselineEngine: no registered versions of '%s' yet — "
                    "will activate after first training window",
                    self._model_name,
                )
                return False
            # Take the highest version number regardless of stage.
            latest = max(versions, key=lambda v: int(v.version))
            run_id = latest.run_id
        except Exception as e:
            logger.info("BaselineEngine: MLflow registry query failed: %s", e)
            return False

        try:
            import torch

            with tempfile.TemporaryDirectory() as tmp:
                client.download_artifacts(run_id, ARTIFACT_ROOT, tmp)
                artifact_dir = os.path.join(tmp, ARTIFACT_ROOT)

                scaler = joblib.load(os.path.join(artifact_dir, SCALER_FILE))
                iforest = joblib.load(os.path.join(artifact_dir, IFOREST_FILE))

                with open(os.path.join(artifact_dir, THRESHOLD_FILE)) as f:
                    threshold = float(f.read().strip())

                if not hasattr(scaler, "n_features_in_"):
                    raise ValueError(
                        "Loaded scaler has no n_features_in_ — "
                        "artifact may have been saved with scikit-learn < 1.0"
                    )
                n_features = int(scaler.n_features_in_)
                lstm_model = LSTMAutoencoder(n_features=n_features)
                # weights_only=True is mandatory — WindowTrainer saves state_dict only.
                # See artifact_schema.py for the matching save-side contract.
                state = torch.load(
                    os.path.join(artifact_dir, LSTM_FILE),
                    map_location="cpu",
                    weights_only=True,
                )
                lstm_model.load_state_dict(state)
                lstm_model.eval()

            with self._swap_lock:
                self._scaler = scaler
                self._iforest = iforest
                self._lstm = lstm_model
                self._threshold = threshold
                self._n_features = n_features
                self._version = str(latest.version)
                self._last_reload_ts = time.time()

            logger.info(
                "BaselineEngine loaded: n_features=%d threshold=%.6f version=%s",
                n_features,
                threshold,
                latest.version,
            )
            return True

        except Exception as e:
            logger.error("BaselineEngine._load failed: %s", e)
            return False

    # ── Protocol interface ────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        with self._swap_lock:
            return (
                self._scaler is not None
                and self._iforest is not None
                and self._lstm is not None
            )

    def update(self, ip: str, host_features: np.ndarray) -> None:
        """Append a host feature vector to this IP's ring buffer (hot path)."""
        with self._buf_lock:
            if ip not in self._buffers and len(self._buffers) >= self._max_buffers:
                # Evict the IP with the shortest buffer (least temporal data).
                victim = min(self._buffers, key=lambda k: len(self._buffers[k]))
                del self._buffers[victim]
            self._buffers[ip].append(host_features.astype(np.float32))

    def anomaly_score(self, ip: str, host_features: np.ndarray) -> Optional[float]:
        """Combined baseline anomaly score in [0, 1], or None if unavailable.

        None signals "no opinion" to the ensemble, which redistributes weight
        to the active engines rather than zeroing out the combined score.

        Score combination: max(s_iforest, s_lstm) — anomalous by either lens.
        """
        if not self.is_available or host_features is None:
            return None

        with self._swap_lock:
            scaler = self._scaler
            iforest = self._iforest
            lstm = self._lstm
            threshold = self._threshold
            seq_len = self._seq_len

        try:
            import torch

            vec = host_features.reshape(1, -1).astype(np.float32)
            vec_s = scaler.transform(vec)

            # ── IsolationForest branch (point anomaly) ─────────────────────
            # decision_function: negative = anomaly, positive = normal.
            # Sigmoid centred at 0 with steepness 5 maps to [0, 1].
            raw_if = float(iforest.decision_function(vec_s)[0])
            s_if = float(1.0 / (1.0 + np.exp(5.0 * raw_if)))

            # ── LSTM branch (temporal anomaly) ─────────────────────────────
            s_lstm = 0.0
            with self._buf_lock:
                buf = self._buffers.get(ip)
                seq = np.array(list(buf), dtype=np.float32) if (
                    buf is not None and len(buf) >= seq_len
                ) else None

            if seq is not None:
                seq_s = scaler.transform(seq).astype(np.float32)
                x = torch.from_numpy(seq_s).unsqueeze(0)  # (1, seq_len, n_features)
                with torch.no_grad():
                    recon = lstm(x)
                err = float(torch.mean((x - recon) ** 2).item())
                s_lstm = min(err / max(threshold, 1e-9), 1.0)

            return float(np.clip(max(s_if, s_lstm), 0.0, 1.0))

        except Exception as e:
            logger.error("BaselineEngine.anomaly_score error for %s: %s", ip, e)
            return None

    # ── Hot-reload ────────────────────────────────────────────────────────────

    def reload_from_mlflow_baseline(self) -> bool:
        """Hot-reload artifacts from MLflow. Called from the background training thread.

        Protected by _reload_lock so concurrent window completions serialise safely.
        The existing model continues serving until the atomic swap succeeds.
        """
        with self._reload_lock:
            success = self._load()
            if not success:
                logger.warning(
                    "BaselineEngine: hot-reload failed — previous model remains active"
                )
            return success

    def get_info(self) -> dict:
        """Return a snapshot of engine state for observability endpoints."""
        with self._swap_lock:
            available = (
                self._scaler is not None
                and self._iforest is not None
                and self._lstm is not None
            )
            return {
                "available": available,
                "n_features": self._n_features,
                "threshold": self._threshold,
                "version": self._version or None,
                "last_reload_iso": (
                    datetime.datetime.fromtimestamp(
                        self._last_reload_ts, tz=datetime.timezone.utc
                    ).isoformat()
                    if self._last_reload_ts > 0
                    else None
                ),
            }
