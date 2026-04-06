"""Isolation Forest unsupervised anomaly detection engine.

Operates on the 18-feature host-level vector from HostExtractor.
Adapted from cognitive-anomaly-detector.
"""

import logging
import os
import threading
import numpy as np
from typing import Optional

import joblib

from ..config import IF_MODEL_PATH, IF_SCALER_PATH, MLFLOW_REGISTRY_NAME
from .. import mlflow_registry

logger = logging.getLogger(__name__)


class IsolationForestEngine:
    """Unsupervised anomaly detector for host-level features."""

    def __init__(
        self,
        model_path: str = IF_MODEL_PATH,
        scaler_path: str = IF_SCALER_PATH,
    ):
        self._model = None
        self._scaler = None
        self._model_path = model_path
        self._scaler_path = scaler_path
        self._swap_lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        # Try MLflow first
        model = mlflow_registry.load_latest("isolation_forest")
        if model is not None:
            self._model = model
            logger.info("IsolationForestEngine loaded from MLflow")
        elif os.path.exists(self._model_path):
            try:
                self._model = joblib.load(self._model_path)
                logger.info("IsolationForestEngine loaded: %s", self._model_path)
            except Exception as e:
                logger.error("Failed to load IF model: %s", e)
        else:
            logger.warning("IF model not found at %s", self._model_path)

        try:
            if os.path.exists(self._scaler_path):
                self._scaler = joblib.load(self._scaler_path)
        except Exception as e:
            logger.warning("IF scaler not loaded: %s", e)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    def anomaly_score(self, host_features: np.ndarray) -> float:
        """Normalised anomaly score [0, 1]; higher = more anomalous."""
        if not self.is_available or host_features is None:
            return 0.0
        # Read model+scaler atomically so a concurrent swap() sees a consistent pair
        with self._swap_lock:
            model = self._model
            scaler = self._scaler
        try:
            vec = host_features.reshape(1, -1)
            if scaler is not None:
                vec = scaler.transform(vec)
            raw = float(model.decision_function(vec)[0])
            # decision_function: negative = anomaly, positive = normal.
            # Map to [0,1] via sigmoid so extreme values retain granularity.
            score = 1.0 / (1.0 + np.exp(5.0 * raw))  # steepness=5 centres transition at 0
            return float(np.clip(score, 0.0, 1.0))
        except Exception as e:
            logger.error("IsolationForestEngine score error: %s", e)
            return 0.0

    # ── Hot-swap ──────────────────────────────────────────────────────────────

    def swap(self, model, scaler=None) -> None:
        """Replace model+scaler atomically. Thread-safe."""
        with self._swap_lock:
            self._model = model
            self._scaler = scaler
        logger.info("IsolationForestEngine: model swapped in-process")

    def reload(self, model_path: str, scaler_path: str = "") -> bool:
        """Load model (and optionally scaler) from disk and hot-swap."""
        try:
            new_model = joblib.load(model_path)
            new_scaler = None
            if scaler_path and os.path.exists(scaler_path):
                new_scaler = joblib.load(scaler_path)
            self.swap(new_model, new_scaler)
            logger.info("IsolationForestEngine reloaded from %s", model_path)
            return True
        except Exception as e:
            logger.error("IsolationForestEngine.reload failed: %s", e)
            return False

    def reload_from_mlflow(self, version: int) -> bool:
        """Load a specific MLflow model version and hot-swap."""
        mlflow = mlflow_registry._get_mlflow()
        if mlflow is None or not mlflow_registry.is_enabled():
            logger.error("MLflow not available for hot-swap")
            return False
        try:
            model_uri = f"models:/{MLFLOW_REGISTRY_NAME}-isolation_forest/{version}"
            new_model = mlflow.sklearn.load_model(model_uri)
            self.swap(new_model, None)
            logger.info("IsolationForestEngine reloaded from MLflow version %d", version)
            return True
        except Exception as e:
            logger.error("IsolationForestEngine.reload_from_mlflow failed: %s", e)
            return False
