"""Supervised classification engine — RF Pipeline trained on CIC-UNSW-NB15.

Supports two model formats:
  - sklearn Pipeline  (clip → log1p → StandardScaler → RandomForestClassifier)
    produced by scripts/train_rf.py — the default for production.
  - Plain RandomForestClassifier (legacy / demo model fallback).

Load priority:
  1. MLflow registry (if MLFLOW_TRACKING_URI is configured)
  2. Local file at RF_MODEL_PATH (models/rf_model.joblib)
"""

import logging
import os
import numpy as np
from typing import Optional, Tuple

import joblib

from ..config import RF_MODEL_PATH, RF_LITE_MODEL_PATH, RF_SCORE_THRESHOLD
from ..features.flow_extractor import FLOW_FEATURE_NAMES
from ..features.payload_analyzer import PAYLOAD_FEATURE_NAMES
from .. import mlflow_registry

logger = logging.getLogger(__name__)

BENIGN_LABEL = "Benign"  # CIC-UNSW-NB15 label
EXTENDED_FEATURE_NAMES = FLOW_FEATURE_NAMES + PAYLOAD_FEATURE_NAMES


def _get_classifier(model):
    """Extract the underlying classifier from a Pipeline or return as-is."""
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            return model.named_steps.get("classifier", model)
    except ImportError:
        pass
    return model


def _get_n_features(model) -> int:
    """Get n_features_in_ handling both Pipeline and plain estimator."""
    clf = _get_classifier(model)
    return int(getattr(clf, "n_features_in_", 76))


def _get_classes(model) -> list:
    """Get classes_ handling both Pipeline and plain estimator."""
    clf = _get_classifier(model)
    return list(getattr(clf, "classes_", []))


class SupervisedEngine:
    """RF Pipeline classifier for named attack detection."""

    def __init__(self, model_path: str = RF_MODEL_PATH):
        self._model = None
        self._model_path = model_path
        self._expects_payload = False
        self._benign_idx: Optional[int] = None
        self._load()

    def _load(self) -> None:
        # 1. Try MLflow registry
        model = mlflow_registry.load_latest("supervised")
        if model is not None:
            self._model = model
            logger.info("SupervisedEngine loaded from MLflow")
        # 2. Fall back to locally trained full model
        elif os.path.exists(self._model_path):
            try:
                self._model = joblib.load(self._model_path)
                logger.info("SupervisedEngine loaded from %s", self._model_path)
            except Exception as e:
                logger.warning("Full RF model failed to load (%s) — trying lite model", e)
        # 3. Bundled lite model — ships with the repo for out-of-the-box detection
        if self._model is None and os.path.exists(RF_LITE_MODEL_PATH):
            try:
                self._model = joblib.load(RF_LITE_MODEL_PATH)
                logger.info("SupervisedEngine loaded from bundled lite model %s "
                            "(~88-90%% accuracy — run scripts/train_rf.py for full model)",
                            RF_LITE_MODEL_PATH)
            except Exception as e:
                logger.error("Failed to load RF lite model: %s", e)

        if self._model is None:
            logger.warning(
                "No RF model found (checked MLflow, %s, %s) — supervised engine disabled. "
                "Run: python scripts/train_rf.py",
                self._model_path, RF_LITE_MODEL_PATH,
            )
            return

        n = _get_n_features(self._model)
        self._expects_payload = (n == len(EXTENDED_FEATURE_NAMES))

        classes = _get_classes(self._model)
        self._benign_idx = classes.index(BENIGN_LABEL) if BENIGN_LABEL in classes else None

        is_pipeline = hasattr(self._model, "named_steps")
        logger.info("SupervisedEngine ready  type=%s  features=%d  benign_idx=%s",
                    "Pipeline" if is_pipeline else "Estimator", n, self._benign_idx)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    @property
    def expects_payload_features(self) -> bool:
        return self._expects_payload

    def predict(
        self,
        flow_features: np.ndarray,
        payload_features: Optional[np.ndarray] = None,
    ) -> Optional[Tuple[str, float]]:
        """Return (attack_type, confidence) for the given flow vector.

        attack_type is BENIGN_LABEL for normal traffic.
        Returns None if the engine is unavailable.
        """
        if not self.is_available:
            return None
        try:
            vec = self._build_vec(flow_features, payload_features)
            label = str(self._model.predict(vec)[0])
            proba = self._model.predict_proba(vec)[0]
            return label, float(proba.max())
        except Exception as e:
            logger.error("SupervisedEngine.predict error: %s", e)
            return None

    def anomaly_score(
        self,
        flow_features: np.ndarray,
        payload_features: Optional[np.ndarray] = None,
    ) -> float:
        """Return calibrated anomaly score in [0, 1].

        Computed as 1 - P(Benign).  Returns 0.0 when below RF_SCORE_THRESHOLD
        to suppress low-confidence false positives.
        """
        if not self.is_available:
            return 0.0
        try:
            vec = self._build_vec(flow_features, payload_features)
            proba = self._model.predict_proba(vec)[0]
            if self._benign_idx is not None:
                score = float(1.0 - proba[self._benign_idx])
            else:
                label = str(self._model.predict(vec)[0])
                score = 0.0 if label == BENIGN_LABEL else float(proba.max())
            return score if score >= RF_SCORE_THRESHOLD else 0.0
        except Exception as e:
            logger.error("SupervisedEngine.anomaly_score error: %s", e)
            return 0.0

    # ── Internal ──────────────────────────────────────────────────────────

    def _build_vec(self, flow_features: np.ndarray,
                   payload_features: Optional[np.ndarray]) -> np.ndarray:
        flat = np.asarray(flow_features).ravel()
        if self._expects_payload and payload_features is not None:
            flat = np.concatenate([flat, np.asarray(payload_features).ravel()])
        return flat.reshape(1, -1)
