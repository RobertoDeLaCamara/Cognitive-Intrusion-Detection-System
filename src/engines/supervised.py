"""Supervised classification engine — Random Forest trained on CIC-IDS2017.

Wraps the ML-IDS model (joblib) and returns a (attack_type, confidence) pair
from a 76-feature flow vector.
"""

import logging
import os
import numpy as np
from typing import Optional, Tuple

import joblib

from ..config import RF_MODEL_PATH, RF_SCORE_THRESHOLD
from ..features.flow_extractor import FLOW_FEATURE_NAMES
from ..features.payload_analyzer import PAYLOAD_FEATURE_NAMES
from .. import mlflow_registry

logger = logging.getLogger(__name__)

BENIGN_LABEL = "Benign"  # CIC-UNSW-NB15 dataset label (was "BENIGN" for demo model)
EXTENDED_FEATURE_NAMES = FLOW_FEATURE_NAMES + PAYLOAD_FEATURE_NAMES


class SupervisedEngine:
    """Random Forest classifier for named attack detection."""

    def __init__(self, model_path: str = RF_MODEL_PATH):
        self._model = None
        self._model_path = model_path
        self._expects_payload = False
        self._load()

    def _load(self) -> None:
        # Try MLflow first, fall back to local file
        model = mlflow_registry.load_latest("supervised")
        if model is not None:
            self._model = model
        elif os.path.exists(self._model_path):
            try:
                self._model = joblib.load(self._model_path)
            except Exception as e:
                logger.error("Failed to load RF model: %s", e)
                return
        else:
            logger.warning("RF model not found at %s — supervised engine disabled", self._model_path)
            return
        n = getattr(self._model, "n_features_in_", 76)
        self._expects_payload = (n == len(EXTENDED_FEATURE_NAMES))
        # Cache the index of the benign class for fast anomaly_score computation
        classes = list(getattr(self._model, "classes_", []))
        self._benign_idx = classes.index(BENIGN_LABEL) if BENIGN_LABEL in classes else None
        logger.info("SupervisedEngine loaded (%d features, benign_idx=%s)",
                    n, self._benign_idx)

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
        """Predict attack type and confidence score.

        Args:
            flow_features: 76-element flow feature vector.
            payload_features: Optional 10-element payload feature vector.
                Appended only if the loaded model expects 86 features.

        Returns:
            (attack_type, confidence) — attack_type is 'BENIGN' for normal traffic.
            None if engine unavailable or prediction fails.
        """
        if not self.is_available:
            return None
        try:
            vec = flow_features
            if self._expects_payload and payload_features is not None:
                vec = np.concatenate([flow_features, payload_features])
            vec = vec.reshape(1, -1)
            label = self._model.predict(vec)[0]
            proba = self._model.predict_proba(vec)[0]
            confidence = float(proba.max())
            return str(label), confidence
        except Exception as e:
            logger.error("SupervisedEngine prediction error: %s", e)
            return None

    def anomaly_score(
        self,
        flow_features: np.ndarray,
        payload_features: Optional[np.ndarray] = None,
    ) -> float:
        """Normalised anomaly score [0, 1]; 1.0 = definitely attack.

        Uses 1 - P(Benign) so the score is calibrated against the actual
        benign probability rather than the confidence of the predicted class.
        Returns 0.0 when the score is below RF_SCORE_THRESHOLD to suppress
        low-confidence predictions that would cause false positives.
        """
        if not self.is_available:
            return 0.0
        try:
            vec = flow_features
            if self._expects_payload and payload_features is not None:
                vec = np.concatenate([flow_features, payload_features])
            vec = vec.reshape(1, -1)
            proba = self._model.predict_proba(vec)[0]
            if self._benign_idx is not None:
                score = float(1.0 - proba[self._benign_idx])
            else:
                # Fallback: use max non-benign class probability
                label = self._model.predict(vec)[0]
                score = 0.0 if label == BENIGN_LABEL else float(proba.max())
            return score if score >= RF_SCORE_THRESHOLD else 0.0
        except Exception as e:
            logger.error("SupervisedEngine anomaly_score error: %s", e)
            return 0.0
