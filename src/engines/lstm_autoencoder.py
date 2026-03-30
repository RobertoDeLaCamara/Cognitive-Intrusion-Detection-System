"""LSTM Autoencoder engine for temporal anomaly detection.

Maintains a per-IP sequence buffer of host feature vectors and scores
anomalies via reconstruction error. Adapted from cognitive-anomaly-detector.
"""

import json
import logging
import os
import threading
import numpy as np
from collections import defaultdict, deque
from typing import Optional

from ..config import LSTM_MODEL_PATH, LSTM_CONFIG_PATH, MAX_TRACKED_IPS
from .. import mlflow_registry

logger = logging.getLogger(__name__)

DEFAULT_SEQ_LEN   = 20
DEFAULT_N_FEATURES = 18


class LSTMAutoencoderEngine:
    """Sequence-based anomaly detection using reconstruction error."""

    def __init__(
        self,
        model_path: str = LSTM_MODEL_PATH,
        config_path: str = LSTM_CONFIG_PATH,
    ):
        self._model = None
        self._seq_len = DEFAULT_SEQ_LEN
        self._n_features = DEFAULT_N_FEATURES
        self._threshold = 0.1  # reconstruction error threshold
        self._buffers: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self._seq_len)
        )
        self._lock = threading.Lock()
        self._max_buffers = MAX_TRACKED_IPS
        self._load(model_path, config_path)

    def _load(self, model_path: str, config_path: str) -> None:
        # Load config first
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                self._seq_len = cfg.get("sequence_length", DEFAULT_SEQ_LEN)
                self._n_features = cfg.get("n_features", DEFAULT_N_FEATURES)
                self._threshold = cfg.get("reconstruction_threshold", 0.1)
            except Exception as e:
                logger.warning("LSTM config load failed: %s", e)

        # Try MLflow first for LSTM
        mlflow_model = mlflow_registry.load_latest_pytorch("lstm")
        if mlflow_model is not None:
            self._model = mlflow_model
            self._model.eval()
            logger.info("LSTMAutoencoderEngine loaded from MLflow")
        elif not os.path.exists(model_path):
            logger.warning("LSTM model not found at %s — LSTM engine disabled", model_path)
            return
        else:
            try:
                import torch
                from .lstm_model import LSTMAutoencoder
                cfg_kwargs = {
                    "n_features": self._n_features,
                    "hidden_dim": 64,
                    "latent_dim": 32,
                    "num_layers": 2,
                    "dropout": 0.2,
                }
                # Load config-driven architecture if available
                if os.path.exists(config_path):
                    try:
                        with open(config_path) as f:
                            import json as _json
                            lcfg = _json.load(f)
                        cfg_kwargs.update({
                            k: lcfg[k] for k in ("hidden_dim", "latent_dim", "num_layers", "dropout")
                            if k in lcfg
                        })
                    except Exception:
                        pass
                self._model = LSTMAutoencoder(**cfg_kwargs)
                state = torch.load(model_path, map_location="cpu", weights_only=True)
                self._model.load_state_dict(state)
                self._model.eval()
                logger.info("LSTMAutoencoderEngine loaded: %s", model_path)
            except Exception as e:
                logger.error("Failed to load LSTM model: %s", e)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    def update(self, ip: str, host_features: np.ndarray) -> None:
        """Add a host feature vector to this IP's sequence buffer."""
        with self._lock:
            if ip not in self._buffers and len(self._buffers) >= self._max_buffers:
                # Evict the IP with the shortest buffer (least data)
                victim = min(self._buffers, key=lambda k: len(self._buffers[k]))
                del self._buffers[victim]
            self._buffers[ip].append(host_features.astype(np.float32))

    def anomaly_score(self, ip: str) -> float:
        """Reconstruction error normalised to [0, 1]. 0 if buffer not full."""
        if not self.is_available:
            return 0.0
        with self._lock:
            buf = self._buffers.get(ip)
            if buf is None or len(buf) < self._seq_len:
                return 0.0
            seq = np.array(list(buf), dtype=np.float32)

        try:
            import torch
            x = torch.tensor(seq).unsqueeze(0)   # (1, seq_len, n_features)
            with torch.no_grad():
                reconstructed = self._model(x)
            error = float(torch.mean((x - reconstructed) ** 2).item())
            # Normalise: errors above threshold map toward 1.0
            score = min(error / max(self._threshold, 1e-9), 1.0)
            return float(score)
        except Exception as e:
            logger.error("LSTM score error for %s: %s", ip, e)
            return 0.0
