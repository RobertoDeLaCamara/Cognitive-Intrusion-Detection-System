"""FT-Transformer supervised engine — drop-in replacement for SupervisedEngine
when the unified ML-IDS+cnds checkpoint is present.

Drop-in interface: implements `is_available`, `predict(flow_features, payload_features=None)`,
and `anomaly_score(...)` so it can be used wherever SupervisedEngine was used.

Inference pipeline (matches notebooks/ft_transformer_optuna_sweep.py):
    x = nan_to_num(x, posinf=1e9, neginf=-1e9)
    x = scaler.transform(x)
    logits = model(x)            # AMP bf16 on CUDA, fp32 on CPU
    logits = logits / FT_TEMPERATURE   # temperature scaling (default 2.0)
    probs = softmax(logits)
    pred = argmax(probs)

Loading priority:
    1. MLflow registry (if MLFLOW_TRACKING_URI is configured)
    2. Local checkpoint at FT_MODEL_PATH + scaler at FT_SCALER_PATH
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

import joblib
import numpy as np

from ..config import (
    FT_MODEL_PATH,
    FT_SCALER_PATH,
    FT_SCORE_THRESHOLD,
    FT_TEMPERATURE,
    FT_USE_GPU,
)
from .. import mlflow_registry

logger = logging.getLogger(__name__)


class FTTransformerEngine:
    """Unified FT-Transformer classifier on the 76 CICFlowMeter features."""

    def __init__(
        self,
        model_path: str = FT_MODEL_PATH,
        scaler_path: str = FT_SCALER_PATH,
        use_gpu: bool = FT_USE_GPU,
        temperature: float = FT_TEMPERATURE,
    ) -> None:
        self._model = None
        self._scaler = None
        self._labels: Tuple[str, ...] = ()
        self._benign_idx: Optional[int] = None
        self._n_features: int = 0
        self._device = "cpu"
        self._use_amp = False
        self._model_path = model_path
        self._scaler_path = scaler_path
        self._use_gpu = use_gpu
        self._temperature = temperature
        self._load()

    # ── Loading ────────────────────────────────────────────────────────────
    def _load(self) -> None:
        # Quick exit before any torch import: if there is no MLflow URI and no
        # local checkpoint file, the engine has nothing to load. Importing torch
        # eagerly here would interfere with tests that install a fake torch
        # module via fixture (`tests/engines/test_baseline_engine.py`).
        if not mlflow_registry.is_enabled() and not os.path.exists(self._model_path):
            logger.info(
                "FTTransformerEngine disabled: no checkpoint at MLflow registry "
                "or local path %s",
                self._model_path,
            )
            return

        try:
            import torch  # noqa: F401  (probe + later use)
        except ImportError:
            logger.info(
                "FTTransformerEngine disabled: torch is not installed "
                "(CPU build is added in Docker; install torch separately for bare-metal use)"
            )
            return

        bundle = self._try_mlflow() or self._try_local()
        if bundle is None:
            logger.info(
                "FTTransformerEngine disabled: no checkpoint at MLflow registry "
                "or local path %s",
                self._model_path,
            )
            return

        try:
            from ..models.ft_transformer import (
                build_from_checkpoint,
                UNIFIED_CLASS_LABELS,
            )
        except Exception as e:
            logger.error("Failed to import FTTransformer module: %s", e)
            return

        self._model = build_from_checkpoint(bundle)
        self._n_features = int(bundle.get("n_features", 0))
        self._labels = tuple(
            bundle.get("class_labels") or UNIFIED_CLASS_LABELS[: int(bundle.get("n_classes", 0))]
        )
        if "Benign" in self._labels:
            self._benign_idx = self._labels.index("Benign")

        # Device
        import torch
        if self._use_gpu and torch.cuda.is_available():
            self._device = "cuda"
            self._use_amp = True
            self._model = self._model.to(self._device)
        else:
            self._device = "cpu"
            self._use_amp = False

        # Scaler
        scaler = self._load_scaler()
        if scaler is None:
            logger.error(
                "FTTransformerEngine: model loaded but scaler missing at %s — "
                "engine disabled (predictions would be uncalibrated).",
                self._scaler_path,
            )
            self._model = None
            return
        self._scaler = scaler

        logger.info(
            "FTTransformerEngine ready  device=%s  features=%d  classes=%d  benign_idx=%s",
            self._device,
            self._n_features,
            len(self._labels),
            self._benign_idx,
        )

    def _try_mlflow(self):
        """Try loading the unified model checkpoint from MLflow.

        Returns a checkpoint bundle (dict) if successful, else None.
        Uses mlflow.pytorch's artifact-download path (not log_model) because
        the registered model is the raw .pt bundle.
        """
        if not mlflow_registry.is_enabled():
            return None
        try:
            import mlflow
            from ..config import MLFLOW_FT_REGISTRY_NAME, MLFLOW_FT_STAGE
            client = mlflow.tracking.MlflowClient()
            versions = client.get_latest_versions(MLFLOW_FT_REGISTRY_NAME, stages=[MLFLOW_FT_STAGE])
            if not versions:
                return None
            artifact_uri = versions[0].source
            local = mlflow.artifacts.download_artifacts(artifact_uri=artifact_uri)
            from ..models.ft_transformer import load_checkpoint
            bundle = load_checkpoint(_pick_pt_file(local))
            logger.info("FTTransformerEngine: loaded from MLflow %s/%s",
                        MLFLOW_FT_REGISTRY_NAME, MLFLOW_FT_STAGE)
            return bundle
        except Exception as e:
            logger.debug("MLflow FT load failed (falling back to local): %s", e)
            return None

    def _try_local(self):
        if not os.path.exists(self._model_path):
            return None
        try:
            from ..models.ft_transformer import load_checkpoint
            bundle = load_checkpoint(self._model_path)
            logger.info("FTTransformerEngine: loaded checkpoint from %s", self._model_path)
            return bundle
        except Exception as e:
            logger.error("Failed to load FT checkpoint at %s: %s", self._model_path, e)
            return None

    def _load_scaler(self):
        if not os.path.exists(self._scaler_path):
            return None
        try:
            return joblib.load(self._scaler_path)
        except Exception as e:
            logger.error("Failed to load scaler at %s: %s", self._scaler_path, e)
            return None

    # ── Public API ─────────────────────────────────────────────────────────
    @property
    def is_available(self) -> bool:
        return self._model is not None and self._scaler is not None

    @property
    def expects_payload_features(self) -> bool:
        # Unified model uses only the 76 flow features.
        return False

    def predict(
        self,
        flow_features: np.ndarray,
        payload_features: Optional[np.ndarray] = None,
    ) -> Optional[Tuple[str, float]]:
        if not self.is_available:
            return None
        try:
            probs = self._forward(flow_features)
            idx = int(probs.argmax())
            label = self._labels[idx] if idx < len(self._labels) else f"class_{idx}"
            return label, float(probs[idx])
        except Exception as e:
            logger.error("FTTransformerEngine.predict error: %s", e)
            return None

    def anomaly_score(
        self,
        flow_features: np.ndarray,
        payload_features: Optional[np.ndarray] = None,
    ) -> float:
        if not self.is_available:
            return 0.0
        try:
            probs = self._forward(flow_features)
            if self._benign_idx is not None:
                score = float(1.0 - probs[self._benign_idx])
            else:
                score = float(probs.max())
            return score if score >= FT_SCORE_THRESHOLD else 0.0
        except Exception as e:
            logger.error("FTTransformerEngine.anomaly_score error: %s", e)
            return 0.0

    # ── Internal ───────────────────────────────────────────────────────────
    def _forward(self, flow_features: np.ndarray) -> np.ndarray:
        """Run a single-sample forward pass and return probabilities (numpy 1D)."""
        import torch

        x = np.asarray(flow_features, dtype=np.float32).ravel()
        if x.shape[0] != self._n_features:
            raise ValueError(
                f"FTTransformer expects {self._n_features} features, got {x.shape[0]}"
            )
        x = np.nan_to_num(x, nan=0.0, posinf=1e9, neginf=-1e9)
        x = self._scaler.transform(x.reshape(1, -1)).astype(np.float32)
        t = torch.from_numpy(x).to(self._device)
        with torch.inference_mode():
            if self._use_amp:
                with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                    logits = self._model(t)
            else:
                logits = self._model(t)
            if self._temperature != 1.0:
                logits = logits / self._temperature
            probs = logits.softmax(-1).float().cpu().numpy()[0]
        return probs


def _pick_pt_file(path: str) -> str:
    """Resolve a downloaded MLflow artifact to a single .pt file path."""
    if os.path.isfile(path):
        return path
    for entry in os.listdir(path):
        if entry.endswith(".pt"):
            return os.path.join(path, entry)
    raise FileNotFoundError(f"No .pt file under {path}")
