"""Train IsolationForest + LSTM Autoencoder on a collected baseline window.

Persists artifacts to MLflow under a canonical layout. If MLflow is not
available, models are still fitted locally (and a warning is logged).
"""

import json
import logging
import os
import tempfile
from typing import Callable, List, Optional

import joblib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .. import mlflow_registry
from ..engines.lstm_model import LSTMAutoencoder
from .artifact_schema import (
    ARTIFACT_ROOT,
    IFOREST_FILE,
    LSTM_FILE,
    MODEL_NAME,
    PROVENANCE_FILE,
    SCALER_FILE,
    THRESHOLD_FILE,
)
from .collector import CollectedSample
from .provenance import ProvenanceMetadata

logger = logging.getLogger(__name__)


def _to_sequences(X: np.ndarray, seq_len: int) -> np.ndarray:
    """Produce sliding-window sequences of shape (N-seq_len+1, seq_len, n_features).

    Uses stride tricks for a zero-copy view — ~10-30x faster than a Python loop
    at 500k samples. The .copy() call converts the view to a contiguous array
    required by torch.from_numpy() and prevents aliasing issues after X is freed.
    """
    if X.ndim != 2:
        raise ValueError(f"expected 2D input, got shape {X.shape}")
    n, f = X.shape
    if n < seq_len:
        return np.empty((0, seq_len, f), dtype=X.dtype)
    shape = (n - seq_len + 1, seq_len, f)
    strides = (X.strides[0], X.strides[0], X.strides[1])
    return np.lib.stride_tricks.as_strided(X, shape=shape, strides=strides).copy()


class WindowTrainer:
    def __init__(
        self,
        experiment_name: str = "cnds-unsupervised-baseline",
        val_fraction: float = 0.20,
        threshold_percentile: float = 99.0,
        iforest_contamination: float = 0.01,
        seq_len: int = 20,
        on_trained: Optional[Callable[[], None]] = None,
    ):
        self._experiment_name = experiment_name
        self._val_fraction = val_fraction
        self._threshold_percentile = threshold_percentile
        self._contamination = iforest_contamination
        self._seq_len = seq_len
        self._on_trained = on_trained
        # Initialise MLflow once at construction time, not on every training run.
        # mlflow_registry.init() strips proxy env vars process-wide — calling it
        # from the background training thread on every window would race with other
        # threads that use the proxy for outbound connections.
        mlflow_registry.init()

    def train_window(
        self, samples: List[CollectedSample], provenance: ProvenanceMetadata
    ) -> None:
        if len(samples) < 1000:
            logger.warning(
                "Baseline window too small (n=%d < 1000) — skipping training",
                len(samples),
            )
            return

        # 1. Stack feature vectors.
        X = np.stack([s.host_vec for s in samples]).astype(np.float32)

        # 2. Train/val split.
        X_train, X_val = train_test_split(
            X, test_size=self._val_fraction, shuffle=True, random_state=42
        )

        # 3. Scaler.
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train).astype(np.float32)
        X_val_s = scaler.transform(X_val).astype(np.float32)

        # 4. IsolationForest.
        iforest = IsolationForest(
            n_estimators=200,
            contamination=self._contamination,
            n_jobs=-1,
            random_state=42,
        )
        iforest.fit(X_train_s)

        # 5. LSTM autoencoder.
        n_features = X_train_s.shape[1]
        seq_train = _to_sequences(X_train_s, self._seq_len)
        seq_val = _to_sequences(X_val_s, self._seq_len)

        if seq_train.shape[0] == 0 or seq_val.shape[0] == 0:
            logger.warning(
                "Not enough samples to form sequences (train=%d, val=%d) — skipping",
                seq_train.shape[0],
                seq_val.shape[0],
            )
            return

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = LSTMAutoencoder(n_features=n_features).to(device)
        optimizer = optim.Adam(model.parameters(), lr=1e-3)
        criterion = nn.MSELoss()

        batch_size = 256
        epochs = 20
        try:
            train_tensor = torch.from_numpy(seq_train).to(device)
            val_tensor = torch.from_numpy(seq_val).to(device)
        except (RuntimeError, Exception) as oom:
            # CUDA OOM or similar — fall back to CPU so training is not lost.
            logger.warning("GPU transfer failed (%s) — falling back to CPU", oom)
            device = torch.device("cpu")
            model = model.to(device)
            train_tensor = torch.from_numpy(seq_train)
            val_tensor = torch.from_numpy(seq_val)

        model.train()
        n_train_seq = train_tensor.shape[0]
        for epoch in range(epochs):
            perm = torch.randperm(n_train_seq, device=device)
            epoch_loss = 0.0
            n_batches = 0
            for start in range(0, n_train_seq, batch_size):
                idx = perm[start : start + batch_size]
                batch = train_tensor[idx]
                optimizer.zero_grad()
                recon = model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += float(loss.item())
                n_batches += 1
            if (epoch + 1) % 5 == 0:
                logger.info(
                    "LSTM epoch %d/%d loss=%.6f",
                    epoch + 1,
                    epochs,
                    epoch_loss / max(n_batches, 1),
                )

        # 6. Threshold on validation reconstruction error.
        model.eval()
        with torch.no_grad():
            val_recon = model(val_tensor)
            # Per-sequence MSE (mean over seq_len and features).
            per_seq = ((val_recon - val_tensor) ** 2).mean(dim=(1, 2)).cpu().numpy()
        threshold = float(np.percentile(per_seq, self._threshold_percentile))
        val_recon_mean = float(per_seq.mean())
        val_recon_std = float(per_seq.std())

        # Training-result counts — kept local; not mutated into ProvenanceMetadata
        # (which describes the collection window, not the training outcome).
        n_sequences = int(seq_train.shape[0] + seq_val.shape[0])
        n_train_seq = int(seq_train.shape[0])
        n_val_seq = int(seq_val.shape[0])

        logger.info(
            "Baseline trained: n=%d iforest✓ lstm_threshold_p%.1f=%.6f",
            len(samples),
            self._threshold_percentile,
            threshold,
        )

        # 7. Persist to MLflow (or fall back to fit-only with a warning).
        mlflow_ok = mlflow_registry.is_enabled()
        if not mlflow_ok:
            logger.warning(
                "MLflow not enabled — baseline models fitted but not persisted to registry"
            )
            return

        mlflow = mlflow_registry._get_mlflow()
        registered_ok = False
        try:
            mlflow.set_experiment(self._experiment_name)
            with mlflow.start_run(run_name="baseline-window") as run:
                mlflow.log_metrics(
                    {
                        "n_sequences": float(n_sequences),
                        "n_train": float(n_train_seq),
                        "n_val": float(n_val_seq),
                        "distinct_src_ips": float(provenance.distinct_src_ips),
                        "dst_port_entropy_bits": float(provenance.dst_port_entropy_bits),
                        "lstm_threshold_p99": threshold,
                        "val_recon_mean": val_recon_mean,
                        "val_recon_std": val_recon_std,
                    }
                )
                mlflow.log_params(
                    {
                        "seq_len": self._seq_len,
                        "val_fraction": self._val_fraction,
                        "threshold_percentile": self._threshold_percentile,
                        "iforest_contamination": self._contamination,
                        "fire_reason": provenance.fire_reason,
                    }
                )

                with tempfile.TemporaryDirectory() as tmp:
                    scaler_path = os.path.join(tmp, SCALER_FILE)
                    iforest_path = os.path.join(tmp, IFOREST_FILE)
                    lstm_path = os.path.join(tmp, LSTM_FILE)
                    threshold_path = os.path.join(tmp, THRESHOLD_FILE)
                    provenance_path = os.path.join(tmp, PROVENANCE_FILE)

                    joblib.dump(scaler, scaler_path)
                    joblib.dump(iforest, iforest_path)
                    torch.save(model.state_dict(), lstm_path)
                    with open(threshold_path, "w") as f:
                        f.write(f"{threshold}")
                    with open(provenance_path, "w") as f:
                        json.dump(provenance.to_dict(), f, indent=2)

                    mlflow.log_artifacts(tmp, artifact_path=ARTIFACT_ROOT)

                try:
                    mlflow.register_model(
                        f"runs:/{run.info.run_id}/{ARTIFACT_ROOT}", MODEL_NAME
                    )
                    registered_ok = True
                except Exception as e:
                    logger.warning("MLflow register_model failed: %s", e)
            # Run is now FINISHED — safe to trigger the inference engine reload.
            # Calling inside the run context risked reading a version while the
            # producing run was still in RUNNING state.
            if registered_ok and self._on_trained is not None:
                try:
                    self._on_trained()
                except Exception as cb_e:
                    logger.exception("on_trained callback failed: %s", cb_e)
        except Exception as e:
            logger.error("MLflow logging failed for baseline window: %s", e)
