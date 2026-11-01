"""Train IsolationForest + LSTM Autoencoder on a collected baseline window.

Persists artifacts to MLflow under a canonical layout. If MLflow is not
available, models are still fitted locally (and a warning is logged).
"""

import json
import logging
import os
import tempfile
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .. import mlflow_registry
from ..config import (
    BASELINE_MAX_CONSECUTIVE_REJECTS,
    BASELINE_THRESHOLD_MAX_RATIO,
    BASELINE_THRESHOLD_REF_WINDOWS,
)
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


def _register_baseline(mlflow, run_id: str, artifact_uri: str) -> None:
    """Create a registry version for the baseline artifacts.

    ``mlflow.register_model()`` from a 3.x client queries ``/logged-models/search``,
    which a 2.x tracking server (ours is 2.22.1) does not implement, so it fails
    before any version is created. ``create_model_version`` only uses the classic
    registry endpoints and works against both server generations.
    """
    client = mlflow.tracking.MlflowClient()
    try:
        client.create_registered_model(MODEL_NAME)
    except Exception:  # already exists (or a race): create_model_version will tell
        pass
    client.create_model_version(
        name=MODEL_NAME,
        source=f"{artifact_uri.rstrip('/')}/{ARTIFACT_ROOT}",
        run_id=run_id,
    )


def _threshold_is_stable(threshold: float, reference: List[float], max_ratio: float) -> bool:
    """True if ``threshold`` is within a factor ``max_ratio`` of the median of ``reference``.

    The p99 of a small validation set is driven by a handful of outliers and was seen to swing
    0.32 -> 8.93 between consecutive windows of the same network. An empty reference or
    ``max_ratio <= 0`` accepts everything (first window after a restart, gate disabled).
    """
    if max_ratio <= 0 or not reference:
        return True
    median = float(np.median(reference))
    if median <= 0:
        return True
    return median / max_ratio <= threshold <= median * max_ratio


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


def _to_host_sequences(X: np.ndarray, hosts: Sequence[str], seq_len: int) -> np.ndarray:
    """Sliding-window sequences built inside each host's own rows.

    ``X`` must be in time order. This mirrors inference, where the engine keeps one
    ``seq_len`` buffer per source IP: a training sequence is ``seq_len`` consecutive
    vectors of ONE host, never a mix of hosts. Hosts with fewer than ``seq_len`` rows
    contribute nothing (the engine also returns no score until a buffer is full).
    """
    if X.ndim != 2:
        raise ValueError(f"expected 2D input, got shape {X.shape}")
    if len(hosts) != len(X):
        raise ValueError(f"hosts ({len(hosts)}) and X ({len(X)}) must have the same length")
    rows_by_host: dict = defaultdict(list)
    for i, h in enumerate(hosts):
        rows_by_host[h].append(i)
    parts = [
        _to_sequences(X[idx], seq_len)
        for idx in rows_by_host.values()
        if len(idx) >= seq_len
    ]
    if not parts:
        return np.empty((0, seq_len, X.shape[1]), dtype=X.dtype)
    return np.concatenate(parts, axis=0)


def _temporal_split(
    X: np.ndarray, hosts: Sequence[str], ts: np.ndarray, val_fraction: float
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """Chronological split: the oldest ``1 - val_fraction`` of rows train, the newest validate.

    A random split puts neighbouring rows of the same host on both sides, which makes the
    validation error optimistic and the LSTM threshold unstable. Rows are ordered by
    timestamp (stable), so equal timestamps keep their arrival order.
    """
    order = np.argsort(ts, kind="stable")
    cut = int(len(order) * (1.0 - val_fraction))
    tr, va = order[:cut], order[cut:]
    return X[tr], X[va], [hosts[i] for i in tr], [hosts[i] for i in va]


@dataclass
class FitResult:
    """Everything ``fit_models`` produces; the same objects ``train_window`` persists."""

    scaler: StandardScaler
    iforest: IsolationForest
    model: object                 # torch LSTMAutoencoder, eval mode
    threshold: float              # LSTM validation-error percentile
    seq_len: int
    n_train_seq: int
    n_val_seq: int
    val_recon_mean: float
    val_recon_std: float
    n_train_rows: int
    n_val_rows: int
    n_features: int


def fit_models(
    X: np.ndarray,
    hosts: Sequence[str],
    ts: np.ndarray,
    *,
    val_fraction: float = 0.20,
    seq_len: int = 20,
    threshold_percentile: float = 99.0,
    contamination: float = 0.01,
    epochs: int = 20,
    batch_size: int = 256,
) -> Optional["FitResult"]:
    """Fit scaler + IsolationForest + LSTM autoencoder on one window of finite host vectors.

    Chronological split, per-host sequences. Returns ``None`` when the window cannot form
    sequences on both sides. This is the single training routine: ``WindowTrainer.train_window``
    persists its result and ``scripts/eval_baseline.py`` evaluates it, so the bench always
    measures what ships.
    """
    import torch
    import torch.nn as nn
    import torch.optim as optim

    # 2. Chronological train/val split (oldest rows train, newest validate).
    X_train, X_val, hosts_train, hosts_val = _temporal_split(
        X, hosts, ts, val_fraction
    )

    # 3. Scaler.
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train).astype(np.float32)
    X_val_s = scaler.transform(X_val).astype(np.float32)

    # 4. IsolationForest.
    iforest = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        n_jobs=-1,
        random_state=42,
    )
    iforest.fit(X_train_s)

    # 5. LSTM autoencoder.
    n_features = X_train_s.shape[1]
    seq_train = _to_host_sequences(X_train_s, hosts_train, seq_len)
    seq_val = _to_host_sequences(X_val_s, hosts_val, seq_len)

    if seq_train.shape[0] == 0 or seq_val.shape[0] == 0:
        logger.warning(
            "Not enough samples to form sequences (train=%d, val=%d) — skipping",
            seq_train.shape[0],
            seq_val.shape[0],
        )
        return None

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = LSTMAutoencoder(n_features=n_features).to(device)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

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
    threshold = float(np.percentile(per_seq, threshold_percentile))
    val_recon_mean = float(per_seq.mean())
    val_recon_std = float(per_seq.std())


    return FitResult(
        scaler=scaler,
        iforest=iforest,
        model=model,
        threshold=threshold,
        seq_len=seq_len,
        n_train_seq=int(seq_train.shape[0]),
        n_val_seq=int(seq_val.shape[0]),
        val_recon_mean=val_recon_mean,
        val_recon_std=val_recon_std,
        n_train_rows=int(len(X_train)),
        n_val_rows=int(len(X_val)),
        n_features=int(n_features),
    )


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

        # Rolling history of the last 20 trained windows (thread-safe).
        self._history: deque = deque(maxlen=20)
        self._history_lock = threading.Lock()

        # Thresholds of the windows that were promoted (stability gate reference), in-process only.
        self._accepted_thresholds: deque = deque(maxlen=max(BASELINE_THRESHOLD_REF_WINDOWS, 1))
        self._consecutive_rejects = 0
        self._windows_trained_total: int = 0

    def get_history(self) -> list:
        """Return a copy of the rolling window history (most recent last)."""
        with self._history_lock:
            return list(self._history)

    def get_windows_trained_total(self) -> int:
        """Return the cumulative count of successfully trained windows (monotone counter)."""
        with self._history_lock:
            return self._windows_trained_total

    def _accept_threshold(self, threshold: float) -> bool:
        """Stability gate. True if the window may be promoted, False to keep the current baseline."""
        reference = list(self._accepted_thresholds)
        if not _threshold_is_stable(threshold, reference, BASELINE_THRESHOLD_MAX_RATIO):
            if self._consecutive_rejects < BASELINE_MAX_CONSECUTIVE_REJECTS:
                self._consecutive_rejects += 1
                logger.warning(
                    "Baseline window REJECTED: threshold %.6f is more than %.1fx away from the "
                    "median %.6f of the last %d accepted windows (reject %d/%d); keeping the "
                    "current baseline",
                    threshold, BASELINE_THRESHOLD_MAX_RATIO, float(np.median(reference)),
                    len(reference), self._consecutive_rejects, BASELINE_MAX_CONSECUTIVE_REJECTS,
                )
                return False
            logger.warning(
                "Baseline threshold %.6f stayed out of range for %d windows in a row — "
                "accepting it as a regime change",
                threshold, self._consecutive_rejects,
            )
            self._accepted_thresholds.clear()
        self._consecutive_rejects = 0
        self._accepted_thresholds.append(threshold)
        return True

    def train_window(
        self, samples: List[CollectedSample], provenance: ProvenanceMetadata
    ) -> None:
        try:
            import torch
        except ImportError as exc:
            raise ImportError(
                "torch is required for baseline window training. "
                "Install it with: pip install torch"
            ) from exc

        if len(samples) < 1000:
            logger.warning(
                "Baseline window too small (n=%d < 1000) — skipping training",
                len(samples),
            )
            return

        # 1. Stack feature vectors.
        X = np.stack([s.host_vec for s in samples]).astype(np.float32)
        hosts = [s.src_ip for s in samples]
        ts = np.asarray([s.ts_epoch for s in samples], dtype=np.float64)

        # Drop NaN/Inf rows before fitting the scaler — StandardScaler propagates NaN
        # silently, producing a poisoned scaler whose mean_/scale_ are NaN.
        nan_mask = ~np.isfinite(X).all(axis=1)
        if nan_mask.any():
            n_bad = int(nan_mask.sum())
            logger.warning(
                "Baseline window: %d/%d samples contain NaN/Inf — dropping before training",
                n_bad, len(X),
            )
            keep = ~nan_mask
            X = X[keep]
            hosts = [h for h, k in zip(hosts, keep) if k]
            ts = ts[keep]
            if len(X) < 1000:
                logger.warning(
                    "After NaN purge, n=%d < 1000 — skipping training", len(X)
                )
                return

        fit = fit_models(
            X, hosts, ts,
            val_fraction=self._val_fraction,
            seq_len=self._seq_len,
            threshold_percentile=self._threshold_percentile,
            contamination=self._contamination,
        )
        if fit is None:
            return
        scaler, iforest, model = fit.scaler, fit.iforest, fit.model
        threshold = fit.threshold
        val_recon_mean, val_recon_std = fit.val_recon_mean, fit.val_recon_std
        seq_train_n, seq_val_n = fit.n_train_seq, fit.n_val_seq
        n_features = fit.n_features

        # Training-result counts — kept local; not mutated into ProvenanceMetadata
        # (which describes the collection window, not the training outcome).
        n_sequences = seq_train_n + seq_val_n
        n_train_seq = seq_train_n
        n_val_seq = seq_val_n

        logger.info(
            "Baseline trained: n=%d iforest✓ lstm_threshold_p%.1f=%.6f",
            len(samples),
            self._threshold_percentile,
            threshold,
        )

        # 6b. Stability gate: do not replace the live baseline with an outlier window.
        if not self._accept_threshold(threshold):
            return

        # 7. Record in rolling history (always, regardless of MLflow availability).
        entry = {
            "trained_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "provenance": provenance.to_dict(),
            "training_stats": {
                "val_recon_mean": val_recon_mean,
                "val_recon_std": val_recon_std,
                "threshold": threshold,
                "n_train": n_train_seq,
                "n_val": n_val_seq,
                "n_features": n_features,
            },
        }
        with self._history_lock:
            self._history.append(entry)
            self._windows_trained_total += 1

        # 8. Persist to MLflow (or fall back to fit-only with a warning).
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
                        json.dump(
                            {"threshold": threshold, "percentile": self._threshold_percentile}, f
                        )
                    with open(provenance_path, "w") as f:
                        json.dump(provenance.to_dict(), f, indent=2)

                    mlflow.log_artifacts(tmp, artifact_path=ARTIFACT_ROOT)

                run_id = run.info.run_id  # capture before the context manager closes the run
                artifact_uri = run.info.artifact_uri
            # Run is now FINISHED — registration outside the context so the artifact
            # set is immutable before the registry entry is created.
            try:
                _register_baseline(mlflow, run_id, artifact_uri)
                registered_ok = True
            except Exception as e:
                logger.warning("MLflow baseline registration failed: %s", e)
            if registered_ok and self._on_trained is not None:
                try:
                    self._on_trained()
                except Exception as cb_e:
                    logger.exception("on_trained callback failed: %s", cb_e)
        except Exception as e:
            logger.error("MLflow logging failed for baseline window: %s", e)
