"""Stability test: two consecutive baseline windows from the same distribution
should produce similar reconstruction thresholds and val loss.

Marked @pytest.mark.slow — excluded from the default run, included in CI nightly.
Run manually with: pytest tests/unsupervised/test_window_stability.py -v -m slow

What a failure means:
  If |threshold_delta| > 25% or |val_recon_mean_delta| > 30%, the training
  process is unstable for the given data distribution. Possible causes:
    - Too few samples (increase n_samples or reduce val_fraction)
    - Unstable LSTM learning rate / epoch count
    - Non-determinism in torch random ops (check torch.manual_seed)
  A consistently failing stability test is a signal that BaselineEngine will
  produce unreliable anomaly scores in production.
"""

import numpy as np
import pytest

from src.unsupervised.window_trainer import WindowTrainer
from src.unsupervised.collector import CollectedSample


def _make_samples(n: int, n_features: int = 18, seed: int = 42) -> list:
    """Generate synthetic samples from a fixed multivariate normal distribution."""
    rng = np.random.default_rng(seed)
    # Realistic homelab traffic-like distribution: positive values, moderate variance
    mean = np.abs(rng.normal(50.0, 20.0, n_features))
    cov = np.diag(np.abs(rng.normal(10.0, 3.0, n_features)) ** 2)
    vectors = rng.multivariate_normal(mean, cov, size=n).astype(np.float32)
    vectors = np.clip(vectors, 0, None)

    samples = []
    ports = [80, 443, 53, 22, 8080, 8443, 3306, 5432, 6379, 27017]
    for i, vec in enumerate(vectors):
        samples.append(CollectedSample(
            host_vec=vec,
            src_ip=f"10.0.{i % 20}.{(i * 7) % 256}",
            dst_ip="192.168.1.1",
            dst_port=ports[i % len(ports)],
            protocol="TCP",
            ts_epoch=1_700_000_000.0 + i,
        ))
    return samples


@pytest.mark.slow
def test_two_consecutive_windows_are_stable():
    """Train two WindowTrainers on samples from the same distribution.

    Assertions verify that the trained threshold and val reconstruction mean
    are within acceptable relative tolerance of each other.
    """
    N_SAMPLES = 5_000
    N_FEATURES = 18

    samples_a = _make_samples(N_SAMPLES, n_features=N_FEATURES, seed=42)
    samples_b = _make_samples(N_SAMPLES, n_features=N_FEATURES, seed=137)

    from unittest.mock import patch, MagicMock
    from src.unsupervised.provenance import ProvenanceMetadata

    def _make_provenance(samples):
        return ProvenanceMetadata.from_window(
            samples,
            window_start_ts=samples[0].ts_epoch,
            window_end_ts=samples[-1].ts_epoch,
            fire_reason="test",
        )

    prov_a = _make_provenance(samples_a)
    prov_b = _make_provenance(samples_b)

    # Disable MLflow so training stays local
    with patch("src.unsupervised.window_trainer.mlflow_registry") as mock_mlflow:
        mock_mlflow.init.return_value = None
        mock_mlflow.is_enabled.return_value = False
        mock_mlflow._get_mlflow.return_value = None

        trainer_a = WindowTrainer(val_fraction=0.20, seq_len=20)
        trainer_b = WindowTrainer(val_fraction=0.20, seq_len=20)

        trainer_a.train_window(samples_a, prov_a)
        trainer_b.train_window(samples_b, prov_b)

    hist_a = trainer_a.get_history()
    hist_b = trainer_b.get_history()

    assert len(hist_a) == 1, "trainer_a should have exactly one history entry"
    assert len(hist_b) == 1, "trainer_b should have exactly one history entry"

    stats_a = hist_a[0]["training_stats"]
    stats_b = hist_b[0]["training_stats"]

    assert stats_a["n_features"] == stats_b["n_features"] == N_FEATURES, (
        "Both windows must extract the same number of features"
    )

    # Threshold stability: |delta| / mean < 25%
    threshold_mean = (stats_a["threshold"] + stats_b["threshold"]) / 2.0
    if threshold_mean > 0:
        threshold_rel_delta = abs(stats_a["threshold"] - stats_b["threshold"]) / threshold_mean
        assert threshold_rel_delta < 0.25, (
            f"Reconstruction threshold unstable: "
            f"a={stats_a['threshold']:.6f} b={stats_b['threshold']:.6f} "
            f"relative_delta={threshold_rel_delta:.2%} (limit 25%)"
        )

    # Val recon mean stability: |delta| / mean < 30%
    recon_mean = (stats_a["val_recon_mean"] + stats_b["val_recon_mean"]) / 2.0
    if recon_mean > 0:
        recon_rel_delta = abs(stats_a["val_recon_mean"] - stats_b["val_recon_mean"]) / recon_mean
        assert recon_rel_delta < 0.30, (
            f"Val reconstruction mean unstable: "
            f"a={stats_a['val_recon_mean']:.6f} b={stats_b['val_recon_mean']:.6f} "
            f"relative_delta={recon_rel_delta:.2%} (limit 30%)"
        )
