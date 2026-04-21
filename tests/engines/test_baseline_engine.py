"""Tests for BaselineEngine — dual-model (IsolationForest + LSTM Autoencoder) inference engine.

Covers:
- is_available state transitions
- _load() artifact path construction
- anomaly_score() return contracts (None / float / LSTM disabled when buffer short)
- update() ring-buffer LRU eviction at MAX_TRACKED_IPS
- Thread safety: concurrent scoring and reload
- reload_from_mlflow_baseline() serialisation via _reload_lock
- Ensemble integration (baseline present / absent)

All external I/O is mocked: mlflow_registry, joblib.load, torch.load, MlflowClient.
The stub_torch fixture (session-scoped autouse) mirrors the pattern in
tests/unsupervised/conftest.py so PyTorch is never imported from disk.
"""

import os
import sys
import threading
import time
from collections import deque
from typing import Optional
from unittest.mock import MagicMock, patch, call

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Session-scoped torch stub — must run before any src import that touches torch
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def stub_torch():
    """Insert a minimal fake torch into sys.modules.

    Mirrors the pattern in tests/unsupervised/conftest.py.
    Runs once for the entire test session; safe if torch is already stubbed.
    """
    if "torch" not in sys.modules:
        torch_mock = MagicMock()
        torch_mock.nn = MagicMock()
        torch_mock.nn.Module = object          # LSTMAutoencoder inherits from nn.Module
        torch_mock.optim = MagicMock()
        torch_mock.no_grad = MagicMock(return_value=_NoGradCtx())
        torch_mock.from_numpy = MagicMock(side_effect=lambda x: MagicMock(spec=[], name="tensor"))
        torch_mock.load = MagicMock(return_value={"fake": "state"})
        sys.modules["torch"] = torch_mock
        sys.modules["torch.nn"] = torch_mock.nn
        sys.modules["torch.optim"] = torch_mock.optim
    yield


class _NoGradCtx:
    """Minimal context manager returned by torch.no_grad()."""
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

N_FEATURES = 18
SEQ_LEN = 20  # BASELINE_SEQ_LEN from artifact_schema


def _make_features(n: int = N_FEATURES) -> np.ndarray:
    return np.random.rand(n).astype(np.float32)


def _mock_scaler(n_features: int = N_FEATURES) -> MagicMock:
    scaler = MagicMock()
    scaler.n_features_in_ = n_features
    scaler.transform = MagicMock(
        side_effect=lambda x: np.asarray(x, dtype=np.float32)
    )
    return scaler


def _mock_iforest(decision_value: float = 0.5) -> MagicMock:
    """decision_function: positive = normal, negative = anomaly."""
    iforest = MagicMock()
    iforest.decision_function = MagicMock(return_value=np.array([decision_value]))
    return iforest


def _mock_lstm_model() -> MagicMock:
    """Fake LSTMAutoencoder that returns a zero reconstruction."""
    lstm = MagicMock()
    lstm.eval = MagicMock(return_value=None)
    lstm.load_state_dict = MagicMock(return_value=None)

    # __call__  →  reconstruction tensor identical to input (zero MSE)
    def _forward(x):
        result = MagicMock()
        # (x - result)**2 must produce something that torch.mean().item() handles.
        # Because torch is fully mocked, the arithmetic operators are MagicMocks;
        # we force item() to return 0.0 to represent perfect reconstruction.
        diff = MagicMock()
        diff.__pow__ = MagicMock(return_value=diff)
        mean_mock = MagicMock()
        mean_mock.item = MagicMock(return_value=0.0)
        # Patched at the module level via torch.mean
        return result

    lstm.side_effect = _forward
    return lstm


def _build_loaded_engine(decision_value: float = 0.5, threshold: float = 0.5):
    """Return a BaselineEngine that has been constructed with mocked artifacts
    already swapped in (bypasses the __init__ _load() call and provides a clean
    engine in available state).
    """
    from src.engines.baseline_engine import BaselineEngine

    with patch("src.engines.baseline_engine.mlflow_registry") as mock_reg:
        mock_reg.is_enabled.return_value = False          # suppress __init__ _load
        engine = BaselineEngine()

    # Directly inject mock artifacts to put engine into available state
    engine._scaler = _mock_scaler(N_FEATURES)
    engine._iforest = _mock_iforest(decision_value)
    engine._lstm = _mock_lstm_model()
    engine._threshold = threshold
    engine._n_features = N_FEATURES
    return engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def unavailable_engine():
    """A BaselineEngine whose _load() found nothing — stays unavailable."""
    with patch("src.engines.baseline_engine.mlflow_registry") as mock_reg:
        mock_reg.is_enabled.return_value = False
        from src.engines.baseline_engine import BaselineEngine
        engine = BaselineEngine()
    return engine


@pytest.fixture
def available_engine():
    """A BaselineEngine in available state with mocked artifacts."""
    return _build_loaded_engine()


# ---------------------------------------------------------------------------
# 1. is_available state transitions
# ---------------------------------------------------------------------------

class TestIsAvailable:

    def test_false_when_mlflow_disabled(self, unavailable_engine):
        assert unavailable_engine.is_available is False

    def test_false_when_no_versions_registered(self):
        """Registry query returns empty list — engine must stay unavailable."""
        mock_client = MagicMock()
        mock_client.search_model_versions.return_value = []

        mock_mlflow_mod = MagicMock()
        mock_mlflow_mod.tracking.MlflowClient.return_value = mock_client

        with patch("src.engines.baseline_engine.mlflow_registry") as mock_reg:
            mock_reg.is_enabled.return_value = True
            mock_reg._get_mlflow.return_value = mock_mlflow_mod
            from src.engines.baseline_engine import BaselineEngine
            engine = BaselineEngine()

        assert engine.is_available is False

    def test_true_after_successful_load(self, available_engine):
        assert available_engine.is_available is True

    def test_false_reverts_if_scaler_missing(self, available_engine):
        """If the scaler is removed the property must return False."""
        available_engine._scaler = None
        assert available_engine.is_available is False


# ---------------------------------------------------------------------------
# 2. _load() artifact path construction
# ---------------------------------------------------------------------------

class TestLoadArtifactPaths:

    def test_correct_artifact_paths_inside_tmpdir(self):
        """joblib.load must be called with paths rooted under ARTIFACT_ROOT."""
        from src.unsupervised.artifact_schema import (
            ARTIFACT_ROOT, SCALER_FILE, IFOREST_FILE, LSTM_FILE, THRESHOLD_FILE,
        )

        captured_paths = []

        def _fake_joblib_load(path):
            captured_paths.append(path)
            mock = _mock_scaler() if "scaler" in path else _mock_iforest()
            return mock

        mock_version = MagicMock()
        mock_version.run_id = "abc123"
        mock_version.version = "1"

        mock_client = MagicMock()
        mock_client.search_model_versions.return_value = [mock_version]

        # download_artifacts writes into tmp/<ARTIFACT_ROOT>/
        def _fake_download(run_id, artifact_path, tmp_dir):
            # Create the expected files so open() and torch.load() work
            artifact_dir = os.path.join(tmp_dir, artifact_path)
            os.makedirs(artifact_dir, exist_ok=True)
            # threshold.txt
            with open(os.path.join(artifact_dir, THRESHOLD_FILE), "w") as fh:
                fh.write("0.05\n")
            # joblib stubs handled by _fake_joblib_load; lstm by torch.load mock

        mock_client.download_artifacts.side_effect = _fake_download

        mock_mlflow_mod = MagicMock()
        mock_mlflow_mod.tracking.MlflowClient.return_value = mock_client

        mock_scaler = _mock_scaler(N_FEATURES)

        def _joblib_dispatch(path):
            captured_paths.append(path)
            if SCALER_FILE in path:
                return mock_scaler
            return _mock_iforest()

        with patch("src.engines.baseline_engine.mlflow_registry") as mock_reg, \
             patch("joblib.load", side_effect=_joblib_dispatch), \
             patch("torch.load", return_value={}):
            mock_reg.is_enabled.return_value = True
            mock_reg._get_mlflow.return_value = mock_mlflow_mod

            from src.engines.baseline_engine import BaselineEngine
            engine = BaselineEngine()

        # Verify both joblib paths contain the ARTIFACT_ROOT directory component
        assert len(captured_paths) == 2, f"Expected 2 joblib.load calls, got: {captured_paths}"
        for p in captured_paths:
            assert ARTIFACT_ROOT in p, f"Path {p!r} does not contain ARTIFACT_ROOT={ARTIFACT_ROOT!r}"

        # Verify the specific filenames
        basenames = {os.path.basename(p) for p in captured_paths}
        assert SCALER_FILE in basenames
        assert IFOREST_FILE in basenames


# ---------------------------------------------------------------------------
# 3. anomaly_score() returns None when unavailable; float in [0,1] when available
# ---------------------------------------------------------------------------

class TestAnomalyScoreContract:

    def test_returns_none_when_not_available(self, unavailable_engine):
        result = unavailable_engine.anomaly_score("10.0.0.1", _make_features())
        assert result is None

    def test_returns_none_for_none_features(self, available_engine):
        result = available_engine.anomaly_score("10.0.0.1", None)
        assert result is None

    def test_returns_float_in_unit_interval(self, available_engine):
        """Full buffer (>= seq_len) — both branches active, score in [0, 1].

        Uses patch() instead of direct sys.modules manipulation so the test
        works whether torch is a real install (Docker) or a session-scoped stub.
        """
        ip = "192.168.1.1"
        for _ in range(SEQ_LEN):
            available_engine.update(ip, _make_features())

        fake_tensor = MagicMock()
        fake_tensor.unsqueeze.return_value = fake_tensor

        mean_result = MagicMock()
        mean_result.item.return_value = 0.0

        with patch("torch.from_numpy", return_value=fake_tensor), \
             patch("torch.no_grad", return_value=_NoGradCtx()), \
             patch("torch.mean", return_value=mean_result):
            score = available_engine.anomaly_score(ip, _make_features())

        assert score is not None, "Expected a float, got None"
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_returns_float_when_iforest_anomalous(self):
        """High anomaly from iforest (negative decision) should produce score > 0.5."""
        import torch

        engine = _build_loaded_engine(decision_value=-2.0, threshold=0.05)

        mean_result = MagicMock()
        mean_result.item.return_value = 0.0
        with patch("torch.mean", return_value=mean_result), \
             patch("torch.no_grad", return_value=_NoGradCtx()):
            score = engine.anomaly_score("10.0.0.2", _make_features())

        assert score is not None
        assert score > 0.5, f"Expected anomaly score > 0.5, got {score}"


# ---------------------------------------------------------------------------
# 4. anomaly_score() returns non-None but LSTM contributes 0 when buffer short
# ---------------------------------------------------------------------------

class TestAnomalyScoreLSTMBypass:

    def test_lstm_score_zero_when_buffer_below_seq_len(self):
        """Buffer has fewer than seq_len frames — LSTM branch must not contribute.

        Strategy: give iforest a near-neutral decision_function (0.0) so s_if ≈ 0.5,
        and configure the lstm model's mean to return 999.0 (which would clamp s_lstm
        to 1.0 if the LSTM branch fired).  If the LSTM branch is correctly skipped,
        the score stays near 0.5; if it fires, score would jump to 1.0.

        We use a fresh MagicMock for torch.mean on the stub so the call count
        is clean for this test and we can assert it was never called.
        """
        torch_stub = sys.modules["torch"]

        engine = _build_loaded_engine(decision_value=0.0)  # s_if ≈ 0.5
        ip = "10.0.0.3"

        # Add fewer than seq_len frames — buffer must not reach threshold
        for _ in range(SEQ_LEN - 5):
            engine.update(ip, _make_features())

        # Install a fresh, clean mean mock so call_count starts at 0
        fresh_mean_mock = MagicMock()
        fresh_mean_mock.return_value.item.return_value = 999.0
        original_mean = torch_stub.mean
        torch_stub.mean = fresh_mean_mock

        torch_stub.no_grad.return_value = _NoGradCtx()

        try:
            score = engine.anomaly_score(ip, _make_features())
        finally:
            torch_stub.mean = original_mean  # restore for subsequent tests

        # Score must be a valid float (iforest path must have run)
        assert score is not None
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

        # LSTM branch must not have fired: torch.mean must not have been called
        fresh_mean_mock.assert_not_called()

        # Sanity: score should be well below 1.0 (iforest at decision=0 → s_if ≈ 0.5)
        assert score < 1.0, (
            f"Score {score:.4f} is suspiciously high — LSTM branch may have fired"
        )

    def test_empty_buffer_uses_only_iforest(self):
        """IP has no history at all — score derived solely from iforest."""
        import torch

        engine = _build_loaded_engine(decision_value=-3.0)  # strong anomaly

        mean_result = MagicMock()
        mean_result.item.return_value = 999.0

        with patch("torch.mean", return_value=mean_result), \
             patch("torch.no_grad", return_value=_NoGradCtx()):
            score = engine.anomaly_score("brand-new-ip", _make_features())

        assert score is not None
        assert score > 0.5  # iforest sees anomaly


# ---------------------------------------------------------------------------
# 5. update() ring buffer LRU eviction at MAX_TRACKED_IPS
# ---------------------------------------------------------------------------

class TestRingBufferEviction:

    def test_evicts_victim_at_max_tracked_ips(self):
        """Inserting MAX_TRACKED_IPS+1 unique IPs must evict the IP with the
        shortest buffer at the moment the limit is exceeded.

        Layout before the 6th insertion (limit=5):
          10.0.1.1 → 2 frames
          10.0.2.1 → 4 frames
          10.0.3.1 → 6 frames
          10.0.4.1 → 8 frames
          10.0.5.1 → 1 frame   ← shortest → evicted when 10.0.6.1 arrives
        """
        engine = _build_loaded_engine()
        engine._max_buffers = 5  # small limit for determinism

        # Fill 4 IPs with increasing amounts of history (slot * 2 frames each)
        for slot in range(1, 5):
            ip = f"10.0.{slot}.1"
            for _ in range(slot * 2):   # slot 1 → 2, slot 2 → 4, ... slot 4 → 8
                engine.update(ip, _make_features())

        assert len(engine._buffers) == 4

        # 5th IP gets only 1 frame — it will be the shortest when limit is hit
        engine.update("10.0.5.1", _make_features())   # now at limit (5)
        assert len(engine._buffers) == 5
        assert "10.0.5.1" in engine._buffers

        # 6th IP triggers eviction: 10.0.5.1 (len=1) is the victim
        engine.update("10.0.6.1", _make_features())

        assert len(engine._buffers) == 5, (
            f"Buffer count should stay at 5 after eviction, got {len(engine._buffers)}"
        )
        assert "10.0.5.1" not in engine._buffers, (
            "Expected 10.0.5.1 (shortest buffer, 1 frame) to be evicted"
        )
        assert "10.0.6.1" in engine._buffers, "New IP must be present after eviction"
        # Longer-lived IPs must survive
        for slot in range(1, 5):
            assert f"10.0.{slot}.1" in engine._buffers, (
                f"10.0.{slot}.1 should not have been evicted"
            )

    def test_no_eviction_when_under_limit(self):
        engine = _build_loaded_engine()
        engine._max_buffers = 100

        for i in range(50):
            engine.update(f"10.1.{i}.1", _make_features())

        assert len(engine._buffers) == 50

    def test_existing_ip_update_does_not_trigger_eviction(self):
        """Re-updating an already-tracked IP must not count as a new insertion."""
        engine = _build_loaded_engine()
        engine._max_buffers = 3

        for i in range(1, 4):
            engine.update(f"10.2.{i}.1", _make_features())

        assert len(engine._buffers) == 3
        # Re-update an existing IP many times
        for _ in range(10):
            engine.update("10.2.1.1", _make_features())

        assert len(engine._buffers) == 3  # no eviction


# ---------------------------------------------------------------------------
# 6. Thread safety — concurrent anomaly_score() and reload_from_mlflow_baseline()
# ---------------------------------------------------------------------------

class TestConcurrentScoringAndReload:

    def test_no_exception_under_concurrent_score_and_reload(self):
        """10 threads scoring while reload fires — no exception, no crash."""
        import torch

        engine = _build_loaded_engine()
        ip = "192.168.50.1"
        for _ in range(SEQ_LEN):
            engine.update(ip, _make_features())

        errors = []
        barrier = threading.Barrier(11)  # 10 scorers + 1 reloader

        mean_result = MagicMock()
        mean_result.item.return_value = 0.0

        def _score_worker():
            try:
                barrier.wait(timeout=5)
                for _ in range(20):
                    with patch("torch.mean", return_value=mean_result), \
                         patch("torch.no_grad", return_value=_NoGradCtx()):
                        result = engine.anomaly_score(ip, _make_features())
                    # result can be None (during swap) or float — both valid
                    if result is not None:
                        assert isinstance(result, float)
                        assert 0.0 <= result <= 1.0
            except Exception as exc:
                errors.append(exc)

        def _reload_worker():
            try:
                barrier.wait(timeout=5)
                # Perform a reload that will fail gracefully (mlflow disabled)
                with patch("src.engines.baseline_engine.mlflow_registry") as mr:
                    mr.is_enabled.return_value = False
                    engine.reload_from_mlflow_baseline()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_score_worker) for _ in range(10)]
        threads.append(threading.Thread(target=_reload_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Concurrent scoring/reload raised exceptions: {errors}"


# ---------------------------------------------------------------------------
# 7. reload_from_mlflow_baseline() serialisation — _reload_lock
# ---------------------------------------------------------------------------

class TestReloadSerialisation:

    def test_concurrent_reloads_serialise(self):
        """Two concurrent reload calls must not run _load() simultaneously.

        Verified by making _load() sleep briefly and counting overlapping
        executions — the count must never exceed 1.
        """
        engine = _build_loaded_engine()

        concurrent_count = [0]
        max_concurrent = [0]
        lock = threading.Lock()

        original_load = engine._load

        def _instrumented_load():
            with lock:
                concurrent_count[0] += 1
                if concurrent_count[0] > max_concurrent[0]:
                    max_concurrent[0] = concurrent_count[0]
            time.sleep(0.05)  # hold the slot briefly to expose races
            result = False     # skip real mlflow
            with lock:
                concurrent_count[0] -= 1
            return result

        engine._load = _instrumented_load

        errors = []

        def _do_reload():
            try:
                engine.reload_from_mlflow_baseline()
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_do_reload)
        t2 = threading.Thread(target=_do_reload)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not errors, f"reload raised: {errors}"
        assert max_concurrent[0] == 1, (
            f"Expected at most 1 concurrent _load(), got {max_concurrent[0]} — "
            "_reload_lock is not serialising correctly"
        )

    def test_reload_returns_false_when_mlflow_disabled(self, unavailable_engine):
        with patch("src.engines.baseline_engine.mlflow_registry") as mock_reg:
            mock_reg.is_enabled.return_value = False
            result = unavailable_engine.reload_from_mlflow_baseline()
        assert result is False


# ---------------------------------------------------------------------------
# 8. Ensemble integration — baseline=0.7 present
# ---------------------------------------------------------------------------

class TestEnsembleIntegrationWithBaseline:

    def test_baseline_appears_in_active_engines(self):
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        scores = EngineScores(baseline=0.7)
        result = EnsembleScorer().score(scores)

        assert "baseline" in result.active_engines
        assert result.score > 0.0

    def test_baseline_contributes_to_combined_score(self):
        """baseline=1.0 alone must produce a non-zero combined score."""
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        result = EnsembleScorer().score(EngineScores(baseline=1.0))
        assert result.score == pytest.approx(1.0)
        assert result.is_anomaly is True

    def test_baseline_with_other_engines(self):
        """baseline alongside supervised — both should appear in active_engines."""
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        scores = EngineScores(supervised=0.8, baseline=0.6)
        result = EnsembleScorer().score(scores)

        assert "supervised" in result.active_engines
        assert "baseline" in result.active_engines
        assert 0.0 < result.score <= 1.0


# ---------------------------------------------------------------------------
# 9. Ensemble integration — baseline=None absent
# ---------------------------------------------------------------------------

class TestEnsembleIntegrationWithoutBaseline:

    def test_baseline_absent_from_active_engines(self):
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        scores = EngineScores(supervised=0.5, isolation_forest=0.5)
        result = EnsembleScorer().score(scores)

        assert "baseline" not in result.active_engines

    def test_weight_redistributed_without_baseline(self):
        """With baseline=None the same score as baseline=0 should be obtainable
        through weight redistribution (single active engine captures full weight)."""
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        # Single active engine; its score should dominate
        result_no_baseline = EnsembleScorer().score(EngineScores(rules=0.9))
        assert result_no_baseline.score == pytest.approx(0.9)
        assert "baseline" not in result_no_baseline.active_engines

    def test_baseline_none_does_not_zero_score(self):
        """Passing baseline=None must NOT pull combined score toward 0."""
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        result_with = EnsembleScorer().score(
            EngineScores(supervised=0.8, isolation_forest=0.8, baseline=0.8)
        )
        result_without = EnsembleScorer().score(
            EngineScores(supervised=0.8, isolation_forest=0.8, baseline=None)
        )
        # Both should be high; the without-baseline score should NOT be lower
        # due to a phantom 0.0 weight — it should be >= with-baseline.
        assert result_without.score >= result_with.score - 0.05  # within 5% tolerance
        assert result_without.score > 0.5

    def test_no_engines_available_returns_zero(self):
        """All None → score=0, active_engines empty, no crash."""
        from src.ensemble.scorer import EnsembleScorer, EngineScores

        result = EnsembleScorer().score(EngineScores())
        assert result.score == 0.0
        assert result.active_engines == []
        assert result.is_anomaly is False
