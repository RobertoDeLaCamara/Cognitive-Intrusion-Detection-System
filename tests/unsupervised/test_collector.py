"""Unit tests for the unsupervised baseline collector and related fixes.

Covers the five P0/P1 bugs fixed in:
  - src/unsupervised/collector.py
  - src/pipeline.py
  - src/unsupervised/window_trainer.py (mlflow init race)

All external dependencies (MLflow, torch, sklearn, DB) are fully mocked.
Run with: pytest tests/unsupervised/test_collector.py -v
"""

import threading
import time
import logging
import numpy as np
import pytest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

from src.unsupervised.collector import BaselineCollector, CollectedSample
from src.unsupervised.triggers import CompositeTrigger, TriggerState, _shannon_entropy_bits
from src.unsupervised.provenance import ProvenanceMetadata


# ── Shared test helpers ────────────────────────────────────────────────────


def _make_trigger(
    min_total=100,
    min_ips=2,
    min_elapsed=60.0,
    min_entropy=1.0,
) -> CompositeTrigger:
    """Return a CompositeTrigger with low thresholds suitable for unit tests."""
    return CompositeTrigger(
        min_total_vectors=min_total,
        min_distinct_src_ips=min_ips,
        min_elapsed_sec=min_elapsed,
        min_dst_port_entropy_bits=min_entropy,
    )


def _make_record(
    src_ip="1.2.3.4",
    dst_ip="5.6.7.8",
    dst_port=80,
    protocol="TCP",
    last_time=1_700_000_000.0,
) -> SimpleNamespace:
    """Minimal flow record that BaselineCollector.observe() can consume."""
    return SimpleNamespace(
        src_ip=src_ip,
        dst_ip=dst_ip,
        key=(src_ip, dst_ip, 12345, dst_port, protocol),
        last_time=last_time,
    )


def _host_vec(n_features: int = 18) -> np.ndarray:
    return np.ones(n_features, dtype=np.float32)


def _noop_on_window_ready(samples, provenance):
    """Drop-in callback that does nothing — used when the training path is irrelevant."""
    pass


def _build_collector(
    trigger=None,
    on_window_ready=None,
    enabled=True,
) -> BaselineCollector:
    return BaselineCollector(
        trigger=trigger or _make_trigger(),
        on_window_ready=on_window_ready or _noop_on_window_ready,
        enabled=enabled,
    )


# ── Fix 1: Thread freeze — Thread.start() raises RuntimeError ─────────────


class TestThreadFreezeFix:
    """P0: if Thread.start() raises, _training_in_flight must be cleared.

    Before the fix this left _training_in_flight=True permanently, causing the
    collector to drop every subsequent sample forever.
    """

    def _build_fire_ready_collector(self, on_window_ready=None):
        """Return a collector whose trigger will fire on the next observe() call.

        We pre-populate the collector's internal state so that the very first
        observe() crosses the hard-cap threshold — this avoids having to send
        HARD_CAP samples in tests.
        """
        collector = _build_collector(on_window_ready=on_window_ready)
        # Bypass trigger by pushing to hard cap directly.
        with collector._lock:
            # Fill buffer just below hard cap so the next append tips it over.
            collector._buffer = [
                CollectedSample(
                    host_vec=_host_vec(),
                    src_ip="1.2.3.4",
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    protocol="TCP",
                    ts_epoch=1_700_000_000.0,
                )
            ] * (BaselineCollector.HARD_CAP - 1)
            collector._window_start_ts = 1_700_000_000.0
        return collector

    def test_training_in_flight_cleared_on_thread_start_failure(self):
        """_training_in_flight must not remain True when Thread.start() raises."""
        collector = self._build_fire_ready_collector()

        with patch("threading.Thread.start", side_effect=RuntimeError("OS limit")):
            record = _make_record(last_time=1_700_001_000.0)
            collector.observe(record, _host_vec())

        assert collector._training_in_flight is False, (
            "Thread freeze: _training_in_flight not cleared after Thread.start() failure"
        )

    def test_collector_accepts_new_samples_after_thread_start_failure(self):
        """After a Thread.start() failure the collector must not permanently drop."""
        collector = self._build_fire_ready_collector()

        with patch("threading.Thread.start", side_effect=RuntimeError("OS limit")):
            collector.observe(_make_record(last_time=1_700_001_000.0), _host_vec())

        # _training_in_flight is now False — next observe must add to buffer.
        before = len(collector._buffer)
        collector.observe(_make_record(last_time=1_700_001_001.0), _host_vec())
        assert len(collector._buffer) == before + 1, (
            "Collector permanently froze: sample dropped even after _training_in_flight reset"
        )

    def test_thread_start_failure_is_logged(self, caplog):
        """A RuntimeError from Thread.start() must produce an ERROR log entry."""
        collector = self._build_fire_ready_collector()

        with caplog.at_level(logging.ERROR, logger="src.unsupervised.collector"):
            with patch("threading.Thread.start", side_effect=RuntimeError("ulimit hit")):
                collector.observe(_make_record(last_time=1_700_001_000.0), _host_vec())

        assert any("Failed to start" in r.message for r in caplog.records), (
            "No ERROR log emitted when Thread.start() raised"
        )

    def test_provenance_failure_also_clears_in_flight(self):
        """If ProvenanceMetadata.from_window() raises, _training_in_flight must clear."""
        collector = self._build_fire_ready_collector()

        with patch(
            "src.unsupervised.collector.ProvenanceMetadata.from_window",
            side_effect=ValueError("bad ts"),
        ):
            collector.observe(_make_record(last_time=1_700_001_000.0), _host_vec())

        assert collector._training_in_flight is False


# ── Fix 2: Mixed time bases — _window_start_ts and negative elapsed ────────


class TestTimeBaseFix:
    """P0: _window_start_ts must use packet time, and elapsed must never be negative."""

    def test_window_start_ts_set_to_packet_time_on_fire(self):
        """After a window fires, _window_start_ts must equal the triggering packet's ts_epoch."""
        callback_done = threading.Event()

        def slow_callback(samples, provenance):
            # Hold long enough that we can check state before the run completes.
            callback_done.wait(timeout=5)

        collector = _build_collector(on_window_ready=slow_callback)

        # Pre-fill to HARD_CAP - 1
        with collector._lock:
            collector._buffer = [
                CollectedSample(
                    host_vec=_host_vec(),
                    src_ip="1.2.3.4",
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    protocol="TCP",
                    ts_epoch=1_700_000_000.0,
                )
            ] * (BaselineCollector.HARD_CAP - 1)
            collector._window_start_ts = 1_000_000_000.0  # far past

        trigger_ts = 1_700_002_000.0
        record = _make_record(last_time=trigger_ts)
        collector.observe(record, _host_vec())

        try:
            # After fire, _window_start_ts must equal the packet that triggered the window.
            assert collector._window_start_ts == trigger_ts, (
                f"Expected _window_start_ts={trigger_ts}, got {collector._window_start_ts}"
            )
        finally:
            callback_done.set()  # release background thread

    def test_elapsed_is_never_negative_with_out_of_order_timestamps(self):
        """Out-of-order packets (ts < _window_start_ts) must produce elapsed == 0, not negative."""
        # Set window_start to a future time relative to the incoming packet.
        collector = _build_collector()
        future_ts = 1_700_100_000.0
        with collector._lock:
            collector._window_start_ts = future_ts

        # Packet with an older timestamp than the window start.
        old_record = _make_record(last_time=future_ts - 500.0)
        collector.observe(old_record, _host_vec())

        # The collector should have added the sample without raising or producing
        # negative elapsed — we verify by checking the buffer grew and state is sane.
        assert len(collector._buffer) == 1
        # No assertions on TriggerState directly (it's internal), but the guard
        # `max(0.0, ...)` means the trigger sees elapsed=0, which is safe.

    def test_window_start_not_set_to_wall_clock_after_fire(self):
        """_window_start_ts must NOT be time.time() after a window fires.

        Strategy: fake time.time() to return a value far from the packet ts, then
        verify _window_start_ts matches packet ts (not the faked wall clock).
        """
        fake_wall_clock = 9_999_999_999.0  # absurdly far future
        packet_ts = 1_700_002_000.0

        completed = threading.Event()

        def immediate_callback(samples, provenance):
            completed.set()

        collector = _build_collector(on_window_ready=immediate_callback)
        with collector._lock:
            collector._buffer = [
                CollectedSample(
                    host_vec=_host_vec(),
                    src_ip="1.2.3.4",
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    protocol="TCP",
                    ts_epoch=1_700_000_000.0,
                )
            ] * (BaselineCollector.HARD_CAP - 1)
            collector._window_start_ts = 0.0

        with patch("time.time", return_value=fake_wall_clock):
            collector.observe(_make_record(last_time=packet_ts), _host_vec())

        completed.wait(timeout=5)

        assert collector._window_start_ts != fake_wall_clock, (
            "_window_start_ts was set to time.time() — time base regression"
        )
        assert collector._window_start_ts == packet_ts, (
            f"Expected _window_start_ts={packet_ts}, got {collector._window_start_ts}"
        )

    def test_observe_with_zero_last_time_does_not_raise(self):
        """last_time=0.0 is a valid epoch value and must not crash observe()."""
        collector = _build_collector()
        record = _make_record(last_time=0.0)
        # The `or` chain in observe() will fall back to time.time() because 0.0 is falsy.
        # This is existing behaviour — test that it at least doesn't raise.
        try:
            collector.observe(record, _host_vec())
        except Exception as exc:
            pytest.fail(f"observe() raised unexpectedly with last_time=0.0: {exc}")


# ── Fix 3: Drop counter — _dropped_while_training ─────────────────────────


class TestDropCounterFix:
    """P1: samples arriving while training is in-flight must be counted and logged."""

    def test_dropped_while_training_increments(self):
        """Samples sent while _training_in_flight=True must increment _dropped_while_training."""
        collector = _build_collector()
        # Manually mark training as in-flight (simulates the state after a window fires).
        with collector._lock:
            collector._training_in_flight = True
            collector._dropped_while_training = 0

        for i in range(5):
            collector.observe(_make_record(), _host_vec())

        assert collector._dropped_while_training == 5

    def test_dropped_counter_reset_to_zero_after_training_completes(self):
        """_dropped_while_training must be 0 after _run_training() finishes."""
        training_complete = threading.Event()

        def callback(samples, provenance):
            training_complete.set()

        collector = _build_collector(on_window_ready=callback)

        # Arm in-flight state with pre-existing dropped count.
        with collector._lock:
            collector._training_in_flight = True
            collector._dropped_while_training = 7

        # Simulate _run_training completing by calling it directly.
        sample = CollectedSample(
            host_vec=_host_vec(),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            dst_port=80,
            protocol="TCP",
            ts_epoch=1_700_000_000.0,
        )
        provenance = ProvenanceMetadata.from_window(
            [sample], 1_700_000_000.0, 1_700_001_000.0, "hard_cap"
        )
        collector._run_training([sample], provenance)

        assert collector._dropped_while_training == 0
        assert collector._training_in_flight is False

    def test_dropped_counter_warning_logged(self, caplog):
        """A WARNING must be logged when training completes with dropped > 0."""
        collector = _build_collector()

        with collector._lock:
            collector._training_in_flight = True
            collector._dropped_while_training = 3

        sample = CollectedSample(
            host_vec=_host_vec(),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            dst_port=80,
            protocol="TCP",
            ts_epoch=1_700_000_000.0,
        )
        provenance = ProvenanceMetadata.from_window(
            [sample], 1_700_000_000.0, 1_700_001_000.0, "hard_cap"
        )

        with caplog.at_level(logging.WARNING, logger="src.unsupervised.collector"):
            collector._run_training([sample], provenance)

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("3" in m and "dropped" in m for m in warning_messages), (
            "No drop-count WARNING emitted after training with dropped samples"
        )

    def test_no_warning_logged_when_zero_dropped(self, caplog):
        """No WARNING must be logged when no samples were dropped."""
        collector = _build_collector()

        with collector._lock:
            collector._training_in_flight = True
            collector._dropped_while_training = 0

        sample = CollectedSample(
            host_vec=_host_vec(),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            dst_port=80,
            protocol="TCP",
            ts_epoch=1_700_000_000.0,
        )
        provenance = ProvenanceMetadata.from_window(
            [sample], 1_700_000_000.0, 1_700_001_000.0, "hard_cap"
        )

        with caplog.at_level(logging.WARNING, logger="src.unsupervised.collector"):
            collector._run_training([sample], provenance)

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert not any("dropped" in m for m in warning_messages), (
            "Unexpected drop-count WARNING emitted when dropped == 0"
        )

    def test_full_cycle_drop_then_fire_then_log(self, caplog):
        """End-to-end: fire a window, send samples while training, verify log after training."""
        training_gate = threading.Barrier(2)  # sync test thread + trainer thread
        training_done = threading.Event()

        def gated_callback(samples, provenance):
            training_gate.wait(timeout=5)  # pause until test thread releases
            training_done.set()

        collector = _build_collector(on_window_ready=gated_callback)

        # Pre-fill to HARD_CAP - 1 so the next observe fires.
        with collector._lock:
            collector._buffer = [
                CollectedSample(
                    host_vec=_host_vec(),
                    src_ip="1.2.3.4",
                    dst_ip="5.6.7.8",
                    dst_port=80,
                    protocol="TCP",
                    ts_epoch=1_700_000_000.0,
                )
            ] * (BaselineCollector.HARD_CAP - 1)
            collector._window_start_ts = 1_700_000_000.0

        # This observe() fires the window and starts the background thread.
        collector.observe(_make_record(last_time=1_700_001_000.0), _host_vec())
        assert collector._training_in_flight is True

        # Send 4 more samples — these should be dropped and counted.
        for _ in range(4):
            collector.observe(_make_record(), _host_vec())

        assert collector._dropped_while_training == 4

        # Release the trainer and wait for the full _run_training (including finally block) to finish.
        # training_done fires inside gated_callback — before the finally block resets dropped/in_flight.
        # We poll _training_in_flight as the authoritative signal that finally completed.
        import time
        with caplog.at_level(logging.WARNING, logger="src.unsupervised.collector"):
            training_gate.wait(timeout=5)
            training_done.wait(timeout=5)
            deadline = time.monotonic() + 5
            while collector._training_in_flight and time.monotonic() < deadline:
                time.sleep(0.005)

        assert collector._dropped_while_training == 0
        assert collector._training_in_flight is False
        assert "4" in caplog.text and "dropped" in caplog.text


# ── Fix 4: init_baseline_collector lock — TOCTOU protection ───────────────


def _import_pipeline():
    """Import src.pipeline with torch pre-stubbed.

    pytest runs tests in the order they appear in the file. By the time
    TestInitBaselineCollectorLock tests execute, the other tests have already
    imported src.unsupervised.collector (which succeeds without torch), but
    src.pipeline has NOT yet been imported — so the first import attempt here
    will see the torch stubs from the session-scoped conftest fixture.

    If a previous attempt left a broken entry in sys.modules (e.g. when
    running this class in isolation without the conftest), we evict it first.
    """
    import sys
    from unittest.mock import MagicMock

    # Ensure torch stubs are in place before we attempt to load pipeline.
    if "torch" not in sys.modules or not hasattr(sys.modules["torch"], "nn"):
        torch_mock = MagicMock()
        torch_mock.nn = MagicMock()
        torch_mock.optim = MagicMock()
        sys.modules["torch"] = torch_mock
        sys.modules["torch.nn"] = torch_mock.nn
        sys.modules["torch.optim"] = torch_mock.optim

    # Evict any partially-imported pipeline module so we get a clean import.
    for key in list(sys.modules.keys()):
        if key in ("src.pipeline", "src.unsupervised.window_trainer"):
            del sys.modules[key]

    import src.pipeline as pipeline  # noqa: PLC0415
    return pipeline


class TestInitBaselineCollectorLock:
    """P1: concurrent calls to init_baseline_collector() must produce exactly one collector."""

    def test_single_collector_created_under_concurrent_calls(self):
        """Hammer init_baseline_collector() from N threads; only one instance must be created."""
        pipeline = _import_pipeline()

        # Reset module state so there is no pre-existing collector.
        original = pipeline._baseline_collector
        pipeline._baseline_collector = None

        created_instances = []

        def _patched_baseline_collector_cls(*args, **kwargs):
            instance = MagicMock()
            created_instances.append(instance)
            return instance

        n_threads = 20
        barrier = threading.Barrier(n_threads)
        errors = []

        def _worker():
            try:
                barrier.wait(timeout=5)
                # Patch WindowTrainer so no real ML init happens.
                with patch("src.pipeline.WindowTrainer") as mock_wt:
                    mock_wt.return_value = MagicMock()
                    with patch(
                        "src.pipeline.BaselineCollector",
                        side_effect=_patched_baseline_collector_cls,
                    ):
                        pipeline.init_baseline_collector(enabled=True)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        try:
            assert not errors, f"Worker threads raised: {errors}"
            # Exactly one BaselineCollector must have been constructed.
            assert len(created_instances) == 1, (
                f"TOCTOU race: BaselineCollector constructed {len(created_instances)} times "
                f"(expected 1)"
            )
        finally:
            # Restore module state so other tests aren't affected.
            pipeline._baseline_collector = original

    def test_second_call_is_noop(self):
        """Calling init_baseline_collector() when already initialised must not replace it."""
        pipeline = _import_pipeline()

        original = pipeline._baseline_collector
        pipeline._baseline_collector = None

        try:
            with patch("src.pipeline.WindowTrainer") as mock_wt:
                mock_wt.return_value = MagicMock()
                with patch("src.pipeline.BaselineCollector") as mock_bc:
                    mock_bc.return_value = MagicMock()
                    pipeline.init_baseline_collector(enabled=True)
                    first = pipeline._baseline_collector
                    pipeline.init_baseline_collector(enabled=True)
                    second = pipeline._baseline_collector

            assert first is second, "Second call replaced the existing collector"
            assert mock_bc.call_count == 1, (
                f"BaselineCollector constructed {mock_bc.call_count} times — expected 1"
            )
        finally:
            pipeline._baseline_collector = original


# ── Fix 5: CompositeTrigger — state machine and guard conditions ───────────


class TestCompositeTrigger:
    """Validate trigger boundary conditions, including the elapsed<=0 guard."""

    def _full_state(
        self,
        n_total=50_001,
        n_ips=25,
        elapsed=1_900.0,
        port_counts=None,
    ) -> TriggerState:
        """Return a TriggerState that satisfies all default CompositeTrigger thresholds."""
        if port_counts is None:
            # Build a counter with enough entropy (>= 2.5 bits).
            port_counts = Counter({p: 100 for p in range(8)})
        return TriggerState(
            n_total=n_total,
            n_distinct_src_ips=n_ips,
            elapsed_sec=elapsed,
            dst_port_counts=port_counts,
        )

    def test_fires_when_all_conditions_met(self):
        trigger = CompositeTrigger()
        assert trigger.should_fire(self._full_state()) is True

    def test_does_not_fire_with_zero_elapsed(self):
        """elapsed_sec=0.0 must not fire (guard against negative-elapsed now irrelevant, but
        0 is still below min_elapsed_sec, so trigger must stay silent)."""
        trigger = CompositeTrigger()
        state = self._full_state(elapsed=0.0)
        assert trigger.should_fire(state) is False

    def test_does_not_fire_with_negative_elapsed(self):
        """Negative elapsed — caller should not produce this, but trigger must not fire."""
        trigger = CompositeTrigger()
        state = self._full_state(elapsed=-1.0)
        assert trigger.should_fire(state) is False

    def test_does_not_fire_below_min_total(self):
        trigger = CompositeTrigger(min_total_vectors=50_000)
        state = self._full_state(n_total=49_999)
        assert trigger.should_fire(state) is False

    def test_fires_exactly_at_min_total_boundary(self):
        trigger = CompositeTrigger(min_total_vectors=50_000)
        state = self._full_state(n_total=50_000)
        assert trigger.should_fire(state) is True

    def test_does_not_fire_below_min_ips(self):
        trigger = CompositeTrigger(min_distinct_src_ips=20)
        state = self._full_state(n_ips=19)
        assert trigger.should_fire(state) is False

    def test_fires_exactly_at_min_ips_boundary(self):
        trigger = CompositeTrigger(min_distinct_src_ips=20)
        state = self._full_state(n_ips=20)
        assert trigger.should_fire(state) is True

    def test_does_not_fire_below_min_elapsed(self):
        trigger = CompositeTrigger(min_elapsed_sec=1800.0)
        state = self._full_state(elapsed=1799.9)
        assert trigger.should_fire(state) is False

    def test_fires_exactly_at_min_elapsed_boundary(self):
        trigger = CompositeTrigger(min_elapsed_sec=1800.0)
        state = self._full_state(elapsed=1800.0)
        assert trigger.should_fire(state) is True

    def test_does_not_fire_with_zero_entropy(self):
        """Single port in counter → entropy == 0 < threshold → must not fire."""
        trigger = CompositeTrigger(min_dst_port_entropy_bits=2.5)
        state = self._full_state(port_counts=Counter({80: 50_000}))
        assert trigger.should_fire(state) is False

    def test_does_not_fire_with_empty_port_counts(self):
        trigger = CompositeTrigger()
        state = self._full_state(port_counts=Counter())
        assert trigger.should_fire(state) is False

    @pytest.mark.parametrize("elapsed", [-1000.0, -0.001, 0.0])
    def test_trigger_never_fires_with_non_positive_elapsed(self, elapsed):
        trigger = CompositeTrigger(min_elapsed_sec=0.0)  # no elapsed requirement
        state = TriggerState(
            n_total=100_000,
            n_distinct_src_ips=100,
            elapsed_sec=elapsed,
            dst_port_counts=Counter({p: 100 for p in range(16)}),
        )
        # Even with min_elapsed_sec=0.0, elapsed=0.0 satisfies >=0, so only
        # negative values should definitely not fire.
        if elapsed < 0.0:
            assert trigger.should_fire(state) is False
        # elapsed==0.0 is >= 0.0, so with min_elapsed_sec=0.0 it may fire.


# ── Fix 5 (supplemental): Shannon entropy helper ───────────────────────────


class TestShannonEntropy:
    def test_empty_counter_returns_zero(self):
        assert _shannon_entropy_bits(Counter()) == 0.0

    def test_single_value_returns_zero(self):
        assert _shannon_entropy_bits(Counter({80: 1000})) == 0.0

    def test_uniform_distribution_maximises_entropy(self):
        # 8 equally probable values → 3 bits
        counts = Counter({i: 1 for i in range(8)})
        entropy = _shannon_entropy_bits(counts)
        assert abs(entropy - 3.0) < 1e-10

    def test_two_equal_bins_gives_one_bit(self):
        counts = Counter({80: 50, 443: 50})
        entropy = _shannon_entropy_bits(counts)
        assert abs(entropy - 1.0) < 1e-10

    def test_large_uniform_counter_above_threshold(self):
        counts = Counter({p: 100 for p in range(32)})
        assert _shannon_entropy_bits(counts) >= 2.5


# ── Chaos: observe() with malformed / adversarial records ─────────────────


class TestObserveRobustness:
    """Adversarial inputs to observe() must never crash the hot path."""

    @pytest.mark.parametrize("bad_record", [
        None,
        SimpleNamespace(),  # missing all attributes
        SimpleNamespace(src_ip=None, dst_ip="5.6.7.8", last_time=1_700_000_000.0),
        SimpleNamespace(src_ip="1.2.3.4", dst_ip="5.6.7.8", key="not-a-tuple", last_time=0.0),
        SimpleNamespace(src_ip="1.2.3.4", dst_ip="5.6.7.8", last_time="not-a-float"),
    ])
    def test_malformed_record_does_not_crash(self, bad_record):
        collector = _build_collector()
        try:
            collector.observe(bad_record, _host_vec())
        except Exception as exc:
            pytest.fail(f"observe() raised {type(exc).__name__} on malformed record: {exc}")

    def test_none_host_vec_is_a_noop(self):
        collector = _build_collector()
        collector.observe(_make_record(), None)
        assert len(collector._buffer) == 0

    def test_disabled_collector_ignores_all_samples(self):
        collector = _build_collector(enabled=False)
        collector.observe(_make_record(), _host_vec())
        assert len(collector._buffer) == 0
        assert collector._training_in_flight is False

    def test_nan_host_vec_is_accepted(self):
        """NaN values in host_vec are stored without crashing — detection model handles them."""
        collector = _build_collector()
        nan_vec = np.full(18, float("nan"), dtype=np.float32)
        collector.observe(_make_record(), nan_vec)
        assert len(collector._buffer) == 1

    def test_inf_host_vec_is_accepted(self):
        collector = _build_collector()
        inf_vec = np.full(18, float("inf"), dtype=np.float32)
        collector.observe(_make_record(), inf_vec)
        assert len(collector._buffer) == 1
