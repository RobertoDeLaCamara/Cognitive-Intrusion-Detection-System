"""BaselineEngine retries its model load in the background while it has no model."""
import threading
import time

import numpy as np

from src.engines import baseline_engine as be


def _engine(monkeypatch, retry_secs, results):
    """Engine whose _load() returns the next value of *results* and counts calls."""
    calls = []
    done = threading.Event()

    def fake_load(self):
        calls.append(time.time())
        ok = results.pop(0) if results else False
        if ok:
            with self._swap_lock:
                self._scaler, self._iforest, self._lstm = object(), object(), object()
        done.set()
        return ok

    monkeypatch.setattr(be.BaselineEngine, "_load", fake_load)
    eng = be.BaselineEngine(retry_secs=retry_secs)
    done.clear()
    return eng, calls, done


def _wait_idle(eng):
    assert eng._reload_lock.acquire(timeout=5)  # the retry thread has finished
    eng._reload_lock.release()


VEC = np.zeros(18, dtype=np.float32)


def test_no_retry_before_the_interval(monkeypatch):
    eng, calls, _ = _engine(monkeypatch, 300, [False])
    assert eng.anomaly_score("10.0.0.1", VEC) is None
    _wait_idle(eng)
    assert len(calls) == 1  # only the startup attempt


def test_retry_loads_the_model_after_the_interval(monkeypatch):
    eng, calls, done = _engine(monkeypatch, 300, [False, True])
    eng._last_load_attempt -= 301
    assert eng.anomaly_score("10.0.0.1", VEC) is None  # never blocks on the load
    assert done.wait(5)
    _wait_idle(eng)
    assert len(calls) == 2 and eng.is_available


def test_failed_retry_waits_another_interval(monkeypatch):
    eng, calls, done = _engine(monkeypatch, 300, [False, False])
    eng._last_load_attempt -= 301
    eng.anomaly_score("10.0.0.1", VEC)
    assert done.wait(5)
    _wait_idle(eng)
    for _ in range(50):
        eng.anomaly_score("10.0.0.1", VEC)
    _wait_idle(eng)
    assert len(calls) == 2 and not eng.is_available


def test_zero_disables_the_retry(monkeypatch):
    eng, calls, _ = _engine(monkeypatch, 0, [False])
    eng._last_load_attempt -= 10_000
    eng.anomaly_score("10.0.0.1", VEC)
    _wait_idle(eng)
    assert len(calls) == 1


def test_retry_skipped_while_a_reload_is_running(monkeypatch):
    eng, calls, _ = _engine(monkeypatch, 300, [False])
    eng._last_load_attempt -= 301
    with eng._reload_lock:  # e.g. the post-training hot-reload
        eng.anomaly_score("10.0.0.1", VEC)
    assert len(calls) == 1
