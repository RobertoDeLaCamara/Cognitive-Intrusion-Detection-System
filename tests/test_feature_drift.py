"""Input-feature drift monitor and GET /api/drift-status (cnds#6)."""

import numpy as np
import pytest

from src.monitoring.feature_drift import FeatureDriftMonitor

NAMES = [f"f{i}" for i in range(10)]


def _monitor(**kw):
    kw.setdefault("window_flows", 400)
    kw.setdefault("min_flows", 100)
    m = FeatureDriftMonitor(NAMES, **kw)
    m.set_baseline(np.zeros(10), np.ones(10))
    return m


def _feed(m, n, shift_cols=(), shift=0.0, seed=0):
    rng = np.random.default_rng(seed)
    for _ in range(n):
        v = rng.normal(0.0, 1.0, 10)
        for c in shift_cols:
            v[c] += shift
        m.observe(v)


def test_matching_distribution_is_nominal():
    m = _monitor()
    _feed(m, 300)
    s = m.status()
    assert s["status"] == "ok" and s["verdict"] == "nominal"
    assert s["drifted_features"] == 0
    assert len(s["features"]) == 10


def test_shifted_features_are_flagged_per_feature():
    m = _monitor()
    _feed(m, 300, shift_cols=(2, 5, 7), shift=3.0)
    s = m.status()
    assert {f["name"] for f in s["features"] if f["drifted"]} == {"f2", "f5", "f7"}
    assert s["drifted_fraction"] == pytest.approx(0.3)
    assert s["verdict"] == "critical"          # 30% >= 25%


def test_warning_between_the_two_fractions():
    m = _monitor()
    _feed(m, 300, shift_cols=(1,), shift=3.0)  # 1 of 10 = 10%
    assert m.status()["verdict"] == "warning"


def test_warming_up_below_min_flows():
    m = _monitor(min_flows=100)
    _feed(m, 50)
    assert m.status()["status"] == "warming_up"


def test_no_baseline_when_loader_returns_none():
    m = FeatureDriftMonitor(NAMES, baseline_loader=lambda: None)
    m.observe(np.zeros(10))
    assert m.status()["status"] == "no_baseline"


def test_baseline_is_loaded_lazily_from_the_loader():
    m = FeatureDriftMonitor(NAMES, window_flows=50, min_flows=10,
                            baseline_loader=lambda: (np.zeros(10), np.ones(10)))
    _feed(m, 20)
    assert m.status()["status"] == "ok"


def test_notifies_once_per_worsening_when_a_window_closes():
    seen = []
    m = _monitor(window_flows=200, on_verdict_worse=seen.append)
    _feed(m, 200)                                         # nominal window: no notice
    assert seen == []
    _feed(m, 200, shift_cols=(0, 1, 2), shift=3.0)         # critical window
    assert [r["verdict"] for r in seen] == ["critical"]
    _feed(m, 200, shift_cols=(0, 1, 2), shift=3.0, seed=1)  # still critical: no repeat
    assert len(seen) == 1


def test_window_resets_after_closing():
    m = _monitor(window_flows=100, min_flows=50)
    _feed(m, 100, shift_cols=(0, 1, 2), shift=3.0)         # closes as critical
    _feed(m, 60, seed=2)                                   # new window, matching data
    assert m.status()["verdict"] == "nominal"


def test_nan_and_wrong_size_vectors_are_tolerated():
    m = _monitor()
    m.observe(np.full(10, np.nan))
    m.observe(np.zeros(3))                                 # wrong length: ignored
    assert m.status()["status"] == "warming_up"


def test_zero_training_std_does_not_divide_by_zero():
    m = FeatureDriftMonitor(NAMES, window_flows=50, min_flows=10)
    m.set_baseline(np.zeros(10), np.zeros(10))
    _feed(m, 20)
    assert m.status()["status"] == "ok"


def test_baseline_shape_is_validated():
    with pytest.raises(ValueError):
        FeatureDriftMonitor(NAMES).set_baseline(np.zeros(3), np.ones(3))


@pytest.mark.asyncio
async def test_endpoint_reports_the_pipeline_monitor():
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport
    from unittest.mock import patch
    from src.api.routers.drift import router
    from src import pipeline

    m = _monitor()
    _feed(m, 300)
    app = FastAPI()
    app.include_router(router)
    with patch.object(pipeline, "feature_drift_monitor", m):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            body = (await c.get("/api/drift-status")).json()
    assert body["status"] == "ok" and body["verdict"] == "nominal"


def test_ft_engine_exposes_scaler_stats_only_when_loaded(tmp_path):
    from sklearn.preprocessing import StandardScaler
    from src.engines.ft_transformer_engine import FTTransformerEngine

    eng = FTTransformerEngine(model_path=str(tmp_path / "none.pt"), scaler_path=str(tmp_path / "none.pkl"))
    assert eng.scaler_stats() is None
    eng._scaler = StandardScaler().fit(np.random.default_rng(0).normal(5, 2, (100, 4)))
    mean, std = eng.scaler_stats()
    assert mean.shape == (4,) and std.shape == (4,)
