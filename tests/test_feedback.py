"""Analyst tp/fp labels, feedback stats and training export (cnds#7)."""

import csv
import io

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.database import get_db
from src.api.models import Alert, Base, SeverityLevel
from src.features.flow_extractor import FLOW_FEATURE_NAMES
from tests.test_api import create_test_app

N = len(FLOW_FEATURE_NAMES)


@pytest_asyncio.fixture(loop_scope="function")
async def ctx():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with sessions() as session:
            yield session

    app = create_test_app()
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        yield ac, sessions
    app.dependency_overrides.clear()
    await engine.dispose()


async def _alert(sessions, features=None, **kw):
    async with sessions() as s:
        a = Alert(src_ip="10.0.0.1", severity=SeverityLevel.HIGH, ensemble_score=0.9,
                  attack_type=kw.pop("attack_type", "DoS"), flow_features=features, **kw)
        s.add(a)
        await s.commit()
        return a.id


@pytest.mark.asyncio
async def test_patch_accepts_labels_and_rejects_others(ctx):
    api, sessions = ctx
    aid = await _alert(sessions)
    for label in ("tp", "fp", "unknown"):
        r = await api.patch(f"/api/alerts/{aid}", json={"label": label})
        assert r.status_code == 200 and r.json()["label"] == label
    assert (await api.patch(f"/api/alerts/{aid}", json={"label": "maybe"})).status_code == 422


@pytest.mark.asyncio
async def test_stats_count_labels_and_exportable_rows(ctx):
    api, sessions = ctx
    await _alert(sessions, [0.0] * N, label="tp")
    await _alert(sessions, [0.0] * N, label="fp")
    await _alert(sessions, None, label="tp")          # labeled but no features: not exportable
    await _alert(sessions, [0.0] * N, label="unknown")
    await _alert(sessions, [0.0] * N)                 # unlabeled
    body = (await api.get("/api/feedback-stats")).json()
    assert (body["tp_count"], body["fp_count"], body["unknown_count"]) == (2, 1, 1)
    assert body["exportable_rows"] == 2
    assert body["retrain_ready"] is False and body["next_retrain_threshold"] > 3


@pytest.mark.asyncio
async def test_retrain_ready_at_threshold(ctx):
    from unittest.mock import patch
    api, sessions = ctx
    await _alert(sessions, [0.0] * N, label="tp")
    await _alert(sessions, [0.0] * N, label="fp")
    with patch("src.api.routers.feedback.FEEDBACK_RETRAIN_THRESHOLD", 2):
        assert (await api.get("/api/feedback-stats")).json()["retrain_ready"] is True


@pytest.mark.asyncio
async def test_export_csv_matches_the_feature_schema(ctx):
    api, sessions = ctx
    tp = await _alert(sessions, [1.0] * N, label="tp", attack_type="DoS")
    fp = await _alert(sessions, [2.0] * N, label="fp", attack_type="Fuzzers")
    await _alert(sessions, [3.0] * N, label="unknown")
    await _alert(sessions, [4.0] * N)
    await _alert(sessions, [5.0] * 5, label="tp")     # wrong width: skipped
    resp = await api.get("/api/feedback-export")
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0] == [*FLOW_FEATURE_NAMES, "label", "attack_type", "alert_id"]
    data = {int(r[-1]): r for r in rows[1:]}
    assert set(data) == {tp, fp}
    assert data[tp][N] == "1" and data[tp][N + 1] == "DoS"
    assert data[fp][N] == "0" and data[fp][0] == "2.0"


def test_detector_alerts_keep_their_flow_features():
    from unittest.mock import patch
    import src.pipeline as pipeline
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from src.features.flow_extractor import FlowRecord
    from src.ensemble.scorer import EngineScores
    from tests.test_pipeline import _ens_result
    import numpy as np

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    flow = FlowRecord(key=("10.0.0.1", "10.0.0.2", 1234, 80, 6))
    item = (flow, EngineScores(), _ens_result(), "high", [], None, None, np.arange(N, dtype=np.float32))
    with patch.object(pipeline, "_SessionLocal", Session):
        pipeline._write_alert(item)
    with Session() as s:
        row = s.query(Alert).one()
    assert row.flow_features == [float(i) for i in range(N)]


@pytest.mark.asyncio
async def test_adaptive_weights_treat_fp_label_like_the_note(ctx):
    from unittest.mock import patch
    from src.enrichment.adaptive_weights import compute_adaptive_weights
    api, sessions = ctx
    scores = {"supervised": 0.9, "isolation_forest": 0.1, "lstm": 0.0, "rules": 0.0}
    for _ in range(4):
        await _alert(sessions, None, acknowledged=True, label="fp", engine_scores=scores)
    async with sessions() as s:
        with patch("src.enrichment.adaptive_weights.ADAPTIVE_WEIGHTS_ENABLED", True), \
             patch("src.enrichment.adaptive_weights.ADAPTIVE_MIN_SAMPLES", 2):
            w = await compute_adaptive_weights(s)
    assert w["supervised"] < w["rules"]   # the engine that drove the false positives is down-weighted
