"""Integration tests for POST /api/predict — the API-mode detection flow.

Covers:
- Benign score → no alert persisted
- Anomaly score → alert persisted, alert_id returned
- Dedup within window → second call returns alert_id=None
- Suppression rule fires → alert rolled back
- Payload-only request (no flow_features)
- GeoIP and MITRE enrichment in response
- Supervised engine called when available
"""

import pytest
import pytest_asyncio
import numpy as np
from contextlib import asynccontextmanager, ExitStack
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from unittest.mock import patch, MagicMock, AsyncMock

from src.api.models import Base, Alert, SeverityLevel
from src.api.database import get_db
from src.ensemble.scorer import EnsembleResult, EngineScores


# ── Helpers ────────────────────────────────────────────────────────────────

def _ens_result(score=0.9, is_anomaly=True, active_engines=None):
    return EnsembleResult(
        score=score,
        is_anomaly=is_anomaly,
        engine_scores=EngineScores(),
        active_engines=active_engines or ["rules"],
        calibrated_score=score,
    )


def create_test_app():
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from src.api.routers import alerts, predict
    from src.api.routers.websocket import router as ws_router
    from src.api.routers.auth import router as auth_router

    @asynccontextmanager
    async def test_lifespan(app):
        yield

    app = FastAPI(lifespan=test_lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )
    app.include_router(alerts.router)
    app.include_router(predict.router)
    app.include_router(ws_router)
    app.include_router(auth_router)
    return app


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(loop_scope="function")
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="function")
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(loop_scope="function")
async def client(db_engine):
    app = create_test_app()
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_predict_state():
    """Clear module-level dedup cache between tests; restore a fresh lock after each test."""
    import asyncio
    import src.api.routers.predict as pred_mod
    pred_mod._api_dedup.clear()
    yield
    pred_mod._api_dedup.clear()
    pred_mod._api_dedup_lock = asyncio.Lock()


# ── Common mock context for no-anomaly runs ────────────────────────────────

def _benign_patches():
    """Return a dict of patches that produce a benign (no-alert) predict response."""
    mock_rules = MagicMock()
    mock_rules.evaluate.return_value = (0.1, [])
    mock_ensemble = MagicMock()
    mock_ensemble.score.return_value = _ens_result(score=0.1, is_anomaly=False)
    return {
        "src.api.routers.predict._supervised": MagicMock(is_available=False),
        "src.api.routers.predict._iforest":    MagicMock(is_available=False),
        "src.api.routers.predict._lstm":       MagicMock(is_available=False),
        "src.api.routers.predict._rules":      mock_rules,
        "src.api.routers.predict._ensemble":   mock_ensemble,
        "src.api.routers.predict.geoip.lookup": lambda ip: None,
        "src.api.routers.predict.apply_decay": lambda ip, s: s,
    }


def _anomaly_patches(rule_result=(0.9, ["icmp_flood"]), score=0.9):
    """Return a dict of patches for a high-score anomaly run."""
    mock_rules = MagicMock()
    mock_rules.evaluate.return_value = rule_result
    mock_ensemble = MagicMock()
    mock_ensemble.score.return_value = _ens_result(score=score, is_anomaly=True)
    return {
        "src.api.routers.predict._supervised": MagicMock(is_available=False),
        "src.api.routers.predict._iforest":    MagicMock(is_available=False),
        "src.api.routers.predict._lstm":       MagicMock(is_available=False),
        "src.api.routers.predict._rules":      mock_rules,
        "src.api.routers.predict._ensemble":   mock_ensemble,
        "src.api.routers.predict.geoip.lookup": lambda ip: None,
        "src.api.routers.predict.apply_decay": lambda ip, s: s,
        "src.api.routers.predict.is_suppressed":   AsyncMock(return_value=False),
        "src.api.routers.predict.correlate_alert": AsyncMock(return_value=None),
        "src.api.routers.predict.broadcast_alert": AsyncMock(),
        "src.api.routers.predict.notify_alert":    AsyncMock(),
        "src.api.routers.predict.inc_alert":       MagicMock(),
    }


# ── Tests ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_predict_benign_returns_no_alert_id(client):
    """Engines return low score → is_anomaly=False, alert_id=None."""
    patches = _benign_patches()
    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "192.168.1.50",
            "flow_features": [0.0] * 76,
        })

    assert resp.status_code == 200
    data = resp.json()
    assert data["is_anomaly"] is False
    assert data["alert_id"] is None
    assert data["ensemble_score"] == pytest.approx(0.1, abs=1e-3)


@pytest.mark.asyncio
async def test_predict_anomaly_persists_alert(client, db_session):
    """Rules engine fires → alert persisted, alert_id returned, triggered_rules present."""
    patches = _anomaly_patches(rule_result=(0.9, ["icmp_flood"]))
    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "10.0.0.99",
            "flow_features": [0.0] * 76,
        })

    assert resp.status_code == 200
    data = resp.json()
    assert data["is_anomaly"] is True
    assert data["alert_id"] is not None
    assert "icmp_flood" in data["engine_scores"]["triggered_rules"]


@pytest.mark.asyncio
async def test_predict_dedup_second_call_returns_no_alert_id(client):
    """Same (src_ip, attack_type) within dedup window → second call has alert_id=None."""
    patches = _anomaly_patches(rule_result=(0.9, ["syn_scan"]))
    payload = {"src_ip": "10.1.1.1", "flow_features": [0.0] * 76}

    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        r1 = await client.post("/api/predict", json=payload)
        r2 = await client.post("/api/predict", json=payload)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["alert_id"] is not None
    assert r2.json()["alert_id"] is None


@pytest.mark.asyncio
async def test_predict_suppressed_alert_not_persisted(client):
    """Suppression rule fires → alert rolled back, response has alert_id=None."""
    patches = _anomaly_patches()
    patches["src.api.routers.predict.is_suppressed"] = AsyncMock(return_value=True)

    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "10.5.5.5",
            "flow_features": [0.0] * 76,
        })

    assert resp.status_code == 200
    assert resp.json()["alert_id"] is None


@pytest.mark.asyncio
async def test_predict_payload_only_uses_payload_branch(client):
    """payload_matches without flow_features → rules score set to 1.0 (payload branch)."""
    mock_ensemble = MagicMock()
    mock_ensemble.score.return_value = _ens_result(score=0.1, is_anomaly=False)

    with patch("src.api.routers.predict._supervised", MagicMock(is_available=False)), \
         patch("src.api.routers.predict._iforest",    MagicMock(is_available=False)), \
         patch("src.api.routers.predict._lstm",       MagicMock(is_available=False)), \
         patch("src.api.routers.predict._ensemble",   mock_ensemble), \
         patch("src.api.routers.predict.geoip.lookup", return_value=None), \
         patch("src.api.routers.predict.apply_decay", return_value=0.1):

        resp = await client.post("/api/predict", json={
            "src_ip": "10.6.6.6",
            "payload_matches": ["sqli", "xss"],
        })

    assert resp.status_code == 200
    data = resp.json()
    # Payload-only branch sets rules to 1.0 regardless of ensemble decision
    assert data["engine_scores"]["rules"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_predict_geoip_in_response(client):
    """GeoIP data returned by geoip.lookup propagates to the response."""
    geo = {"country": "US", "city": "Ashburn", "latitude": 39.05, "longitude": -77.49}
    patches = _anomaly_patches()
    patches["src.api.routers.predict.geoip.lookup"] = lambda ip: geo

    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "1.2.3.4",
            "flow_features": [0.0] * 76,
        })

    assert resp.json()["src_geo"] == geo


@pytest.mark.asyncio
async def test_predict_mitre_techniques_in_response(client):
    """MITRE techniques are included in the response when rules fire."""
    patches = _anomaly_patches(rule_result=(0.9, ["icmp_flood"]))
    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "5.5.5.5",
            "flow_features": [0.0] * 76,
        })

    data = resp.json()
    assert isinstance(data["mitre_techniques"], list)


@pytest.mark.asyncio
async def test_predict_supervised_engine_used_when_available(client):
    """When supervised is available and predicts an attack, score propagates correctly."""
    mock_sup = MagicMock()
    mock_sup.is_available = True
    mock_sup.predict.return_value = ("DoS Hulk", 0.95)

    mock_rules = MagicMock()
    mock_rules.evaluate.return_value = (0.0, [])

    mock_ensemble = MagicMock()
    mock_ensemble.score.return_value = _ens_result(score=0.95, is_anomaly=True,
                                                    active_engines=["supervised"])

    with patch("src.api.routers.predict._supervised", mock_sup), \
         patch("src.api.routers.predict._iforest",    MagicMock(is_available=False)), \
         patch("src.api.routers.predict._lstm",       MagicMock(is_available=False)), \
         patch("src.api.routers.predict._rules",      mock_rules), \
         patch("src.api.routers.predict._ensemble",   mock_ensemble), \
         patch("src.api.routers.predict.geoip.lookup", return_value=None), \
         patch("src.api.routers.predict.apply_decay", return_value=0.95), \
         patch("src.api.routers.predict.is_suppressed",   AsyncMock(return_value=False)), \
         patch("src.api.routers.predict.correlate_alert", AsyncMock(return_value=None)), \
         patch("src.api.routers.predict.broadcast_alert", AsyncMock()), \
         patch("src.api.routers.predict.notify_alert",    AsyncMock()), \
         patch("src.api.routers.predict.inc_alert",       MagicMock()):

        resp = await client.post("/api/predict", json={
            "src_ip": "10.9.9.9",
            "flow_features": [0.0] * 76,
        })

    assert resp.status_code == 200
    data = resp.json()
    assert data["attack_type"] == "DoS Hulk"
    assert data["engine_scores"]["supervised"] == pytest.approx(0.95, abs=1e-3)
    mock_sup.predict.assert_called_once()


@pytest.mark.asyncio
async def test_predict_response_shape(client):
    """Response schema contains all expected top-level fields."""
    patches = _benign_patches()
    with ExitStack() as stack:
        for target, value in patches.items():
            stack.enter_context(patch(target, value))
        resp = await client.post("/api/predict", json={
            "src_ip": "192.168.1.1",
            "flow_features": [0.0] * 76,
        })

    data = resp.json()
    expected_keys = {
        "src_ip", "ensemble_score", "is_anomaly", "severity",
        "attack_type", "engine_scores", "active_engines", "alert_id",
    }
    assert expected_keys.issubset(data.keys())
