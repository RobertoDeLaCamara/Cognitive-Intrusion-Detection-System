"""API integration tests using httpx + in-memory SQLite."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from unittest.mock import patch, AsyncMock
from contextlib import asynccontextmanager

from src.api.models import Base, Alert, SeverityLevel
from src.api.database import get_db


# Create a test app without the lifespan that calls init_db
def create_test_app():
    """Create a fresh FastAPI app for testing."""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from src.api.routers import alerts, predict
    from src.api.routers.websocket import router as ws_router
    from src.api.routers.auth import router as auth_router

    @asynccontextmanager
    async def test_lifespan(app: FastAPI):
        yield

    test_app = FastAPI(lifespan=test_lifespan)
    test_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )
    test_app.include_router(alerts.router)
    test_app.include_router(predict.router)
    test_app.include_router(ws_router)
    test_app.include_router(auth_router)

    # Add health endpoint
    from src.engines.registry import supervised, iforest, lstm

    @test_app.get("/health")
    async def health():
        return {
            "status": "ok",
            "engines": {
                "supervised": supervised.is_available,
                "isolation_forest": iforest.is_available,
                "lstm": lstm.is_available,
                "rules": True,
            },
            "capture_stats": None,
        }

    return test_app


@pytest_asyncio.fixture(loop_scope="function")
async def test_engine():
    """Create in-memory SQLite engine."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="function")
async def test_session(test_engine):
    """Create test database session."""
    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture(loop_scope="function")
async def client(test_engine):
    """Create test client with overridden database."""
    test_app = create_test_app()
    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with async_session() as session:
            yield session

    test_app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    test_app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "engines" in data


@pytest.mark.asyncio
async def test_list_alerts_empty(client):
    resp = await client.get("/api/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_and_list_alerts(client, test_session):
    """Insert alert directly and verify list endpoint."""
    from datetime import datetime, timezone
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        severity=SeverityLevel.HIGH,
        ensemble_score=0.85,
    )
    test_session.add(alert)
    await test_session.commit()

    resp = await client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_get_alert_not_found(client):
    resp = await client.get("/api/alerts/9999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_alert(client, test_session):
    from datetime import datetime, timezone
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.5",
        severity=SeverityLevel.MEDIUM,
    )
    test_session.add(alert)
    await test_session.commit()
    await test_session.refresh(alert)

    resp = await client.patch(f"/api/alerts/{alert.id}", json={"acknowledged": True, "notes": "Test note"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["acknowledged"] is True
    assert data["notes"] == "Test note"


@pytest.mark.asyncio
async def test_stats_endpoint(client, test_session):
    from datetime import datetime, timezone
    for sev in [SeverityLevel.LOW, SeverityLevel.HIGH, SeverityLevel.HIGH]:
        test_session.add(Alert(timestamp=datetime.now(timezone.utc), src_ip="1.2.3.4", severity=sev))
    await test_session.commit()

    resp = await client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_alerts"] == 3
    assert data["by_severity"]["high"] == 2


@pytest.mark.asyncio
async def test_predict_allowlisted_ip(client):
    """Allowlisted IPs should return score=0, is_anomaly=False."""
    with patch("src.api.routers.predict.is_allowlisted", return_value=True):
        resp = await client.post("/api/predict", json={
            "src_ip": "192.168.1.1",
            "host_features": [0.0] * 18,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["ensemble_score"] == 0.0
    assert data["is_anomaly"] is False


@pytest.mark.asyncio
async def test_predict_blocklisted_ip(client):
    """Blocklisted IPs should return score=1, is_anomaly=True."""
    with patch("src.api.routers.predict.is_blocklisted", return_value=True), \
         patch("src.api.routers.predict.is_allowlisted", return_value=False):
        resp = await client.post("/api/predict", json={
            "src_ip": "192.168.1.1",
            "host_features": [0.0] * 18,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["ensemble_score"] == 1.0
    assert data["is_anomaly"] is True
    assert data["attack_type"] == "Blocklisted"


@pytest.mark.asyncio
async def test_incidents_crud(client):
    # Create
    resp = await client.post("/api/incidents", json={
        "title": "Test Incident",
        "description": "Testing",
        "severity": "high",
    })
    assert resp.status_code == 201
    inc = resp.json()
    assert inc["title"] == "Test Incident"

    # List
    resp = await client.get("/api/incidents")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_alert_trends(client, test_session):
    from datetime import datetime, timezone
    test_session.add(Alert(timestamp=datetime.now(timezone.utc), src_ip="1.1.1.1", severity=SeverityLevel.LOW))
    await test_session.commit()

    resp = await client.get("/api/alerts/trends?hours=1&bucket=hour")
    assert resp.status_code == 200
    data = resp.json()
    assert data["bucket"] == "hour"


@pytest.mark.asyncio
async def test_export_alerts_json(client, test_session):
    from datetime import datetime, timezone
    test_session.add(Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.1",
        severity=SeverityLevel.HIGH,
        attack_type="DoS",
    ))
    await test_session.commit()

    resp = await client.get("/api/alerts/export?format=json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")
    assert "attachment" in resp.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_export_alerts_csv(client, test_session):
    from datetime import datetime, timezone
    test_session.add(Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.2",
        severity=SeverityLevel.MEDIUM,
    ))
    await test_session.commit()

    resp = await client.get("/api/alerts/export?format=csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    content = resp.text
    assert "src_ip" in content
    assert "10.0.0.2" in content


@pytest.mark.asyncio
async def test_export_alerts_with_filters(client, test_session):
    from datetime import datetime, timezone
    test_session.add(Alert(timestamp=datetime.now(timezone.utc), src_ip="1.1.1.1", severity=SeverityLevel.LOW))
    test_session.add(Alert(timestamp=datetime.now(timezone.utc), src_ip="2.2.2.2", severity=SeverityLevel.HIGH))
    await test_session.commit()

    resp = await client.get("/api/alerts/export?format=json&severity=high")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_alert_includes_mitre_and_ja3(client, test_session):
    """Alerts with MITRE and JA3 data should serialize correctly."""
    from datetime import datetime, timezone
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.99",
        severity=SeverityLevel.HIGH,
        attack_type="DoS Hulk",
        mitre_techniques=[{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}],
        ja3_hash="abcdef1234567890abcdef1234567890",
        ja3_string="771,49196-49195,0-23,29-23,0",
    )
    test_session.add(alert)
    await test_session.commit()

    resp = await client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["mitre_techniques"][0]["id"] == "T1498"
    assert data[0]["ja3_hash"] == "abcdef1234567890abcdef1234567890"


@pytest.mark.asyncio
async def test_export_json_includes_mitre(client, test_session):
    """JSON export should include mitre_techniques."""
    from datetime import datetime, timezone
    import json as _json
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.88",
        severity=SeverityLevel.MEDIUM,
        mitre_techniques=[{"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"}],
    )
    test_session.add(alert)
    await test_session.commit()

    resp = await client.get("/api/alerts/export?format=json")
    assert resp.status_code == 200
    data = _json.loads(resp.text)
    assert len(data) == 1
    assert data[0]["mitre_techniques"][0]["id"] == "T1046"
