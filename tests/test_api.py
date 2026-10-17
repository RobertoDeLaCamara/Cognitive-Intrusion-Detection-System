"""API integration tests using httpx + in-memory SQLite."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from unittest.mock import patch
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


# ---------------------------------------------------------------------------
# Date-range filter on GET /api/alerts
# ---------------------------------------------------------------------------

def _now():
    from src.timeutils import utcnow
    return utcnow().replace(microsecond=0)


async def _add_alerts(session, specs):
    """specs: list of (timestamp, src_ip, severity, acknowledged)."""
    for ts, ip, sev, ack in specs:
        session.add(Alert(
            timestamp=ts, src_ip=ip, dst_ip="10.0.0.1",
            severity=sev, ensemble_score=0.5, acknowledged=ack,
        ))
    await session.commit()


async def _seed_three(session):
    from datetime import timedelta
    now = _now()
    times = {"old": now - timedelta(hours=48),
             "mid": now - timedelta(hours=12),
             "new": now - timedelta(hours=1)}
    await _add_alerts(session, [
        (times["old"], "1.1.1.1", SeverityLevel.HIGH, False),
        (times["mid"], "2.2.2.2", SeverityLevel.HIGH, False),
        (times["new"], "3.3.3.3", SeverityLevel.HIGH, False),
    ])
    return now, times


@pytest.mark.asyncio
async def test_list_alerts_date_range(client, test_session):
    from datetime import timedelta, timezone
    now, times = await _seed_three(test_session)
    start = now - timedelta(hours=24)
    end = now - timedelta(minutes=30)

    resp = await client.get("/api/alerts", params={
        "start": start.isoformat(), "end": end.isoformat()})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"2.2.2.2", "3.3.3.3"}

    # Inclusive bound: start exactly at an alert's timestamp
    resp = await client.get("/api/alerts", params={"start": times["mid"].isoformat()})
    assert {a["src_ip"] for a in resp.json()} == {"2.2.2.2", "3.3.3.3"}

    # tz-aware start (+02:00) for the same instant
    aware = (start.replace(tzinfo=timezone.utc)
             .astimezone(timezone(timedelta(hours=2))))
    resp = await client.get("/api/alerts", params={
        "start": aware.isoformat(), "end": end.isoformat()})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"2.2.2.2", "3.3.3.3"}


@pytest.mark.asyncio
async def test_list_alerts_hours(client, test_session):
    await _seed_three(test_session)
    resp = await client.get("/api/alerts", params={"hours": 24})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"2.2.2.2", "3.3.3.3"}

    resp = await client.get("/api/alerts", params={"hours": 0})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_alerts_invalid_datetime(client):
    resp = await client.get("/api/alerts", params={"start": "not-a-date"})
    assert resp.status_code == 422
    resp = await client.get("/api/alerts", params={"end": "2026-13-45T00:00:00"})
    assert resp.status_code == 422
    resp = await client.get("/api/alerts", params={
        "start": "2026-01-02T00:00:00", "end": "2026-01-01T00:00:00"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_alerts_date_range_composes(client, test_session):
    from datetime import timedelta
    now = _now()
    inside = now - timedelta(hours=2)
    outside = now - timedelta(hours=72)
    await _add_alerts(test_session, [
        (inside, "9.9.9.9", SeverityLevel.HIGH, False),      # match
        (inside, "9.9.9.9", SeverityLevel.LOW, False),       # wrong severity
        (inside, "9.9.9.9", SeverityLevel.HIGH, True),       # acknowledged
        (inside, "8.8.8.8", SeverityLevel.HIGH, False),      # wrong ip
        (outside, "9.9.9.9", SeverityLevel.HIGH, False),     # out of range
    ])
    resp = await client.get("/api/alerts", params={
        "start": (now - timedelta(hours=6)).isoformat(),
        "end": now.isoformat(),
        "severity": "high", "acknowledged": "false", "src_ip": "9.9.9.9"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["src_ip"] == "9.9.9.9"
    assert data[0]["severity"] == "high"
    assert data[0]["acknowledged"] is False

    resp = await client.get("/api/alerts", params={"hours": 6, "severity": "low"})
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_list_alerts_end_only_inclusive(client, test_session):
    now, times = await _seed_three(test_session)
    resp = await client.get("/api/alerts", params={"end": times["mid"].isoformat()})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.asyncio
async def test_list_alerts_start_equals_end(client, test_session):
    now, times = await _seed_three(test_session)
    ts = times["mid"].isoformat()
    resp = await client.get("/api/alerts", params={"start": ts, "end": ts})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"2.2.2.2"}


@pytest.mark.asyncio
async def test_list_alerts_range_empty_result(client, test_session):
    from datetime import timedelta
    now, _ = await _seed_three(test_session)
    resp = await client.get("/api/alerts", params={
        "start": (now - timedelta(hours=100)).isoformat(),
        "end": (now - timedelta(hours=60)).isoformat()})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_alerts_tz_aware_end_normalised(client, test_session):
    from datetime import timedelta, timezone
    now, times = await _seed_three(test_session)
    end = (times["mid"].replace(tzinfo=timezone.utc)
           .astimezone(timezone(timedelta(hours=-5))))
    resp = await client.get("/api/alerts", params={"end": end.isoformat()})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.asyncio
async def test_list_alerts_hours_invalid_values(client):
    for bad in ("-1", "abc", "1.5"):
        resp = await client.get("/api/alerts", params={"hours": bad})
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_alerts_hours_composes_with_filters(client, test_session):
    from datetime import timedelta
    now = _now()
    recent = now - timedelta(hours=2)
    old = now - timedelta(hours=50)
    await _add_alerts(test_session, [
        (recent, "5.5.5.5", SeverityLevel.HIGH, False),   # match
        (recent, "5.5.5.5", SeverityLevel.HIGH, True),    # acknowledged
        (recent, "6.6.6.6", SeverityLevel.HIGH, False),   # wrong ip
        (old, "5.5.5.5", SeverityLevel.HIGH, False),      # too old
    ])
    resp = await client.get("/api/alerts", params={
        "hours": 24, "severity": "high", "acknowledged": "false",
        "src_ip": "5.5.5.5"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_list_alerts_hours_and_start_both_apply(client, test_session):
    from datetime import timedelta
    now, times = await _seed_three(test_session)
    # hours=24 admits mid+new; start at T-6h narrows to new only
    resp = await client.get("/api/alerts", params={
        "hours": 24, "start": (now - timedelta(hours=6)).isoformat()})
    assert resp.status_code == 200
    assert {a["src_ip"] for a in resp.json()} == {"3.3.3.3"}


@pytest.mark.asyncio
async def test_list_alerts_date_range_with_pagination(client, test_session):
    from datetime import timedelta
    now, _ = await _seed_three(test_session)
    params = {"start": (now - timedelta(hours=24)).isoformat(), "limit": 1}
    first = await client.get("/api/alerts", params=params)
    second = await client.get("/api/alerts", params={**params, "offset": 1})
    assert [a["src_ip"] for a in first.json()] == ["3.3.3.3"]
    assert [a["src_ip"] for a in second.json()] == ["2.2.2.2"]


MAX_HOURS = 24 * 365 * 10


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/alerts", "/api/alerts/export"])
@pytest.mark.parametrize("hours", [1_000_000_000, MAX_HOURS + 1])
async def test_hours_above_upper_bound_is_422(client, path, hours):
    resp = await client.get(path, params={"hours": hours})
    assert resp.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/alerts", "/api/alerts/export"])
async def test_hours_at_upper_bound_is_ok(client, path):
    resp = await client.get(path, params={"hours": MAX_HOURS})
    assert resp.status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/alerts", "/api/alerts/export"])
async def test_hours_lower_bound_unchanged(client, path):
    assert (await client.get(path, params={"hours": 0})).status_code == 422
    assert (await client.get(path, params={"hours": 1})).status_code == 200


@pytest.mark.asyncio
async def test_hours_max_still_filters_normally(client, test_session):
    await _seed_three(test_session)
    resp = await client.get("/api/alerts", params={"hours": MAX_HOURS})
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    resp = await client.get("/api/alerts/export", params={"hours": MAX_HOURS})
    assert resp.status_code == 200


# ── CSV export: formula-injection hardening (cnds#28) ─────────────────────────

@pytest.mark.parametrize("value, expected", [
    ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
    ("+SUM(1+1)", "'+SUM(1+1)"),
    ("-2+3", "'-2+3"),
    ("@SUM(A1)", "'@SUM(A1)"),
    ("\t=1+1", "'\t=1+1"),
    ("\r=1+1", "'\r=1+1"),
    ("Port Scan", "Port Scan"),
    ("10.0.0.2", "10.0.0.2"),
    ("::1", "::1"),
    ("", ""),
    (None, None),
    (0.75, 0.75),
    (-3, -3),          # negative numbers are numbers, not text: left alone
    (True, True),
])
def test_csv_safe(value, expected):
    from src.api.routers.alerts import _csv_safe
    assert _csv_safe(value) == expected


@pytest.mark.asyncio
async def test_export_csv_neutralises_formulas_in_text_fields(client, test_session):
    import csv
    import io
    from datetime import datetime, timezone
    test_session.add(Alert(
        timestamp=datetime.now(timezone.utc),
        src_ip="10.0.0.9",
        attack_type="=HYPERLINK(\"http://evil.example\",\"x\")",
        triggered_rules=["@rule", "ok"],
        severity=SeverityLevel.HIGH,
    ))
    await test_session.commit()

    resp = await client.get("/api/alerts/export?format=csv")
    assert resp.status_code == 200
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert len(rows) == 1
    assert rows[0]["attack_type"].startswith("'=HYPERLINK(")
    # the join is "@rule;ok": the cell as a whole starts with '@', so it is quoted
    assert rows[0]["triggered_rules"] == "'@rule;ok"
    assert rows[0]["src_ip"] == "10.0.0.9"
