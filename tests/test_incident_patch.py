"""PATCH /api/incidents/{id}: forward-only status machine (cnds#4)."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.database import get_db
from src.api.models import Base
from tests.test_api import create_test_app


@pytest_asyncio.fixture(loop_scope="function")
async def api():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with sessions() as session:
            yield session

    app = create_test_app()
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    await engine.dispose()


async def _new_incident(api):
    r = await api.post("/api/incidents", json={"title": "t", "severity": "high"})
    assert r.status_code == 201
    return r.json()["id"]


@pytest.mark.asyncio
async def test_forward_transitions_succeed(api):
    iid = await _new_incident(api)
    for status in ("investigating", "resolved", "closed"):
        r = await api.patch(f"/api/incidents/{iid}", json={"status": status})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == status


@pytest.mark.asyncio
async def test_backward_transition_is_409(api):
    iid = await _new_incident(api)
    await api.patch(f"/api/incidents/{iid}", json={"status": "resolved"})
    r = await api.patch(f"/api/incidents/{iid}", json={"status": "open"})
    assert r.status_code == 409
    assert (await api.get("/api/incidents")).json()[0]["status"] == "resolved"


@pytest.mark.asyncio
async def test_resolved_at_is_set_once_on_resolve(api):
    iid = await _new_incident(api)
    assert (await api.patch(f"/api/incidents/{iid}", json={"status": "investigating"})).json()["resolved_at"] is None
    first = (await api.patch(f"/api/incidents/{iid}", json={"status": "resolved"})).json()["resolved_at"]
    assert first is not None
    closed = (await api.patch(f"/api/incidents/{iid}", json={"status": "closed"})).json()["resolved_at"]
    assert closed == first


@pytest.mark.asyncio
async def test_same_status_and_notes_only_updates_are_allowed(api):
    iid = await _new_incident(api)
    r = await api.patch(f"/api/incidents/{iid}", json={"status": "open", "notes": "looking", "assigned_to": "ana"})
    assert r.status_code == 200
    assert (r.json()["notes"], r.json()["assigned_to"]) == ("looking", "ana")


@pytest.mark.asyncio
async def test_unknown_incident_is_404_and_bad_status_is_422(api):
    assert (await api.patch("/api/incidents/999", json={"status": "closed"})).status_code == 404
    iid = await _new_incident(api)
    assert (await api.patch(f"/api/incidents/{iid}", json={"status": "bogus"})).status_code == 422
