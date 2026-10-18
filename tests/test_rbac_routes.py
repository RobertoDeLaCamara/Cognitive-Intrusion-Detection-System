"""Role matrix for the alerts, incidents and predict routes (cnds#21, #1).

With JWT auth enabled every route needs a token, and the role decides what it may do:

* read routes   -> viewer, analyst, admin
* write routes  -> analyst, admin
* admin routes  -> admin

Without JWT_SECRET the routes stay open (API-key or AUTH_DISABLED deployments).
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from unittest.mock import patch

from src.api.auth import create_token
from src.api.database import get_db
from src.api.models import Base
from tests.test_api import create_test_app

SECRET = "testsecret_32bytes_long_for_hmac"

READ = [
    ("GET", "/api/alerts", None),
    ("GET", "/api/alerts/trends", None),
    ("GET", "/api/alerts/1", None),
    ("GET", "/api/incidents", None),
    ("GET", "/api/stats", None),
    ("GET", "/api/suppression-rules", None),
    ("GET", "/api/adaptive-weights", None),
    ("GET", "/api/dns-log", None),
    ("GET", "/api/engines", None),
]
WRITE = [
    ("PATCH", "/api/alerts/1", {"acknowledged": True}),
    ("POST", "/api/predict", {"src_ip": "10.0.0.1"}),
    ("POST", "/api/incidents", {"title": "t", "severity": "high"}),
    ("PATCH", "/api/incidents/1", {"status": "investigating"}),
    ("POST", "/api/suppression-rules", {"src_ip": "10.1.1.1"}),
    ("GET", "/api/alerts/export", None),
]
ADMIN = [
    ("DELETE", "/api/suppression-rules/1", None),
]
ALL = READ + WRITE + ADMIN


def ids(routes):
    return [f"{m} {p}" for m, p, _ in routes]


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
    # A route may fail for reasons unrelated to auth (no engines, no data): report
    # that as a 500 instead of raising, because only 401/403 matter here.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    await engine.dispose()


def bearer(role):
    with patch("src.api.auth.JWT_SECRET", SECRET):
        return {"Authorization": f"Bearer {create_token('someone', role)}"}


async def call(api, method, path, body, headers=None):
    with patch("src.api.auth.JWT_SECRET", SECRET):
        return await api.request(method, path, json=body, headers=headers or {})


def allowed(resp):
    """Authorised: whatever the route answers, it is not an auth failure."""
    return resp.status_code not in (401, 403)


# --- no / bad token ------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", ALL, ids=ids(ALL))
async def test_no_token_is_401(api, method, path, body):
    resp = await call(api, method, path, body)
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", ALL, ids=ids(ALL))
async def test_garbage_token_is_401(api, method, path, body):
    resp = await call(api, method, path, body, {"Authorization": "Bearer not.a.token"})
    assert resp.status_code == 401, resp.text


# --- viewer: read only ---------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", READ, ids=ids(READ))
async def test_viewer_can_read(api, method, path, body):
    assert allowed(await call(api, method, path, body, bearer("viewer")))


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", WRITE + ADMIN, ids=ids(WRITE + ADMIN))
async def test_viewer_cannot_write(api, method, path, body):
    resp = await call(api, method, path, body, bearer("viewer"))
    assert resp.status_code == 403, resp.text


# --- analyst: read and write, not admin ----------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", READ + WRITE, ids=ids(READ + WRITE))
async def test_analyst_can_read_and_write(api, method, path, body):
    assert allowed(await call(api, method, path, body, bearer("analyst")))


@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", ADMIN, ids=ids(ADMIN))
async def test_analyst_cannot_use_admin_routes(api, method, path, body):
    resp = await call(api, method, path, body, bearer("analyst"))
    assert resp.status_code == 403, resp.text


# --- admin: everything ---------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", ALL, ids=ids(ALL))
async def test_admin_can_do_everything(api, method, path, body):
    assert allowed(await call(api, method, path, body, bearer("admin")))


# --- the two issues called out by name -----------------------------------------

@pytest.mark.asyncio
async def test_patch_alert_needs_a_write_role(api):
    """cnds#1: PATCH /alerts/{id} used to accept any caller."""
    assert (await call(api, "PATCH", "/api/alerts/1", {"acknowledged": True})).status_code == 401
    viewer = await call(api, "PATCH", "/api/alerts/1", {"acknowledged": True}, bearer("viewer"))
    assert viewer.status_code == 403
    analyst = await call(api, "PATCH", "/api/alerts/1", {"acknowledged": True}, bearer("analyst"))
    assert analyst.status_code == 404  # authorised; there is simply no alert 1


@pytest.mark.asyncio
async def test_predict_needs_a_write_role(api):
    """cnds#22 (first step): /predict creates alerts, so a viewer or anonymous caller must not."""
    assert (await call(api, "POST", "/api/predict", {"src_ip": "10.0.0.1"})).status_code == 401
    resp = await call(api, "POST", "/api/predict", {"src_ip": "10.0.0.1"}, bearer("viewer"))
    assert resp.status_code == 403


# --- without JWT nothing changes -----------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("method, path, body", ALL, ids=ids(ALL))
async def test_open_when_jwt_is_not_configured(api, method, path, body):
    """API-key and AUTH_DISABLED deployments are unaffected: no JWT, no role checks."""
    resp = await api.request(method, path, json=body)
    assert allowed(resp), resp.text


@pytest.mark.asyncio
async def test_health_stays_public_with_jwt(api):
    resp = await call(api, "GET", "/health", None)
    assert resp.status_code == 200
