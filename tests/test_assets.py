"""Asset inventory: tracker, classification heuristics, persistence and GET /api/assets (cnds#13)."""

from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.database import get_db
from src.api.models import Alert, Base, HostProfile, SeverityLevel
from src.inventory.assets import AssetTracker, classify, flush, is_lan_address
from src.timeutils import utcnow
from tests.test_api import create_test_app


# ── classification ───────────────────────────────────────────────────────────

def test_too_little_traffic_is_unknown():
    assert classify(3, 2, [80], [443], ["10.0.0.9"]) == "unknown"


def test_server_receives_far_more_than_it_initiates():
    assert classify(5, 100, [22, 80, 443], [53], ["10.0.0.%d" % i for i in range(20)]) == "server"


def test_iot_talks_to_few_peers_on_device_ports_and_is_not_contacted():
    assert classify(200, 2, [], [443, 8883, 123], ["52.1.1.1", "52.1.1.2"]) == "iot"


def test_workstation_initiates_to_many_peers():
    peers = ["93.184.216.%d" % i for i in range(30)]
    assert classify(300, 40, [], [80, 443, 8080, 22], peers) == "workstation"


def test_unusual_outbound_port_is_not_iot():
    assert classify(200, 2, [], [443, 31337], ["52.1.1.1"]) == "unknown"


# ── tracker ──────────────────────────────────────────────────────────────────

def test_only_lan_addresses_are_tracked():
    assert is_lan_address("192.168.1.38") and is_lan_address("10.1.2.3")
    assert not is_lan_address("8.8.8.8") and not is_lan_address("224.0.0.1")
    assert not is_lan_address("127.0.0.1") and not is_lan_address("not-an-ip")


def test_observe_counts_both_ends_and_drain_resets():
    t = AssetTracker()
    t.observe("192.168.1.38", "8.8.8.8", 443)
    t.observe("192.168.1.38", "192.168.1.62", 22)
    d = t.drain()
    assert set(d) == {"192.168.1.38", "192.168.1.62"}        # 8.8.8.8 is not LAN
    assert d["192.168.1.38"].flows_out == 2 and d["192.168.1.62"].flows_in == 1
    assert d["192.168.1.62"].listen_ports == {22}
    assert t.drain() == {}


def test_host_cap_bounds_memory():
    t = AssetTracker(max_hosts=3)
    for i in range(10):
        t.observe(f"10.0.0.{i}", "8.8.8.8", 53)
    assert len(t.drain()) == 3


# ── persistence ──────────────────────────────────────────────────────────────

@pytest.fixture
def sync_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as s:
        yield s


def test_flush_merges_across_restarts(sync_session):
    t = AssetTracker()
    for _ in range(8):
        t.observe("192.168.1.50", "52.1.1.1", 443)
    assert flush(sync_session, t.drain()) == 1
    first = sync_session.query(HostProfile).one()
    first_seen, flows = first.first_seen, first.flows_out

    for _ in range(8):
        t.observe("192.168.1.50", "52.1.1.1", 8883)
    flush(sync_session, t.drain())
    row = sync_session.query(HostProfile).one()
    assert row.first_seen == first_seen and row.flows_out == flows + 8
    assert row.out_ports == [443, 8883] and row.classification == "iot"


# ── API ──────────────────────────────────────────────────────────────────────

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


async def _seed(sessions):
    now = utcnow()
    async with sessions() as s:
        s.add_all([
            HostProfile(ip="192.168.1.10", first_seen=now - timedelta(days=30), last_seen=now,
                        flows_out=5, flows_in=500, classification="server"),
            HostProfile(ip="192.168.1.20", first_seen=now - timedelta(hours=1), last_seen=now - timedelta(minutes=5),
                        flows_out=50, flows_in=1, classification="iot"),
        ])
        s.add_all([
            Alert(src_ip="192.168.1.20", severity=SeverityLevel.HIGH),
            Alert(src_ip="192.168.1.20", severity=SeverityLevel.CRITICAL),
            Alert(src_ip="192.168.1.10", severity=SeverityLevel.LOW),
        ])
        await s.commit()


@pytest.mark.asyncio
async def test_assets_listing_with_risk_and_new_flag(ctx):
    api, sessions = ctx
    await _seed(sessions)
    body = (await api.get("/api/assets")).json()
    assert body["total"] == 2
    by_ip = {a["ip"]: a for a in body["assets"]}
    iot, server = by_ip["192.168.1.20"], by_ip["192.168.1.10"]
    assert iot["is_new"] is True and server["is_new"] is False
    assert (iot["alert_count"], iot["risk_score"]) == (2, 22)       # high 7 + critical 15
    assert (server["alert_count"], server["risk_score"]) == (1, 1)
    assert [a["ip"] for a in body["assets"]][0] == "192.168.1.10"   # newest last_seen first


@pytest.mark.asyncio
async def test_assets_filter_and_pagination(ctx):
    api, sessions = ctx
    await _seed(sessions)
    only = (await api.get("/api/assets", params={"classification": "iot"})).json()
    assert only["total"] == 1 and only["assets"][0]["ip"] == "192.168.1.20"
    page = (await api.get("/api/assets", params={"limit": 1, "offset": 1})).json()
    assert page["total"] == 2 and len(page["assets"]) == 1
    assert (await api.get("/api/assets", params={"classification": "toaster"})).status_code == 422


@pytest.mark.asyncio
async def test_alerts_carry_src_asset_type(ctx):
    api, sessions = ctx
    await _seed(sessions)
    alerts = (await api.get("/api/alerts")).json()
    kinds = {a["src_ip"]: a["src_asset_type"] for a in alerts}
    assert kinds == {"192.168.1.20": "iot", "192.168.1.10": "server"}
    one = (await api.get(f"/api/alerts/{alerts[0]['id']}")).json()
    assert one["src_asset_type"] in ("iot", "server")


@pytest.mark.asyncio
async def test_alert_from_unknown_host_has_null_asset_type(ctx):
    api, sessions = ctx
    async with sessions() as s:
        s.add(Alert(src_ip="203.0.113.9", severity=SeverityLevel.LOW))
        await s.commit()
    assert (await api.get("/api/alerts")).json()[0]["src_asset_type"] is None
