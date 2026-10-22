"""logwatch alerts are stored like any other alert, with source="logwatch" and no Guardian path."""

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.models import Alert, Base, SeverityLevel
from src.config import GUARDIAN_ALERT_SOURCES
from src.logwatch import persist
from src.logwatch.events import LogAlert


@pytest_asyncio.fixture(loop_scope="function")
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)() as s:
        yield s
    await engine.dispose()


def log_alert(**kw):
    base = dict(rule="gitea_signup_attempts", service="gitea", description="Persistent Gitea sign-up attempts",
                severity="medium", key="203.0.113.7", ip="203.0.113.7", count=49, window_secs=86400,
                first_ts=1792600000.0, last_ts=1792681982.0,
                mitre=[{"id": "T1136", "name": "Create Account", "tactic": "Persistence"}],
                samples=["line one", "line two"])
    base.update(kw)
    return LogAlert(**base)


@pytest.fixture(autouse=True)
def sent(monkeypatch):
    calls = []

    async def fake_notify(data):
        calls.append(data)

    monkeypatch.setattr(persist, "notify_alert", fake_notify)
    return calls


@pytest.mark.asyncio
async def test_persisted_alert_has_logwatch_source_and_enrichment(session, sent):
    saved = await persist.persist_alert(session, log_alert())
    row = (await session.execute(select(Alert).where(Alert.id == saved.id))).scalar_one()
    assert row.source == "logwatch" and row.src_ip == "203.0.113.7"
    assert row.severity == SeverityLevel.MEDIUM and row.ensemble_score == 0.60
    assert row.attack_type == "Persistent Gitea sign-up attempts" and row.triggered_rules == ["gitea_signup_attempts"]
    assert row.mitre_techniques[0]["id"] == "T1136"
    assert row.payload_matches[0].startswith("49 event(s) in 86400s") and row.payload_matches[1:] == ["line one", "line two"]
    assert row.timestamp.year == 2026 and row.timestamp.tzinfo is None       # naive UTC like every column
    assert row.acknowledged is False
    assert sent and sent[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_notify_failure_does_not_lose_the_alert(session, monkeypatch):
    async def boom(data):
        raise RuntimeError("webhook down")

    monkeypatch.setattr(persist, "notify_alert", boom)
    saved = await persist.persist_alert(session, log_alert(severity="critical"))
    assert saved.id is not None and saved.severity == SeverityLevel.CRITICAL


@pytest.mark.asyncio
async def test_notify_can_be_disabled(session, sent):
    await persist.persist_alert(session, log_alert(), notify=False)
    assert sent == []


def test_guardian_never_acts_on_logwatch_by_default():
    assert persist.SOURCE not in GUARDIAN_ALERT_SOURCES
