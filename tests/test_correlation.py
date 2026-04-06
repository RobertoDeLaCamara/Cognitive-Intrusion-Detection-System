"""Unit tests for src/enrichment/correlation.py.

Covers:
- Below threshold → returns None, no incident created
- At threshold → new incident created, all related alerts linked
- Existing open incident → alert linked to it, no new incident
- Resolved/closed incident → ignored, new incident created
- Alerts outside CORRELATION_WINDOW_SECS are not counted
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.models import Base, Alert, Incident, SeverityLevel, IncidentStatus
from src.enrichment.correlation import correlate_alert
from src.config import CORRELATION_THRESHOLD, CORRELATION_WINDOW_SECS


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(loop_scope="function")
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session
    await engine.dispose()


# ── Helpers ────────────────────────────────────────────────────────────────

def _alert(src_ip="10.0.0.1", severity=SeverityLevel.HIGH, minutes_ago=0):
    return Alert(
        src_ip=src_ip,
        attack_type="DoS Hulk",
        severity=severity,
        ensemble_score=0.9,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )


async def _seed_alerts(db, count, src_ip="10.0.0.1", minutes_ago=0):
    """Add `count` past alerts (not the current one) and flush to assign IDs."""
    alerts = [_alert(src_ip=src_ip, minutes_ago=minutes_ago) for _ in range(count)]
    for a in alerts:
        db.add(a)
    await db.flush()
    return alerts


# ── Tests ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_below_threshold_returns_none(db):
    """Fewer prior alerts than CORRELATION_THRESHOLD-1 → no correlation."""
    # Need CORRELATION_THRESHOLD - 2 prior alerts so that total (including current) < threshold
    prior_count = CORRELATION_THRESHOLD - 2
    await _seed_alerts(db, prior_count, src_ip="10.0.1.1")

    current = _alert(src_ip="10.0.1.1")
    db.add(current)
    await db.flush()

    result = await correlate_alert(current, db)
    assert result is None
    assert current.incident_id is None


@pytest.mark.asyncio
async def test_at_threshold_creates_new_incident(db):
    """Exactly CORRELATION_THRESHOLD total alerts → auto-incident created."""
    prior_count = CORRELATION_THRESHOLD - 1
    prior = await _seed_alerts(db, prior_count, src_ip="10.0.2.1")

    current = _alert(src_ip="10.0.2.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)

    assert incident_id is not None
    assert current.incident_id == incident_id


@pytest.mark.asyncio
async def test_new_incident_links_all_prior_alerts(db):
    """All prior alerts get linked to the newly created incident."""
    prior_count = CORRELATION_THRESHOLD - 1
    prior = await _seed_alerts(db, prior_count, src_ip="10.0.3.1")

    current = _alert(src_ip="10.0.3.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)

    for a in prior:
        assert a.incident_id == incident_id


@pytest.mark.asyncio
async def test_links_to_existing_open_incident(db):
    """Open incident for the same IP → alert linked to it, no new incident."""
    # Create an existing open incident for this IP
    incident = Incident(
        title="Correlated attack from 10.0.4.1",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.OPEN,
    )
    db.add(incident)
    await db.flush()

    prior = await _seed_alerts(db, CORRELATION_THRESHOLD - 1, src_ip="10.0.4.1")

    current = _alert(src_ip="10.0.4.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)

    assert incident_id == incident.id
    assert current.incident_id == incident.id


@pytest.mark.asyncio
async def test_links_to_existing_investigating_incident(db):
    """INVESTIGATING incident for the same IP → alert linked to it."""
    incident = Incident(
        title="Correlated attack from 10.0.5.1",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.INVESTIGATING,
    )
    db.add(incident)
    await db.flush()

    await _seed_alerts(db, CORRELATION_THRESHOLD - 1, src_ip="10.0.5.1")

    current = _alert(src_ip="10.0.5.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)
    assert incident_id == incident.id


@pytest.mark.asyncio
async def test_resolved_incident_ignored_new_one_created(db):
    """RESOLVED incident is not reused — a new one is created instead."""
    resolved = Incident(
        title="Correlated attack from 10.0.6.1",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.RESOLVED,
    )
    db.add(resolved)
    await db.flush()

    await _seed_alerts(db, CORRELATION_THRESHOLD - 1, src_ip="10.0.6.1")

    current = _alert(src_ip="10.0.6.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)

    assert incident_id is not None
    assert incident_id != resolved.id


@pytest.mark.asyncio
async def test_closed_incident_ignored_new_one_created(db):
    """CLOSED incident is not reused."""
    closed = Incident(
        title="Correlated attack from 10.0.7.1",
        severity=SeverityLevel.HIGH,
        status=IncidentStatus.CLOSED,
    )
    db.add(closed)
    await db.flush()

    await _seed_alerts(db, CORRELATION_THRESHOLD - 1, src_ip="10.0.7.1")

    current = _alert(src_ip="10.0.7.1")
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)
    assert incident_id is not None
    assert incident_id != closed.id


@pytest.mark.asyncio
async def test_old_alerts_outside_window_not_counted(db):
    """Alerts outside CORRELATION_WINDOW_SECS are excluded from the count."""
    minutes_outside = int(CORRELATION_WINDOW_SECS / 60) + 10
    await _seed_alerts(db, CORRELATION_THRESHOLD - 1,
                       src_ip="10.0.8.1", minutes_ago=minutes_outside)

    current = _alert(src_ip="10.0.8.1")
    db.add(current)
    await db.flush()

    result = await correlate_alert(current, db)
    assert result is None


@pytest.mark.asyncio
async def test_alerts_from_different_ips_not_correlated(db):
    """Alerts from a different src_ip do not contribute to this IP's count."""
    await _seed_alerts(db, CORRELATION_THRESHOLD + 5, src_ip="10.10.10.10")

    current = _alert(src_ip="10.0.9.1")
    db.add(current)
    await db.flush()

    result = await correlate_alert(current, db)
    assert result is None


@pytest.mark.asyncio
async def test_new_incident_title_contains_src_ip(db):
    """Auto-created incident title references the attacker IP."""
    src_ip = "192.168.1.100"
    await _seed_alerts(db, CORRELATION_THRESHOLD - 1, src_ip=src_ip)

    current = _alert(src_ip=src_ip)
    db.add(current)
    await db.flush()

    incident_id = await correlate_alert(current, db)

    from sqlalchemy import select
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one()
    assert src_ip in incident.title
