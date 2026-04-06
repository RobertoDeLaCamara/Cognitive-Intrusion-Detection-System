"""Unit tests for src/enrichment/suppression.py.

Covers:
- invalidate_cache: resets _cache_ts to 0
- _refresh_cache: loads active rules, excludes expired, respects TTL
- is_suppressed: matches by src_ip, dst_ip, attack_type, min_severity, combos
- cleanup_expired: deletes expired rules, returns rowcount, invalidates cache
"""

import time
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

import src.enrichment.suppression as suppression_mod
from src.api.models import Base, Alert, SuppressionRule, SeverityLevel


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


@pytest.fixture(autouse=True)
def reset_cache():
    suppression_mod._cache = []
    suppression_mod._cache_ts = 0.0
    yield


# ── Builder helpers ────────────────────────────────────────────────────────

def _alert(src_ip="1.2.3.4", dst_ip="10.0.0.1",
           attack_type="DoS Hulk", severity=SeverityLevel.HIGH):
    return Alert(
        src_ip=src_ip, dst_ip=dst_ip,
        attack_type=attack_type, severity=severity,
        ensemble_score=0.9,
        timestamp=datetime.now(timezone.utc),
    )


def _rule(src_ip=None, dst_ip=None, attack_type=None, min_severity=None,
          expires_in=3600, reason="test"):
    """Create an in-memory SuppressionRule (not yet added to DB)."""
    return SuppressionRule(
        src_ip=src_ip, dst_ip=dst_ip,
        attack_type=attack_type, min_severity=min_severity,
        reason=reason,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )


# ── invalidate_cache ───────────────────────────────────────────────────────

def test_invalidate_cache_resets_timestamp():
    suppression_mod._cache_ts = 999999.0
    suppression_mod.invalidate_cache()
    assert suppression_mod._cache_ts == 0.0


def test_invalidate_cache_idempotent():
    suppression_mod.invalidate_cache()
    suppression_mod.invalidate_cache()
    assert suppression_mod._cache_ts == 0.0


# ── _refresh_cache ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_refresh_cache_loads_active_rule(db):
    db.add(_rule(src_ip="1.2.3.4"))
    await db.commit()

    await suppression_mod._refresh_cache(db)
    assert len(suppression_mod._cache) == 1
    assert suppression_mod._cache[0].src_ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_refresh_cache_excludes_expired_rule(db):
    db.add(_rule(src_ip="5.6.7.8", expires_in=-10))
    await db.commit()

    await suppression_mod._refresh_cache(db)
    assert suppression_mod._cache == []


@pytest.mark.asyncio
async def test_refresh_cache_updates_timestamp(db):
    before = time.time()
    await suppression_mod._refresh_cache(db)
    assert suppression_mod._cache_ts >= before


@pytest.mark.asyncio
async def test_refresh_cache_respects_ttl(db):
    """Within TTL window, cache is not refreshed from DB even if data changed."""
    rule = _rule(src_ip="9.9.9.9")
    db.add(rule)
    await db.commit()

    # First call: loads rule into cache
    await suppression_mod._refresh_cache(db)
    assert len(suppression_mod._cache) == 1

    # Delete rule from DB — within TTL, cache should not be refreshed
    await db.delete(rule)
    await db.commit()
    await suppression_mod._refresh_cache(db)
    assert len(suppression_mod._cache) == 1  # still stale cached value


@pytest.mark.asyncio
async def test_refresh_cache_loads_multiple_rules(db):
    for i in range(3):
        db.add(_rule(src_ip=f"10.0.0.{i}"))
    await db.commit()

    await suppression_mod._refresh_cache(db)
    assert len(suppression_mod._cache) == 3


# ── is_suppressed ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_not_suppressed_when_no_rules(db):
    alert = _alert()
    assert await suppression_mod.is_suppressed(alert, db) is False


@pytest.mark.asyncio
async def test_suppressed_by_src_ip(db):
    db.add(_rule(src_ip="1.2.3.4"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(src_ip="1.2.3.4"), db) is True


@pytest.mark.asyncio
async def test_not_suppressed_wrong_src_ip(db):
    db.add(_rule(src_ip="9.9.9.9"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(src_ip="1.2.3.4"), db) is False


@pytest.mark.asyncio
async def test_suppressed_by_dst_ip(db):
    db.add(_rule(dst_ip="10.0.0.1"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(dst_ip="10.0.0.1"), db) is True


@pytest.mark.asyncio
async def test_not_suppressed_wrong_dst_ip(db):
    db.add(_rule(dst_ip="172.16.0.1"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(dst_ip="10.0.0.1"), db) is False


@pytest.mark.asyncio
async def test_suppressed_by_attack_type(db):
    db.add(_rule(attack_type="DoS Hulk"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(attack_type="DoS Hulk"), db) is True


@pytest.mark.asyncio
async def test_not_suppressed_wrong_attack_type(db):
    db.add(_rule(attack_type="PortScan"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(attack_type="DoS Hulk"), db) is False


@pytest.mark.asyncio
async def test_suppressed_by_severity_at_threshold(db):
    """Rule with min_severity=medium suppresses alerts at medium and below."""
    db.add(_rule(min_severity="medium"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(severity=SeverityLevel.MEDIUM), db) is True


@pytest.mark.asyncio
async def test_suppressed_by_severity_below_threshold(db):
    """Rule with min_severity=medium also suppresses low severity."""
    db.add(_rule(min_severity="medium"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(severity=SeverityLevel.LOW), db) is True


@pytest.mark.asyncio
async def test_not_suppressed_severity_above_rule(db):
    """Alert severity HIGH is above min_severity=medium → NOT suppressed."""
    db.add(_rule(min_severity="medium"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(severity=SeverityLevel.HIGH), db) is False


@pytest.mark.asyncio
async def test_not_suppressed_critical_above_medium_rule(db):
    db.add(_rule(min_severity="medium"))
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(severity=SeverityLevel.CRITICAL), db) is False


@pytest.mark.asyncio
async def test_suppressed_by_combined_src_and_attack(db):
    """Both src_ip AND attack_type must match when both fields are set."""
    db.add(_rule(src_ip="1.2.3.4", attack_type="DoS Hulk"))
    await db.commit()

    # Both match → suppressed
    suppression_mod.invalidate_cache()
    assert await suppression_mod.is_suppressed(
        _alert(src_ip="1.2.3.4", attack_type="DoS Hulk"), db
    ) is True

    # src_ip matches, attack_type differs → not suppressed
    suppression_mod.invalidate_cache()
    assert await suppression_mod.is_suppressed(
        _alert(src_ip="1.2.3.4", attack_type="PortScan"), db
    ) is False


@pytest.mark.asyncio
async def test_wildcard_rule_suppresses_all(db):
    """Rule with no filters (all None) suppresses any alert."""
    db.add(_rule())  # all fields None
    await db.commit()

    assert await suppression_mod.is_suppressed(_alert(src_ip="any.ip", attack_type="Anything"), db) is True


# ── cleanup_expired ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_removes_expired_rule(db):
    db.add(_rule(src_ip="expired", expires_in=-10))
    db.add(_rule(src_ip="alive",   expires_in=3600))
    await db.commit()

    deleted = await suppression_mod.cleanup_expired(db)
    assert deleted == 1


@pytest.mark.asyncio
async def test_cleanup_invalidates_cache(db):
    suppression_mod._cache_ts = 999999.0
    await suppression_mod.cleanup_expired(db)
    assert suppression_mod._cache_ts == 0.0


@pytest.mark.asyncio
async def test_cleanup_returns_zero_when_nothing_expired(db):
    db.add(_rule(src_ip="alive", expires_in=3600))
    await db.commit()

    deleted = await suppression_mod.cleanup_expired(db)
    assert deleted == 0


@pytest.mark.asyncio
async def test_cleanup_removes_multiple_expired(db):
    for i in range(3):
        db.add(_rule(src_ip=f"old.{i}", expires_in=-1))
    db.add(_rule(src_ip="alive", expires_in=3600))
    await db.commit()

    deleted = await suppression_mod.cleanup_expired(db)
    assert deleted == 3
