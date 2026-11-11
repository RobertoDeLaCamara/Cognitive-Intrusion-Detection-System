"""Tests for the guardian background loops (guardian_loop, guardian_expiry_loop).

tests/test_guardian.py covers the helpers and the AdGuard backend; this file
runs the loops themselves against an in-memory database. The loops are
`while True`, so each test replaces the module's `asyncio.sleep` with a fake
that lets a fixed number of iterations run and then cancels the loop.
"""

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from src.api.models import Alert, Base, MitigationAction, MitigationStatus, SeverityLevel
from src.guardian import engine as guardian
from src.timeutils import utcnow


@pytest_asyncio.fixture(loop_scope="function")
async def session_factory(monkeypatch):
    """In-memory DB shared by every session the loop opens (StaticPool = one connection)."""
    db_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", echo=False, poolclass=StaticPool,
    )
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    monkeypatch.setattr(guardian, "AsyncSessionLocal", factory)
    yield factory
    await db_engine.dispose()


@pytest.fixture
def backend(monkeypatch):
    fake = SimpleNamespace(block=AsyncMock(), unblock=AsyncMock())
    monkeypatch.setattr(guardian, "_backend", fake)
    return fake


@pytest.fixture
def notify(monkeypatch):
    """Default guardian settings for the tests, with both notification paths mocked."""
    mocks = SimpleNamespace(alert=AsyncMock(), telegram=AsyncMock())
    monkeypatch.setattr(guardian, "notify_alert", mocks.alert)
    monkeypatch.setattr(guardian, "send_action_notice", mocks.telegram)
    monkeypatch.setattr(guardian, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(guardian, "GUARDIAN_MIN_SEVERITY", "critical")
    monkeypatch.setattr(guardian, "GUARDIAN_ALERT_SOURCES", {"detector"})
    monkeypatch.setattr(guardian, "GUARDIAN_WHITELIST", {"192.168.1.1"})
    monkeypatch.setattr(guardian, "GUARDIAN_BLOCK_MINUTES", 30)
    monkeypatch.setattr(guardian, "GUARDIAN_CIRCUIT_MAX_ACTIONS", 5)
    monkeypatch.setattr(guardian, "GUARDIAN_CIRCUIT_WINDOW_SECS", 600)
    monkeypatch.setattr(guardian, "_circuit_paused_notified", False)
    return mocks


def _alert(src_ip="10.0.0.5", severity=SeverityLevel.CRITICAL, **kwargs):
    kwargs.setdefault("dst_ip", "192.168.1.50")
    kwargs.setdefault("attack_type", "DoS")
    kwargs.setdefault("ensemble_score", 0.97)
    return Alert(src_ip=src_ip, severity=severity, **kwargs)


async def _add(factory, *rows):
    async with factory() as db:
        db.add_all(rows)
        await db.commit()


async def _actions(factory):
    async with factory() as db:
        result = await db.execute(select(MitigationAction).order_by(MitigationAction.id))
        return list(result.scalars().all())


async def _run(loop_fn, monkeypatch, iterations=1, before_iteration=None):
    """Run `iterations` passes of a guardian loop, then cancel it.

    `before_iteration(n)` is awaited inside the n-th sleep (1-based), which is
    where new alerts arrive in production: after the loop has started.
    """
    calls = 0

    async def fake_sleep(_secs):
        nonlocal calls
        calls += 1
        if calls > iterations:
            raise asyncio.CancelledError
        if before_iteration is not None:
            await before_iteration(calls)

    monkeypatch.setattr(guardian, "asyncio", SimpleNamespace(sleep=fake_sleep))
    with pytest.raises(asyncio.CancelledError):
        await loop_fn()


class TestGuardianLoop:
    async def test_blocks_new_critical_alert(self, session_factory, backend, notify, monkeypatch):
        async def arrive(_n):
            await _add(session_factory, _alert())

        started = utcnow()
        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        backend.block.assert_awaited_once_with("10.0.0.5", "DoS (score=0.97)")
        (action,) = await _actions(session_factory)
        assert action.src_ip == "10.0.0.5"
        assert action.status == MitigationStatus.PENDING
        assert action.action_type == "dns_block"
        assert action.backend == "adguard"
        assert action.alert_id == 1
        assert timedelta(minutes=29) < action.expires_at - started < timedelta(minutes=31)

    async def test_block_is_announced_through_notify_alert_without_telegram(
        self, session_factory, backend, notify, monkeypatch,
    ):
        async def arrive(_n):
            await _add(session_factory, _alert())

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        notify.telegram.assert_not_awaited()
        notify.alert.assert_awaited_once()
        payload = notify.alert.await_args.args[0]
        assert payload["src_ip"] == "10.0.0.5"
        assert payload["attack_type"] == "Guardian auto-block: DoS (score=0.97)"

    async def test_block_is_announced_through_telegram_when_token_is_set(
        self, session_factory, backend, notify, monkeypatch,
    ):
        monkeypatch.setattr(guardian, "TELEGRAM_BOT_TOKEN", "token")

        async def arrive(_n):
            await _add(session_factory, _alert())

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        notify.alert.assert_not_awaited()
        notify.telegram.assert_awaited_once()
        assert notify.telegram.await_args.args[0].src_ip == "10.0.0.5"

    async def test_alerts_that_predate_the_loop_are_ignored(
        self, session_factory, backend, notify, monkeypatch,
    ):
        await _add(session_factory, _alert())

        await _run(guardian.guardian_loop, monkeypatch)

        backend.block.assert_not_awaited()
        assert await _actions(session_factory) == []

    @pytest.mark.parametrize("alert_kwargs", [
        {"severity": SeverityLevel.HIGH},          # below GUARDIAN_MIN_SEVERITY
        {"src_ip": "192.168.1.1"},                 # whitelisted
        {"src_ip": ""},                            # nothing to block
        {"source": "api"},                         # not in GUARDIAN_ALERT_SOURCES
    ], ids=["below-min-severity", "whitelisted", "no-src-ip", "source-not-allowed"])
    async def test_alert_is_skipped(self, session_factory, backend, notify, monkeypatch, alert_kwargs):
        async def arrive(_n):
            await _add(session_factory, _alert(**alert_kwargs))

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        backend.block.assert_not_awaited()
        assert await _actions(session_factory) == []
        notify.alert.assert_not_awaited()

    async def test_lower_min_severity_widens_what_is_blocked(
        self, session_factory, backend, notify, monkeypatch,
    ):
        monkeypatch.setattr(guardian, "GUARDIAN_MIN_SEVERITY", "high")

        async def arrive(_n):
            await _add(session_factory, _alert(severity=SeverityLevel.HIGH))

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        backend.block.assert_awaited_once()

    async def test_ip_with_a_pending_action_is_not_blocked_again(
        self, session_factory, backend, notify, monkeypatch,
    ):
        async def arrive(_n):
            await _add(
                session_factory,
                MitigationAction(src_ip="10.0.0.5", status=MitigationStatus.PENDING),
                _alert(),
            )

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        backend.block.assert_not_awaited()
        assert len(await _actions(session_factory)) == 1

    async def test_two_alerts_from_one_ip_in_a_batch_block_once(
        self, session_factory, backend, notify, monkeypatch,
    ):
        async def arrive(_n):
            await _add(session_factory, _alert(), _alert(attack_type="PortScan"))

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        backend.block.assert_awaited_once()
        assert len(await _actions(session_factory)) == 1

    async def test_failed_block_records_nothing_and_the_batch_continues(
        self, session_factory, backend, notify, monkeypatch,
    ):
        backend.block.side_effect = [RuntimeError("adguard down"), None]

        async def arrive(_n):
            await _add(session_factory, _alert("10.0.0.5"), _alert("10.0.0.6"))

        await _run(guardian.guardian_loop, monkeypatch, before_iteration=arrive)

        assert backend.block.await_count == 2
        assert [a.src_ip for a in await _actions(session_factory)] == ["10.0.0.6"]

    async def test_tripped_circuit_breaker_blocks_nothing_and_does_not_replay_the_batch(
        self, session_factory, backend, notify, monkeypatch,
    ):
        monkeypatch.setattr(guardian, "GUARDIAN_CIRCUIT_MAX_ACTIONS", 2)

        async def arrive(n):
            if n == 1:
                # Two recent actions trip the breaker; the alert lands in the same batch.
                await _add(
                    session_factory,
                    MitigationAction(src_ip="10.0.0.1", status=MitigationStatus.CONFIRMED),
                    MitigationAction(src_ip="10.0.0.2", status=MitigationStatus.CONFIRMED),
                    _alert("10.0.0.5"),
                )
            else:
                # Breaker released before the second pass: the earlier alert must stay skipped.
                monkeypatch.setattr(guardian, "GUARDIAN_CIRCUIT_MAX_ACTIONS", 50)

        await _run(guardian.guardian_loop, monkeypatch, iterations=2, before_iteration=arrive)

        backend.block.assert_not_awaited()
        assert len(await _actions(session_factory)) == 2
        # The pause itself is announced once.
        notify.alert.assert_awaited_once()
        assert notify.alert.await_args.args[0]["attack_type"].startswith("Guardian paused: 2 auto-blocks")

    async def test_loop_survives_a_database_error(self, session_factory, backend, notify, monkeypatch):
        real_factory = session_factory
        state = {"fail": True}

        def flaky_factory():
            if state["fail"]:
                state["fail"] = False
                raise RuntimeError("database unavailable")
            return real_factory()

        monkeypatch.setattr(guardian, "AsyncSessionLocal", flaky_factory)
        # _init_last_seen_id opens a session too; start it from a known value instead.
        monkeypatch.setattr(guardian, "_init_last_seen_id", AsyncMock())
        monkeypatch.setattr(guardian, "_last_seen_alert_id", 0)

        async def arrive(n):
            if n == 2:
                await _add(real_factory, _alert())

        await _run(guardian.guardian_loop, monkeypatch, iterations=2, before_iteration=arrive)

        backend.block.assert_awaited_once()


class TestGuardianExpiryLoop:
    async def test_expired_pending_action_is_unblocked(self, session_factory, backend, monkeypatch):
        await _add(session_factory, MitigationAction(
            src_ip="10.0.0.5", status=MitigationStatus.PENDING,
            expires_at=utcnow() - timedelta(minutes=1),
        ))

        await _run(guardian.guardian_expiry_loop, monkeypatch)

        backend.unblock.assert_awaited_once_with("10.0.0.5")
        (action,) = await _actions(session_factory)
        assert action.status == MitigationStatus.EXPIRED
        assert action.resolved_at is not None

    @pytest.mark.parametrize("status, expires_in", [
        (MitigationStatus.PENDING, timedelta(minutes=10)),     # not due yet
        (MitigationStatus.PENDING, None),                      # no expiry set
        (MitigationStatus.CONFIRMED, timedelta(minutes=-1)),   # analyst made it permanent
        (MitigationStatus.UNDONE, timedelta(minutes=-1)),      # already lifted
    ], ids=["not-due", "no-expiry", "confirmed", "undone"])
    async def test_action_is_left_alone(self, session_factory, backend, monkeypatch, status, expires_in):
        expires_at = None if expires_in is None else utcnow() + expires_in
        await _add(session_factory, MitigationAction(src_ip="10.0.0.5", status=status, expires_at=expires_at))

        await _run(guardian.guardian_expiry_loop, monkeypatch)

        backend.unblock.assert_not_awaited()
        (action,) = await _actions(session_factory)
        assert action.status == status
        assert action.resolved_at is None

    async def test_failed_unblock_stays_pending_and_others_still_expire(
        self, session_factory, backend, monkeypatch,
    ):
        past = utcnow() - timedelta(minutes=1)
        await _add(
            session_factory,
            MitigationAction(src_ip="10.0.0.5", status=MitigationStatus.PENDING, expires_at=past),
            MitigationAction(src_ip="10.0.0.6", status=MitigationStatus.PENDING, expires_at=past),
        )

        async def unblock(ip):
            if ip == "10.0.0.5":
                raise RuntimeError("adguard down")

        backend.unblock.side_effect = unblock

        await _run(guardian.guardian_expiry_loop, monkeypatch)

        by_ip = {a.src_ip: a.status for a in await _actions(session_factory)}
        assert by_ip == {"10.0.0.5": MitigationStatus.PENDING, "10.0.0.6": MitigationStatus.EXPIRED}

    async def test_failed_unblock_is_retried_on_the_next_pass(self, session_factory, backend, monkeypatch):
        await _add(session_factory, MitigationAction(
            src_ip="10.0.0.5", status=MitigationStatus.PENDING,
            expires_at=utcnow() - timedelta(minutes=1),
        ))
        backend.unblock.side_effect = [RuntimeError("adguard down"), None]

        await _run(guardian.guardian_expiry_loop, monkeypatch, iterations=2)

        assert backend.unblock.await_count == 2
        (action,) = await _actions(session_factory)
        assert action.status == MitigationStatus.EXPIRED
