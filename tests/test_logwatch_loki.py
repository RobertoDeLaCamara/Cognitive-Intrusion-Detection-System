"""logwatch live path: Loki source cursor, watcher health alerts and the persist loop (fake Loki, no network)."""

import asyncio
import time

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.models import Alert, Base
from src.logwatch import gitea, persist, watcher as watcher_mod
from src.logwatch.engine import LogRuleEngine, parse_networks
from src.logwatch.events import LogAlert
from src.logwatch.loki import LokiError, LokiSource
from src.logwatch.rules import load_rules
from src.logwatch.replay import DEFAULT_RULES_DIR

NS = 1_000_000_000
ATTACKER = "203.0.113.7"


class FakeLoki:
    """Answers /loki/api/v1/query_range like Loki: start inclusive, end exclusive, oldest first, limited."""

    def __init__(self):
        self.entries = []           # (ts_ns, line)
        self.requests = []
        self.fail = None            # None | int status | Exception (typed loosely on purpose)

    def add(self, ts, line):
        self.entries.append((int(ts * NS), line))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail:
            return httpx.Response(self.fail, text="boom")
        q = request.url.params
        start, end, limit = int(q["start"]), int(q["end"]), int(q["limit"])
        assert q["direction"] == "forward"
        rows = sorted(e for e in self.entries if start <= e[0] < end)[:limit]
        values = [[str(ts), line] for ts, line in rows]
        return httpx.Response(200, json={"data": {"result": [{"stream": {"container": "gitea"}, "values": values}] if values else []}})


def source(fake, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake.handler))
    kw.setdefault("lag_secs", 0)
    return LokiSource("http://loki:3100", {"gitea": '{container="gitea"}'}, client=client, **kw)


def gitea_line(path="/user/sign_up", status=403, ip=ATTACKER, method="POST", n=0):
    return (f"2026/10/22 17:13:02 HTTPRequest [I] router: completed {method} {path} for {ip}:{33000 + n}, "
            f"{status} Forbidden in 1.1ms @ auth/auth.go:538(auth.SignUpPost)")


# ── LokiSource ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_first_poll_reads_the_backfill_window_then_only_new_entries():
    fake, now = FakeLoki(), time.time()
    for i in range(3):
        fake.add(now - 3600 + i, f"old {i}")
    fake.add(now - 90000, "older than the backfill")          # outside 24 h
    src = source(fake, backfill_secs=86400)
    first = await src.poll("gitea", now=now)
    assert [e.line for e in first] == ["old 0", "old 1", "old 2"]
    assert int(fake.requests[0].url.params["start"]) == int((now - 86400) * NS)
    assert await src.poll("gitea", now=now + 1) == []          # nothing new, overlap filtered
    fake.add(now + 5, "new")
    assert [e.line for e in await src.poll("gitea", now=now + 10)] == ["new"]
    # the request that fetched "new" started at the cursor left by the last delivered entry ("old 2")
    assert int(fake.requests[-1].url.params["start"]) == int((now - 3600 + 2) * NS)


@pytest.mark.asyncio
async def test_lines_sharing_a_timestamp_are_delivered_exactly_once():
    fake, now = FakeLoki(), time.time()
    fake.add(now - 10, "a")
    src = source(fake)
    assert [e.line for e in await src.poll("gitea", now=now)] == ["a"]
    fake.add(now - 10, "b")                                    # same ns, arrives late
    assert [e.line for e in await src.poll("gitea", now=now + 1)] == ["b"]
    assert await src.poll("gitea", now=now + 2) == []


@pytest.mark.asyncio
async def test_pagination_returns_everything_once():
    fake, now = FakeLoki(), time.time()
    for i in range(8):
        fake.add(now - 100 + i, f"l{i}")
    src = source(fake, batch=3)
    assert [e.line for e in await src.poll("gitea", now=now)] == [f"l{i}" for i in range(8)]
    assert len(fake.requests) >= 3


@pytest.mark.asyncio
async def test_more_lines_than_a_batch_on_one_timestamp_cannot_loop_forever():
    fake, now = FakeLoki(), time.time()
    for i in range(5):
        fake.add(now - 10, f"same-{i}")
    got = await asyncio.wait_for(source(fake, batch=2).poll("gitea", now=now), timeout=5)
    assert len(got) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [503, httpx.ConnectError("down")])
async def test_failures_raise_and_the_cursor_resumes_afterwards(failure):
    fake, now = FakeLoki(), time.time()
    fake.add(now - 20, "one")
    src = source(fake)
    assert [e.line for e in await src.poll("gitea", now=now)] == ["one"]
    fake.fail = failure
    with pytest.raises(LokiError):
        await src.poll("gitea", now=now + 1)
    fake.fail = None
    fake.add(now + 2, "two")
    assert [e.line for e in await src.poll("gitea", now=now + 3)] == ["two"]


@pytest.mark.asyncio
async def test_malformed_response_is_a_loki_error():
    src = LokiSource("http://loki", {"gitea": "{}"}, client=httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"unexpected": 1}))))
    with pytest.raises(LokiError, match="unexpected"):
        await src.poll("gitea")


@pytest.mark.asyncio
async def test_lag_excludes_the_newest_entries_and_basic_auth_is_sent():
    fake, now = FakeLoki(), time.time()
    fake.add(now - 5, "too fresh")
    fake.add(now - 60, "settled")
    src = source(fake, lag_secs=15, user="reader", password="pw")
    assert [e.line for e in await src.poll("gitea", now=now)] == ["settled"]
    assert fake.requests[0].headers["authorization"].startswith("Basic ")


# ── LogWatcher ────────────────────────────────────────────────────────────────

def make_watcher(fake, **kw):
    engine = LogRuleEngine(load_rules(DEFAULT_RULES_DIR), trusted=parse_networks(["192.168.0.0/16"]))
    return watcher_mod.LogWatcher(source(fake), engine, {"gitea": gitea.parse_line}, **kw)


@pytest.mark.asyncio
async def test_low_and_slow_attack_over_the_backfill_window_alerts_once():
    fake, now = FakeLoki(), time.time()
    for i in range(6):                                          # one attempt every 30 min, like the real bot
        fake.add(now - 3 * 3600 + i * 1800, gitea_line(n=i))
    fake.add(now - 100, "unrelated line that is not an access log")
    w = make_watcher(fake)
    alerts = await w.poll_once()
    assert [(a.rule, a.key) for a in alerts] == [("gitea_signup_attempts", ATTACKER)]
    assert await w.poll_once() == []                           # same data is not counted twice


@pytest.mark.asyncio
async def test_alert_fires_on_live_entries_after_the_first_poll():
    fake = FakeLoki()
    w = make_watcher(fake)
    assert await w.poll_once() == []
    for i in range(3):
        fake.add(time.time() - 20 + i, gitea_line(n=i))
    assert [a.rule for a in await w.poll_once()] == ["gitea_signup_attempts"]


@pytest.mark.asyncio
async def test_silent_source_alerts_once_and_rearms_when_data_returns():
    fake = FakeLoki()
    w = make_watcher(fake, silent_polls=3)
    out = [await w.poll_once() for _ in range(5)]
    assert [len(x) for x in out] == [0, 0, 1, 0, 0]
    assert out[2][0].rule == watcher_mod.SILENT_RULE and out[2][0].severity == "high"
    fake.add(time.time() - 20, gitea_line(path="/", status=200, ip="192.168.1.5", method="GET"))
    await w.poll_once()
    out = [await w.poll_once() for _ in range(3)]
    assert [len(x) for x in out] == [0, 0, 1]


@pytest.mark.asyncio
async def test_unreachable_source_alerts_after_repeated_failures_once():
    fake = FakeLoki()
    fake.fail = httpx.ConnectError("down")
    w = make_watcher(fake)
    out = [await w.poll_once() for _ in range(7)]
    assert [len(x) for x in out] == [0, 0, 0, 0, 1, 0, 0]
    assert out[4][0].rule == watcher_mod.UNREACHABLE_RULE
    fake.fail = None
    assert await w.poll_once() == []                           # recovery is silent and rearms the flag
    fake.fail = httpx.ConnectError("down")
    out = [await w.poll_once() for _ in range(5)]
    assert len(out[-1]) == 1


# ── persistence loop ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture(loop_scope="function")
async def session_factory(tmp_path):
    # file-backed: an in-memory SQLite shares one connection, so the run loop and the test's own
    # reads would trample each other's transactions (a test artifact, not a production concern)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/logwatch.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()


@pytest.fixture(autouse=True)
def quiet_notifications(monkeypatch):
    async def _noop(data):
        return None
    monkeypatch.setattr(persist, "notify_alert", _noop)


async def stored(factory):
    async with factory() as db:
        return (await db.execute(select(Alert))).scalars().all()


async def run_until(watcher, factory, predicate, timeout=5):
    stop = asyncio.Event()
    task = asyncio.create_task(watcher_mod.run(watcher, factory, poll_secs=0.05, stop=stop))
    try:
        async with asyncio.timeout(timeout):
            while not predicate(await stored(factory)):
                await asyncio.sleep(0.02)
    finally:
        stop.set()
        await task


@pytest.mark.asyncio
async def test_run_loop_persists_alerts_and_a_restart_does_not_duplicate_them(session_factory):
    fake, now = FakeLoki(), time.time()
    for i in range(6):
        fake.add(now - 3 * 3600 + i * 1800, gitea_line(n=i))
    await run_until(make_watcher(fake), session_factory, lambda rows: len(rows) == 1)
    row = (await stored(session_factory))[0]
    assert (row.source, row.src_ip, row.triggered_rules) == ("logwatch", ATTACKER, ["gitea_signup_attempts"])

    # "restart": new watcher with empty state re-reads the same 24 h of history
    await run_until(make_watcher(fake), session_factory, lambda rows: True)
    await asyncio.sleep(0.2)
    assert len(await stored(session_factory)) == 1


@pytest.mark.asyncio
async def test_run_loop_survives_a_failing_cycle(session_factory):
    class Exploding:
        parsers = {"gitea": None}
        calls = 0

        async def poll_once(self):
            Exploding.calls += 1
            if Exploding.calls == 1:
                raise RuntimeError("bug")
            return [LogAlert(rule="r", service="gitea", description="d", severity="low", key="203.0.113.9",
                             ip="203.0.113.9", count=1, window_secs=1, first_ts=time.time(), last_ts=time.time())]

    await run_until(Exploding(), session_factory, lambda rows: len(rows) == 1)
    assert Exploding.calls >= 2


@pytest.mark.asyncio
async def test_already_alerted_respects_the_cooldown(session_factory):
    now = time.time()
    la = LogAlert(rule="r", service="gitea", description="d", severity="low", key=ATTACKER, ip=ATTACKER,
                  count=1, window_secs=60, first_ts=now, last_ts=now, cooldown_secs=3600)
    async with session_factory() as db:
        assert not await persist.already_alerted(db, la)
        await persist.persist_alert(db, la, notify=False)
        assert await persist.already_alerted(db, la)
        later = LogAlert(**{**la.__dict__, "last_ts": now + 7200})
        assert not await persist.already_alerted(db, later)             # cooldown over
        other_rule = LogAlert(**{**la.__dict__, "rule": "other"})
        assert not await persist.already_alerted(db, other_rule)
