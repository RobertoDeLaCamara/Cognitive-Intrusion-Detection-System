"""Failures in background loops must leave a trace in the log.

These loops used to swallow errors with `except Exception: pass` (or log them at
DEBUG), so a broken cleanup or drift computation was invisible in production.
"""

import asyncio
import logging
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.api import main as api_main
from src.api import metrics


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def _run_cleanup_once(monkeypatch):
    """Run one pass of _periodic_cleanup, then cancel it at the second sleep."""
    interval = 4242
    real_sleep = asyncio.sleep
    calls = 0

    async def fake_sleep(secs, *args, **kwargs):
        nonlocal calls
        if secs != interval:
            return await real_sleep(secs, *args, **kwargs)
        calls += 1
        if calls > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    monkeypatch.setattr("src.api.database.AsyncSessionLocal", _Session)
    with pytest.raises(asyncio.CancelledError):
        await api_main._periodic_cleanup(interval=interval)


class TestPeriodicCleanup:
    async def test_rate_limiter_prune_failure_is_logged(self, monkeypatch, caplog):
        monkeypatch.setattr("src.enrichment.suppression.cleanup_expired", AsyncMock(return_value=0))
        monkeypatch.setattr("src.api.rate_limit.prune_inactive", AsyncMock(side_effect=RuntimeError("boom")))

        with caplog.at_level(logging.WARNING, logger="src.api.main"):
            await _run_cleanup_once(monkeypatch)

        assert [r.getMessage() for r in caplog.records] == ["Rate limiter prune error: boom"]

    async def test_suppression_cleanup_failure_is_logged_and_prune_still_runs(self, monkeypatch, caplog):
        prune = AsyncMock(return_value=0)
        monkeypatch.setattr(
            "src.enrichment.suppression.cleanup_expired", AsyncMock(side_effect=RuntimeError("db down")),
        )
        monkeypatch.setattr("src.api.rate_limit.prune_inactive", prune)

        with caplog.at_level(logging.WARNING, logger="src.api.main"):
            await _run_cleanup_once(monkeypatch)

        assert [r.getMessage() for r in caplog.records] == ["Suppression cleanup error: db down"]
        prune.assert_awaited_once()

    async def test_clean_pass_logs_nothing(self, monkeypatch, caplog):
        monkeypatch.setattr("src.enrichment.suppression.cleanup_expired", AsyncMock(return_value=0))
        monkeypatch.setattr("src.api.rate_limit.prune_inactive", AsyncMock(return_value=0))

        with caplog.at_level(logging.WARNING, logger="src.api.main"):
            await _run_cleanup_once(monkeypatch)

        assert caplog.records == []


class TestBaselineScrapeDrift:
    def _start(self, monkeypatch, compute_drift, passes):
        """Run the scrape thread for `passes` iterations, then park it."""
        done = threading.Event()
        seen = []

        def update(snapshot, engine_info, drift_score, windows_trained):
            seen.append(drift_score)
            if len(seen) >= passes:
                done.set()

        # After `passes` iterations the collector getter returns None, so the daemon
        # thread keeps sleeping without doing any work for the rest of the session.
        collector = MagicMock()
        monkeypatch.setattr(metrics, "update_baseline_metrics", update)
        monkeypatch.setattr("src.unsupervised.drift.compute_drift", compute_drift)
        metrics.start_baseline_scrape(
            collector_getter=lambda: None if done.is_set() else collector,
            engine_getter=lambda: None,
            history_getter=lambda: [{"provenance": {}}],
            scrape_interval=0.01,
            log_interval=float("inf"),
        )
        assert done.wait(timeout=5.0)
        return seen

    def test_failing_drift_is_warned_once_not_on_every_scrape(self, monkeypatch, caplog):
        compute_drift = MagicMock(side_effect=RuntimeError("bad provenance"))

        with caplog.at_level(logging.WARNING, logger="src.api.metrics"):
            seen = self._start(monkeypatch, compute_drift, passes=5)

        assert seen[:5] == [None] * 5
        warnings = [r for r in caplog.records if "drift computation failed" in r.getMessage()]
        assert len(warnings) == 1
        assert "bad provenance" in warnings[0].getMessage()
        assert warnings[0].exc_info is not None

    def test_drift_is_warned_again_after_it_recovers_and_fails_again(self, monkeypatch, caplog):
        ok = MagicMock(drift_score=0.25)
        compute_drift = MagicMock(side_effect=[
            RuntimeError("first"), RuntimeError("first"), ok, RuntimeError("second"), RuntimeError("second"),
        ])

        with caplog.at_level(logging.WARNING, logger="src.api.metrics"):
            seen = self._start(monkeypatch, compute_drift, passes=5)

        assert seen[:5] == [None, None, 0.25, None, None]
        messages = [r.getMessage() for r in caplog.records if "drift computation failed" in r.getMessage()]
        assert len(messages) == 2
        assert "first" in messages[0] and "second" in messages[1]


class TestBaselineReloadTimestamp:
    @pytest.fixture
    def reload_gauge(self, monkeypatch):
        """Stand-ins for every baseline gauge (they are None when Prometheus is off)."""
        for name in dir(metrics):
            if name.startswith("_baseline_"):
                monkeypatch.setattr(metrics, name, MagicMock())
        return metrics._baseline_last_reload_ts

    def test_malformed_last_reload_timestamp_does_not_break_the_update(self, reload_gauge):
        metrics.update_baseline_metrics(MagicMock(), {"last_reload_iso": "not-a-date", "version": 7}, None, 0)

        reload_gauge.set.assert_not_called()
        # The gauges set before the timestamp are still updated.
        metrics._baseline_engine_version.set.assert_called_once_with(7)

    def test_valid_last_reload_timestamp_sets_the_gauge(self, reload_gauge):
        metrics.update_baseline_metrics(
            MagicMock(), {"last_reload_iso": "2026-11-01T10:00:00+00:00"}, None, 0,
        )

        reload_gauge.set.assert_called_once_with(1793527200.0)
