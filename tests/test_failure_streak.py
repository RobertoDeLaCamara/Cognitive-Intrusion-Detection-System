"""Failures that used to be invisible (no log, or DEBUG only) now leave a trace.

Covers the FailureStreak helper and the five places that use it or the same
idea: DB migrations, host feature extraction, the baseline collector, the
baseline metrics scrape loop and the drift block of GET /api/baseline/status.
"""

import logging
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import numpy as np
import pytest
from scapy.all import IP, TCP
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from src.api import database, metrics
from src.api.routers import baseline as baseline_router
from src.failure_streak import FailureStreak
from src.features.host_extractor import HostExtractor
from src.unsupervised.collector import BaselineCollector
from src.unsupervised.triggers import CompositeTrigger


def _levels(caplog, needle):
    return [r.levelname for r in caplog.records if needle in r.getMessage()]


class TestFailureStreak:
    def _streak(self):
        return FailureStreak(logging.getLogger("tests.streak"), "Thing")

    def test_first_failure_is_a_warning_with_traceback(self, caplog):
        streak = self._streak()
        with caplog.at_level(logging.DEBUG, logger="tests.streak"):
            streak.failed(ValueError("boom"))

        (record,) = caplog.records
        assert record.levelname == "WARNING"
        assert "Thing failed" in record.getMessage() and "boom" in record.getMessage()
        assert record.exc_info[0] is ValueError
        assert streak.failing is True

    def test_repeated_failures_drop_to_debug(self, caplog):
        streak = self._streak()
        with caplog.at_level(logging.DEBUG, logger="tests.streak"):
            for _ in range(4):
                streak.failed(ValueError("boom"))

        assert [r.levelname for r in caplog.records] == ["WARNING", "DEBUG", "DEBUG", "DEBUG"]

    def test_recovery_is_logged_once_and_rearms_the_warning(self, caplog):
        streak = self._streak()
        with caplog.at_level(logging.DEBUG, logger="tests.streak"):
            streak.failed(ValueError("first"))
            streak.ok()
            streak.ok()
            streak.failed(ValueError("second"))

        assert [r.levelname for r in caplog.records] == ["WARNING", "INFO", "WARNING"]
        assert caplog.records[1].getMessage() == "Thing recovered"

    def test_success_without_a_failure_logs_nothing(self, caplog):
        streak = self._streak()
        with caplog.at_level(logging.DEBUG, logger="tests.streak"):
            streak.ok()

        assert caplog.records == []
        assert streak.failing is False


class TestInitDb:
    @pytest.fixture
    async def file_db(self, monkeypatch, tmp_path):
        """Point init_db at an empty on-disk SQLite DB (":memory:" takes another branch)."""
        url = f"sqlite+aiosqlite:///{tmp_path / 'cnds.db'}"
        engine = create_async_engine(url)
        monkeypatch.setattr(database, "DATABASE_URL", url)
        monkeypatch.setattr(database, "engine", engine)
        ini = tmp_path / "alembic.ini"
        ini.write_text("[alembic]\n")
        monkeypatch.setattr(database, "ALEMBIC_INI", str(ini))

        async def tables():
            async with engine.connect() as conn:
                return await conn.run_sync(lambda sync: inspect(sync).get_table_names())

        yield SimpleNamespace(ini=ini, tables=tables)
        await engine.dispose()

    async def test_failed_migration_is_an_error_and_tables_are_still_created(self, file_db, monkeypatch, caplog):
        def broken():
            raise RuntimeError("duplicate column name: src_port")

        monkeypatch.setattr(database, "_run_alembic", broken)

        with caplog.at_level(logging.WARNING, logger="src.api.database"):
            await database.init_db()

        (record,) = caplog.records
        assert record.levelname == "ERROR"
        assert "Alembic migration failed: duplicate column name: src_port" in record.getMessage()
        assert "does NOT alter existing tables" in record.getMessage()
        assert record.exc_info[0] is RuntimeError
        assert "alerts" in await file_db.tables()

    async def test_missing_alembic_ini_is_a_warning_and_alembic_is_not_run(self, file_db, monkeypatch, caplog):
        file_db.ini.unlink()
        run = MagicMock()
        monkeypatch.setattr(database, "_run_alembic", run)

        with caplog.at_level(logging.WARNING, logger="src.api.database"):
            await database.init_db()

        (record,) = caplog.records
        assert record.levelname == "WARNING"
        assert "not found" in record.getMessage()
        run.assert_not_called()
        assert "alerts" in await file_db.tables()

    async def test_successful_migration_logs_nothing_and_skips_create_all(self, file_db, monkeypatch, caplog):
        run = MagicMock()
        monkeypatch.setattr(database, "_run_alembic", run)

        with caplog.at_level(logging.WARNING, logger="src.api.database"):
            await database.init_db()

        run.assert_called_once()
        assert caplog.records == []
        # The (mocked) migration owns the schema: create_all must not have run behind it.
        assert await file_db.tables() == []


class TestHostFeatureExtraction:
    def _extractor_with_host(self, ip="10.0.0.5"):
        extractor = HostExtractor()
        for i in range(5):
            extractor.process_packet(IP(src=ip, dst="10.0.0.1") / TCP(sport=1000 + i, dport=80), timestamp=100.0 + i)
        return extractor

    def test_compute_failure_returns_none_and_warns_once(self, monkeypatch, caplog):
        extractor = self._extractor_with_host()
        monkeypatch.setattr(extractor, "_compute", MagicMock(side_effect=ZeroDivisionError("empty window")))

        with caplog.at_level(logging.DEBUG, logger="src.features.host_extractor"):
            results = [extractor.extract_features("10.0.0.5", now=110.0) for _ in range(3)]

        assert results == [None, None, None]
        assert _levels(caplog, "Host feature extraction") == ["WARNING", "DEBUG", "DEBUG"]
        assert "empty window" in caplog.records[0].getMessage()

    def test_normal_extraction_returns_the_vector_and_logs_nothing(self, caplog):
        extractor = self._extractor_with_host()

        with caplog.at_level(logging.DEBUG, logger="src.features.host_extractor"):
            vec = extractor.extract_features("10.0.0.5", now=110.0)

        assert isinstance(vec, np.ndarray) and vec.shape == (18,)
        assert caplog.records == []

    def test_recovery_after_a_failure_is_logged(self, monkeypatch, caplog):
        extractor = self._extractor_with_host()
        real_compute = extractor._compute
        monkeypatch.setattr(extractor, "_compute", MagicMock(side_effect=ZeroDivisionError("x")))

        with caplog.at_level(logging.DEBUG, logger="src.features.host_extractor"):
            assert extractor.extract_features("10.0.0.5", now=110.0) is None
            monkeypatch.setattr(extractor, "_compute", real_compute)
            assert extractor.extract_features("10.0.0.5", now=110.0) is not None

        assert _levels(caplog, "Host feature extraction") == ["WARNING", "INFO"]


class TestBaselineCollectorFieldExtraction:
    def _collector(self):
        trigger = CompositeTrigger(
            min_total_vectors=100, min_distinct_src_ips=2, min_elapsed_sec=60.0, min_dst_port_entropy_bits=1.0,
        )
        return BaselineCollector(trigger=trigger, on_window_ready=MagicMock())

    def test_unreadable_record_is_skipped_and_warned_once(self, caplog):
        collector = self._collector()
        # dst_port is not a number: int(key[3]) raises.
        bad = SimpleNamespace(src_ip="10.0.0.5", dst_ip="10.0.0.1", key=("10.0.0.5", "10.0.0.1", 1234, "http", 6))

        with caplog.at_level(logging.DEBUG, logger="src.unsupervised.collector"):
            for _ in range(3):
                collector.observe(bad, np.zeros(18, dtype=np.float32))

        assert collector.snapshot().n_total == 0
        assert _levels(caplog, "BaselineCollector field extraction") == ["WARNING", "DEBUG", "DEBUG"]

    def test_readable_record_is_buffered_and_logs_nothing(self, caplog):
        collector = self._collector()
        good = SimpleNamespace(
            src_ip="10.0.0.5", dst_ip="10.0.0.1", key=("10.0.0.5", "10.0.0.1", 1234, 80, 6), last_time=100.0,
        )

        with caplog.at_level(logging.DEBUG, logger="src.unsupervised.collector"):
            collector.observe(good, np.zeros(18, dtype=np.float32))

        assert collector.snapshot().n_total == 1
        assert _levels(caplog, "BaselineCollector field extraction") == []


class TestBaselineMetricsScrape:
    def test_broken_scrape_is_warned_once_not_on_every_pass(self, caplog):
        calls = 0
        done = threading.Event()

        def collector_getter():
            nonlocal calls
            if done.is_set():
                return None     # park the daemon thread for the rest of the session
            calls += 1
            if calls >= 5:
                done.set()
            raise RuntimeError("collector gone")

        with caplog.at_level(logging.WARNING, logger="src.api.metrics"):
            metrics.start_baseline_scrape(
                collector_getter=collector_getter,
                engine_getter=lambda: None,
                history_getter=lambda: [],
                scrape_interval=0.01,
                log_interval=float("inf"),
            )
            assert done.wait(timeout=5.0)

        warnings = [r for r in caplog.records if "baseline metrics scrape failed" in r.getMessage()]
        assert len(warnings) == 1
        assert "collector gone" in warnings[0].getMessage()
        assert warnings[0].exc_info[0] is RuntimeError


class TestBaselineStatusDrift:
    @pytest.fixture
    def status(self, monkeypatch):
        """baseline_status() with a collector, an engine and one trained window."""
        snap = SimpleNamespace(
            n_total=10, n_distinct_src_ips=2, elapsed_sec=60.0, dst_port_entropy_bits=1.0,
            training_in_flight=False, dropped_while_training=0,
            trigger_thresholds={"vectors": 100}, progress_ratios={"vectors": 0.1},
        )
        monkeypatch.setattr(baseline_router, "_get_collector", lambda: MagicMock(snapshot=lambda: snap))
        monkeypatch.setattr(baseline_router, "_get_engine", lambda: MagicMock(get_info=lambda: {"available": True}))
        monkeypatch.setattr(
            baseline_router, "_get_trainer", lambda: MagicMock(get_history=lambda: [{"provenance": {}}]),
        )
        monkeypatch.setattr(
            baseline_router, "_drift_streak", FailureStreak(baseline_router.logger, "Drift computation"),
        )
        return baseline_router.baseline_status

    def test_drift_failure_keeps_the_endpoint_working_and_warns_once(self, status, monkeypatch, caplog):
        monkeypatch.setattr(
            "src.unsupervised.drift.compute_drift", MagicMock(side_effect=KeyError("top_ports")),
        )

        with caplog.at_level(logging.DEBUG, logger="src.api.routers.baseline"):
            bodies = [status() for _ in range(3)]

        assert all(body["engine"] == {"available": True} for body in bodies)
        assert _levels(caplog, "Drift computation") == ["WARNING", "DEBUG", "DEBUG"]

    def test_working_drift_logs_nothing(self, status, monkeypatch, caplog):
        report = SimpleNamespace(
            drift_score=0.12345, verdict="stable", dst_port_entropy_delta_bits=0.1,
            distinct_src_ips_ratio=1.0, top_ports_jaccard=0.9,
        )
        monkeypatch.setattr("src.unsupervised.drift.compute_drift", MagicMock(return_value=report))

        with caplog.at_level(logging.DEBUG, logger="src.api.routers.baseline"):
            body = status()

        assert _levels(caplog, "Drift computation") == []
        assert body["drift"]["drift_score"] == 0.1235
        assert body["drift"]["verdict"] == "stable"
