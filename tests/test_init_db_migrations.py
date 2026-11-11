"""init_db refuses to start on a failed migration of an Alembic-managed database (ADR 0004).

The companion cases (missing alembic.ini, failed migration on a database without a
revision, successful migration) are in tests/test_failure_streak.py::TestInitDb.
"""

import logging

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from src.api import database
from src.api import main as api_main
from src.api.models import Base


@pytest.fixture
async def file_db(monkeypatch, tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'cnds.db'}"
    engine = create_async_engine(url)
    monkeypatch.setattr(database, "DATABASE_URL", url)
    monkeypatch.setattr(database, "engine", engine)
    ini = tmp_path / "alembic.ini"
    ini.write_text("[alembic]\n")
    monkeypatch.setattr(database, "ALEMBIC_INI", str(ini))
    yield engine
    await engine.dispose()


async def _stamp(engine, revision="a8b9c0d1e2f3"):
    """Make the database look Alembic-managed, as after any successful migration."""
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        await conn.execute(text("INSERT INTO alembic_version VALUES (:rev)"), {"rev": revision})


async def _tables(engine):
    async with engine.connect() as conn:
        return await conn.run_sync(lambda sync: inspect(sync).get_table_names())


def _broken_migration():
    raise RuntimeError("duplicate column name: src_port")


async def test_failed_migration_on_a_managed_database_refuses_to_start(file_db, monkeypatch, caplog):
    await _stamp(file_db)
    monkeypatch.setattr(database, "_run_alembic", _broken_migration)

    with caplog.at_level(logging.WARNING, logger="src.api.database"):
        with pytest.raises(database.MigrationError, match="duplicate column name: src_port"):
            await database.init_db()

    (record,) = caplog.records
    assert record.levelname == "CRITICAL"
    assert "Refusing to start" in record.getMessage()
    assert record.exc_info[0] is RuntimeError
    # No create_all behind a failed migration.
    assert await _tables(file_db) == ["alembic_version"]


async def test_failed_migration_on_a_create_all_database_still_starts(file_db, monkeypatch, caplog):
    # Tables made by create_all, no revision: what the detector leaves when it runs first.
    async with file_db.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(database, "_run_alembic", _broken_migration)

    with caplog.at_level(logging.WARNING, logger="src.api.database"):
        await database.init_db()

    (record,) = caplog.records
    assert record.levelname == "ERROR"
    assert "no Alembic revision" in record.getMessage()
    assert "alembic stamp" in record.getMessage()


async def test_an_empty_alembic_version_table_does_not_count_as_managed(file_db, monkeypatch):
    # Alembic creates the table before running the first migration; if that one fails
    # the table is left empty.
    async with file_db.begin() as conn:
        await conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
    monkeypatch.setattr(database, "_run_alembic", _broken_migration)

    await database.init_db()

    assert "alerts" in await _tables(file_db)


async def test_unreachable_database_refuses_to_start(file_db, monkeypatch):
    monkeypatch.setattr(database, "_run_alembic", _broken_migration)

    async def unreachable():
        raise ConnectionError("database is down")

    monkeypatch.setattr(database, "_is_alembic_managed", unreachable)

    with pytest.raises(ConnectionError):
        await database.init_db()


async def test_api_lifespan_does_not_start_when_the_migration_fails(monkeypatch):
    async def failing_init_db():
        raise database.MigrationError("Alembic migration failed: boom")

    monkeypatch.setattr(api_main, "init_db", failing_init_db)

    with pytest.raises(database.MigrationError):
        async with api_main.lifespan(api_main.app):
            pytest.fail("the API must not reach the serving state")
