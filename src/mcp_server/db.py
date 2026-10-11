"""Read-only async database access for the MCP server.

A dedicated engine, separate from ``src/api/database.py``, for two reasons:

1. The MCP server normally runs as its own process (an MCP client spawns it
   over stdio), so it must not assume the API's engine or event loop exists.
2. Read-only is enforced *by the engine*, not by convention:

   * SQLite  — ``PRAGMA query_only=ON`` on every new connection. Any INSERT /
     UPDATE / DELETE raises ``sqlite3.OperationalError``.
   * PostgreSQL — the ``postgresql_readonly`` execution option, which issues
     ``SET TRANSACTION READ ONLY`` per transaction.

   A logic bug in a query function therefore cannot corrupt the alert store.

The read-only guarantee applies to sessions obtained from this module. Query
functions in :mod:`src.mcp_server.queries` take an ``AsyncSession`` argument so
they stay unit-testable against an ordinary test database.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import DATABASE_URL

logger = logging.getLogger(__name__)

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker] = None


def _install_sqlite_query_only(engine: AsyncEngine) -> None:
    """Force ``PRAGMA query_only=ON`` on every pooled SQLite connection."""

    @event.listens_for(engine.sync_engine, "connect")
    def _set_query_only(dbapi_connection, _connection_record):  # pragma: no cover
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA query_only=ON")
        finally:
            cursor.close()


def create_readonly_engine(url: str = DATABASE_URL) -> AsyncEngine:
    """Build an async engine that cannot write to ``url``."""
    kwargs: dict = {"echo": False}

    # asyncpg / psycopg: promoted to SET TRANSACTION READ ONLY by SQLAlchemy.
    if url.startswith("postgresql"):
        kwargs["execution_options"] = {"postgresql_readonly": True}

    engine = create_async_engine(url, **kwargs)

    if engine.dialect.name == "sqlite":
        _install_sqlite_query_only(engine)

    return engine


def get_sessionmaker() -> async_sessionmaker:
    """Return the process-wide read-only session factory, building it lazily."""
    global _engine, _sessionmaker
    if _sessionmaker is None:
        _engine = create_readonly_engine()
        # autoflush=False: nothing is ever added to these sessions, and a flush
        # against a query_only connection would raise rather than no-op.
        _sessionmaker = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        logger.info("MCP read-only engine ready (dialect=%s)", _engine.dialect.name)
    return _sessionmaker


@asynccontextmanager
async def readonly_session() -> AsyncIterator[AsyncSession]:
    """Yield a read-only session, rolling back on exit.

    Rollback rather than commit: there is nothing to commit, and it releases
    the transaction snapshot promptly so a long-lived MCP client does not pin
    an old view of the alert store.
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.rollback()


async def dispose() -> None:
    """Tear down the engine — used on shutdown and in tests."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
