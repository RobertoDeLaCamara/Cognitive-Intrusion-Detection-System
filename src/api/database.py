"""Async SQLAlchemy database setup."""

import asyncio
import logging
import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from ..config import DATABASE_URL
from .models import Base

logger = logging.getLogger(__name__)

ALEMBIC_INI = "alembic.ini"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _run_alembic():
    """Run Alembic migrations synchronously (called from thread executor)."""
    from alembic.config import Config
    from alembic import command
    alembic_cfg = Config(ALEMBIC_INI)
    command.upgrade(alembic_cfg, "head")


class MigrationError(RuntimeError):
    """A migration failed on a database that Alembic manages. The API must not start."""


def _current_revision(sync_conn):
    from alembic.runtime.migration import MigrationContext
    return MigrationContext.configure(sync_conn).get_current_revision()


async def _is_alembic_managed() -> bool:
    """True when the database carries an Alembic revision.

    A database whose tables were created by create_all (the detector does that in
    src/pipeline.py when it writes before the API has ever run) has no revision.
    """
    async with engine.connect() as conn:
        return await conn.run_sync(_current_revision) is not None


async def init_db() -> None:
    """Bring the schema up to date before the API serves anything.

    - In-memory DB (tests): create_all.
    - No alembic.ini: create_all, with a warning.
    - Migration fails on an Alembic-managed DB: log and raise MigrationError, so the API
      refuses to start instead of serving on a schema that is behind the models (ADR 0004).
    - Migration fails on a DB without a revision (tables made by create_all): keep the old
      create_all fallback, with an error that says how to adopt the DB.
    """
    if ":memory:" in DATABASE_URL:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return
    if not os.path.exists(ALEMBIC_INI):
        logger.warning(
            "%s not found: creating tables with create_all, no migration is applied", ALEMBIC_INI,
        )
    else:
        try:
            await asyncio.get_event_loop().run_in_executor(None, _run_alembic)
            return
        except Exception as exc:
            # If the revision cannot even be read (database unreachable), this raises too
            # and the API does not start.
            if await _is_alembic_managed():
                logger.critical(
                    "Alembic migration failed: %s. Refusing to start: the schema would be behind "
                    "the models. Fix the migration (or roll back the release) and start again.",
                    exc, exc_info=exc,
                )
                raise MigrationError(f"Alembic migration failed: {exc}") from exc
            # create_all only adds missing tables: it never alters an existing one.
            logger.error(
                "Alembic migration failed: %s. The database has no Alembic revision (its tables "
                "were created by create_all, not by a migration). Falling back to create_all, "
                "which does NOT alter existing tables: the schema may be out of date. Once the "
                "schema matches a revision, adopt it with `alembic stamp <revision>`.",
                exc, exc_info=exc,
            )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
