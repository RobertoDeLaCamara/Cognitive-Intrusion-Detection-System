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


async def init_db() -> None:
    """Run Alembic migrations, falling back to create_all for in-memory DBs."""
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
            # create_all only adds missing tables: it never alters an existing one, so after a
            # failed migration the schema can be behind the models. Say so loudly.
            logger.error(
                "Alembic migration failed: %s. Falling back to create_all, which does NOT alter "
                "existing tables: the schema may be out of date until the migration is fixed.",
                exc, exc_info=exc,
            )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
