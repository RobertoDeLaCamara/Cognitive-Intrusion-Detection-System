"""Async SQLAlchemy database setup."""

import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from ..config import DATABASE_URL
from .models import Base

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _run_alembic():
    """Run Alembic migrations synchronously (called from thread executor)."""
    from alembic.config import Config
    from alembic import command
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")


async def init_db() -> None:
    """Run Alembic migrations, falling back to create_all for in-memory DBs."""
    if ":memory:" in DATABASE_URL:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return
    try:
        await asyncio.get_event_loop().run_in_executor(None, _run_alembic)
    except Exception:
        # Fallback for environments without alembic.ini (e.g. Docker first run)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
