"""GET /api/engines lists the registered engines (cnds#9)."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi import FastAPI

from src.api.database import get_db
from src.api.models import Base
from src.api.routers.engines import router


@pytest_asyncio.fixture(loop_scope="function")
async def api():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        yield ac
    await engine.dispose()


@pytest.mark.asyncio
async def test_lists_every_engine_with_weight_and_state(api):
    resp = await api.get("/api/engines")
    assert resp.status_code == 200
    rows = {r["name"]: r for r in resp.json()["engines"]}
    assert set(rows) == {"supervised", "isolation_forest", "lstm", "baseline", "rules"}
    assert rows["rules"]["enabled"] is True
    assert all(isinstance(r["enabled"], bool) for r in rows.values())
    assert sum(r["weight"] for r in rows.values()) == pytest.approx(1.0, abs=0.01)
    assert all(r["adaptive_weight"] is None for r in rows.values())  # not enough feedback yet


def test_registry_keys_match_ensemble_weights():
    from src.engines.registry import ENGINES, EnsembleScorer
    assert set(ENGINES) | {"rules"} == set(EnsembleScorer._BASE_WEIGHTS)
