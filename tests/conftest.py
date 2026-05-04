"""Shared pytest fixtures for CNDS tests."""

import os

# Disable MLflow before any src import — BaselineEngine.__init__ calls _load()
# which tries to connect to the homelab MLflow server (192.168.1.147:5050) and
# hangs under test. setdefault leaves a real URI intact when set externally.
os.environ.setdefault("MLFLOW_TRACKING_URI", "")

# Disable FT-Transformer auto-load in the registry singleton. Loading the FT
# engine triggers a real `import torch` at collection time, which prevents
# tests/engines/test_baseline_engine.py from substituting its fake torch
# fixture (the real names are already bound). Tests that need the FT engine
# instantiate it explicitly via test_ft_transformer_engine.py.
os.environ.setdefault("FT_MODEL_FILE", "__disabled_in_tests__")


def pytest_collection_modifyitems(config, items):
    """Move tests that swap real torch for a MagicMock to the END of the run.

    `tests/engines/test_baseline_engine.py` swaps `sys.modules["torch"]` with
    a MagicMock via an autouse fixture, which corrupts the in-process state
    of real torch (Tensor comparison ops, `torch.nn.init` references) for
    any test running afterwards — even with explicit teardown and reloads,
    because some torch C-level state is process-global. Letting these
    mock-based tests run last preserves a clean torch for tests that need
    the real one (FT-Transformer engine, window stability).
    """
    LATE = ("tests/engines/test_baseline_engine.py",)
    early, late = [], []
    for item in items:
        rel = str(item.fspath).removeprefix(str(item.session.fspath) + "/")
        (late if rel in LATE else early).append(item)
    items[:] = early + late

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.api.models import Base


# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)


@pytest_asyncio.fixture(loop_scope="function")
async def test_db():
    """Create in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def mock_flow_features():
    """76-element flow feature vector."""
    import numpy as np
    return np.zeros(76, dtype=np.float32)


@pytest.fixture
def mock_host_features():
    """18-element host feature vector."""
    import numpy as np
    return np.array([
        45.2, 5200.0, 115.0, 800.0, 452, 52000,
        0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0,
        3.0, 0.2, 3.5, 80.0, 200.0
    ], dtype=np.float32)
