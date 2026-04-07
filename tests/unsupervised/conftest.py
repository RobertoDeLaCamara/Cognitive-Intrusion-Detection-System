"""Conftest for unsupervised unit tests.

Stubs the `torch` package and its required submodules so that tests in this
directory never need a real PyTorch installation.  The stubs are inserted into
sys.modules once at collection time (autouse session-scoped fixture).
"""

import sys
from unittest.mock import MagicMock
import pytest


@pytest.fixture(scope="session", autouse=True)
def stub_torch():
    """Insert a minimal fake torch into sys.modules before any import of pipeline
    or window_trainer occurs.  This fixture runs once for the whole test session."""
    if "torch" not in sys.modules:
        torch_mock = MagicMock()
        torch_mock.nn = MagicMock()
        torch_mock.optim = MagicMock()
        sys.modules["torch"] = torch_mock
        sys.modules["torch.nn"] = torch_mock.nn
        sys.modules["torch.optim"] = torch_mock.optim
    yield
