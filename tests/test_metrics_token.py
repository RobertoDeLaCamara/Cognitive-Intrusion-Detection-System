"""/metrics honours the optional METRICS_TOKEN (cnds#25)."""

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

pytest.importorskip("prometheus_client")


@pytest.fixture(scope="module")
def metrics_app():
    # setup_prometheus registers collectors globally, so build the app once; the handler
    # reads METRICS_TOKEN at request time, which each test patches.
    from src.api import metrics
    app = FastAPI()
    with patch.object(metrics, "PROMETHEUS_ENABLED", True):
        metrics.setup_prometheus(app)
    return app


async def _get(app, token, headers=None):
    from src.api import metrics
    with patch.object(metrics, "METRICS_TOKEN", token):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            return await c.get("/metrics", headers=headers or {})


@pytest.mark.asyncio
async def test_public_when_no_token_configured(metrics_app):
    assert (await _get(metrics_app, "")).status_code == 200


@pytest.mark.asyncio
async def test_token_required_when_configured(metrics_app):
    assert (await _get(metrics_app, "s3cret")).status_code == 401
    assert (await _get(metrics_app, "s3cret", {"Authorization": "Bearer wrong"})).status_code == 401
    assert (await _get(metrics_app, "s3cret", {"Authorization": "Bearer s3cret"})).status_code == 200
