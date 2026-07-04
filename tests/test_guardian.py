"""Tests for the guardian auto-response module (Phase 10)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from src.api.models import MitigationAction, MitigationStatus
from src.guardian.backends import AdGuardBackend


def _mock_client(get_json: dict):
    """Build an AsyncMock standing in for httpx.AsyncClient's async context manager."""
    mock_get_resp = MagicMock()
    mock_get_resp.json.return_value = get_json
    mock_get_resp.raise_for_status = MagicMock()

    mock_post_resp = MagicMock()
    mock_post_resp.raise_for_status = MagicMock()

    client = AsyncMock()
    client.get = AsyncMock(return_value=mock_get_resp)
    client.post = AsyncMock(return_value=mock_post_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestAdGuardBackend:
    @pytest.mark.asyncio
    async def test_block_adds_ip_when_absent(self):
        client = _mock_client({"allowed_clients": [], "disallowed_clients": [], "blocked_hosts": []})
        with patch("src.guardian.backends.httpx.AsyncClient", return_value=client):
            await AdGuardBackend().block("10.0.0.5", "test")
        client.post.assert_called_once()
        posted = client.post.call_args.kwargs["json"]
        assert "10.0.0.5" in posted["disallowed_clients"]

    @pytest.mark.asyncio
    async def test_block_is_idempotent(self):
        client = _mock_client({"allowed_clients": [], "disallowed_clients": ["10.0.0.5"], "blocked_hosts": []})
        with patch("src.guardian.backends.httpx.AsyncClient", return_value=client):
            await AdGuardBackend().block("10.0.0.5", "test")
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_unblock_removes_ip_when_present(self):
        client = _mock_client({"allowed_clients": [], "disallowed_clients": ["10.0.0.5"], "blocked_hosts": []})
        with patch("src.guardian.backends.httpx.AsyncClient", return_value=client):
            await AdGuardBackend().unblock("10.0.0.5")
        client.post.assert_called_once()
        posted = client.post.call_args.kwargs["json"]
        assert "10.0.0.5" not in posted["disallowed_clients"]

    @pytest.mark.asyncio
    async def test_unblock_is_idempotent(self):
        client = _mock_client({"allowed_clients": [], "disallowed_clients": [], "blocked_hosts": []})
        with patch("src.guardian.backends.httpx.AsyncClient", return_value=client):
            await AdGuardBackend().unblock("10.0.0.5")
        client.post.assert_not_called()


class TestGuardianEngine:
    def test_severity_value_ordering(self):
        from src.guardian.engine import _severity_value
        from src.api.models import SeverityLevel
        assert _severity_value(SeverityLevel.LOW) < _severity_value(SeverityLevel.CRITICAL)
        assert _severity_value("critical") == 3
        assert _severity_value("unknown") == 0

    @pytest.mark.asyncio
    async def test_has_active_action_true_when_pending_exists(self, test_db):
        from src.guardian.engine import _has_active_action
        test_db.add(MitigationAction(src_ip="10.0.0.9", status=MitigationStatus.PENDING))
        await test_db.commit()
        assert await _has_active_action(test_db, "10.0.0.9") is True

    @pytest.mark.asyncio
    async def test_has_active_action_false_when_resolved(self, test_db):
        from src.guardian.engine import _has_active_action
        test_db.add(MitigationAction(src_ip="10.0.0.9", status=MitigationStatus.EXPIRED))
        await test_db.commit()
        assert await _has_active_action(test_db, "10.0.0.9") is False

    @pytest.mark.asyncio
    async def test_has_active_action_false_when_no_rows(self, test_db):
        from src.guardian.engine import _has_active_action
        assert await _has_active_action(test_db, "10.0.0.9") is False

    @pytest.mark.asyncio
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_MAX_ACTIONS", 3)
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_WINDOW_SECS", 600)
    async def test_circuit_breaker_trips_over_threshold(self, test_db):
        from src.guardian.engine import _circuit_breaker_tripped
        now = datetime.now(timezone.utc)
        for i in range(3):
            test_db.add(MitigationAction(src_ip=f"10.0.0.{i}", status=MitigationStatus.PENDING, created_at=now))
        await test_db.commit()
        with patch("src.guardian.engine.notify_alert", new=AsyncMock()):
            assert await _circuit_breaker_tripped(test_db) is True

    @pytest.mark.asyncio
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_MAX_ACTIONS", 3)
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_WINDOW_SECS", 600)
    async def test_circuit_breaker_not_tripped_under_threshold(self, test_db):
        from src.guardian.engine import _circuit_breaker_tripped
        now = datetime.now(timezone.utc)
        test_db.add(MitigationAction(src_ip="10.0.0.1", status=MitigationStatus.PENDING, created_at=now))
        await test_db.commit()
        assert await _circuit_breaker_tripped(test_db) is False

    @pytest.mark.asyncio
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_MAX_ACTIONS", 3)
    @patch("src.guardian.engine.GUARDIAN_CIRCUIT_WINDOW_SECS", 600)
    async def test_circuit_breaker_ignores_actions_outside_window(self, test_db):
        from src.guardian.engine import _circuit_breaker_tripped
        stale = datetime.now(timezone.utc) - timedelta(seconds=1200)
        for i in range(5):
            test_db.add(MitigationAction(src_ip=f"10.0.0.{i}", status=MitigationStatus.EXPIRED, created_at=stale))
        await test_db.commit()
        assert await _circuit_breaker_tripped(test_db) is False
