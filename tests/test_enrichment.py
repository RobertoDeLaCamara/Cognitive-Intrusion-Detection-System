"""Tests for Phase 8 enrichment modules."""

import time
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ── GeoIP ──────────────────────────────────────────────────────────────────────

class TestGeoIP:
    def test_lookup_returns_none_when_disabled(self):
        from src.enrichment import geoip
        with patch.object(geoip, "MOCK_GEOIP", {}), patch.object(geoip, "_reader", None):
            assert geoip.lookup("8.8.8.8") is None

    def test_is_enabled_false_by_default(self):
        from src.enrichment import geoip
        with patch.object(geoip, "_reader", None):
            assert geoip.is_enabled() is False


# ── DNS Logger ─────────────────────────────────────────────────────────────────

class TestDNSLogger:
    def test_extract_returns_none_when_disabled(self):
        from src.enrichment.dns_logger import extract_dns_query
        pkt = MagicMock()
        assert extract_dns_query(pkt) is None

    def test_get_dns_log_empty(self):
        from src.enrichment.dns_logger import get_dns_log
        assert get_dns_log("1.2.3.4") == []

    def test_get_all_logs_returns_dict(self):
        from src.enrichment.dns_logger import get_all_logs
        result = get_all_logs()
        assert isinstance(result, dict)

    @patch("src.enrichment.dns_logger.DNS_LOGGING_ENABLED", True)
    def test_extract_dns_query_valid_packet(self):
        from src.enrichment.dns_logger import extract_dns_query, _dns_log
        from scapy.all import IP, UDP, DNS, DNSQR

        pkt = MagicMock()
        pkt.__contains__ = lambda self, layer: True

        ip_layer = MagicMock()
        ip_layer.src = "10.0.0.1"

        dnsqr_layer = MagicMock()
        dnsqr_layer.qname = b"example.com."
        dnsqr_layer.qtype = 1

        dns_layer = MagicMock()
        dns_layer.qr = 0
        dns_layer.qd = True
        dns_layer.__getitem__ = lambda self, layer: dnsqr_layer

        def getitem(layer):
            if layer is IP:
                return ip_layer
            if layer is DNS:
                return dns_layer
            if layer is DNSQR:
                return dnsqr_layer
            return MagicMock()

        pkt.__getitem__ = lambda self, layer: getitem(layer)

        result = extract_dns_query(pkt)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["domain"] == "example.com"

        # Cleanup
        _dns_log.pop("10.0.0.1", None)


# ── Notifications ──────────────────────────────────────────────────────────────

class TestNotifications:
    @pytest.mark.asyncio
    @patch("src.enrichment.notifications.WEBHOOK_URLS", [])
    async def test_notify_noop_when_no_urls(self):
        from src.enrichment.notifications import notify_alert
        # Should not raise
        await notify_alert({"severity": "critical", "src_ip": "1.2.3.4"})

    @pytest.mark.asyncio
    @patch("src.enrichment.notifications.WEBHOOK_URLS", ["http://example.com/hook"])
    @patch("src.enrichment.notifications.NOTIFY_MIN_SEVERITY", "high")
    async def test_notify_skips_low_severity(self):
        from src.enrichment.notifications import notify_alert
        with patch("httpx.AsyncClient") as mock_client:
            await notify_alert({"severity": "low", "src_ip": "1.2.3.4"})
            mock_client.assert_not_called()

    @pytest.mark.asyncio
    @patch("src.enrichment.notifications.WEBHOOK_URLS", ["http://example.com/hook"])
    @patch("src.enrichment.notifications.NOTIFY_MIN_SEVERITY", "high")
    async def test_notify_sends_for_critical(self):
        from src.enrichment.notifications import notify_alert

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client_instance = AsyncMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("src.enrichment.notifications.httpx.AsyncClient", return_value=mock_client_instance):
            await notify_alert({
                "severity": "critical",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "ensemble_score": 0.95,
                "attack_type": "DoS",
                "triggered_rules": ["icmp_flood"],
            })
            mock_client_instance.post.assert_called_once()

    @pytest.mark.asyncio
    @patch("src.enrichment.notifications.WEBHOOK_URLS", [])
    @patch("src.enrichment.notifications.TELEGRAM_BOT_TOKEN", "123:ABC")
    @patch("src.enrichment.notifications.TELEGRAM_CHAT_ID", "456")
    @patch("src.enrichment.notifications.NOTIFY_MIN_SEVERITY", "high")
    async def test_notify_sends_telegram(self):
        from src.enrichment.notifications import notify_alert

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client_instance = AsyncMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("src.enrichment.notifications.httpx.AsyncClient", return_value=mock_client_instance):
            await notify_alert({
                "severity": "critical",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "ensemble_score": 0.95,
                "attack_type": "DoS",
                "triggered_rules": [],
            })
            mock_client_instance.post.assert_called_once()
            call_args = mock_client_instance.post.call_args
            assert "api.telegram.org" in call_args[0][0]
            assert call_args[1]["json"]["chat_id"] == "456"

    @pytest.mark.asyncio
    @patch("src.enrichment.notifications.WEBHOOK_URLS", [])
    @patch("src.enrichment.notifications.TELEGRAM_BOT_TOKEN", "")
    @patch("src.enrichment.notifications.TELEGRAM_CHAT_ID", "")
    @patch("src.enrichment.notifications.NOTIFY_MIN_SEVERITY", "high")
    async def test_notify_noop_when_no_channels(self):
        from src.enrichment.notifications import notify_alert
        # Should not raise even with no channels configured
        await notify_alert({"severity": "critical", "src_ip": "1.2.3.4"})


# ── Rate Limiter ───────────────────────────────────────────────────────────────

class TestRateLimiter:
    def test_rate_limiter_allows_under_limit(self):
        from src.api.rate_limit import RateLimitMiddleware
        # Just verify the class can be instantiated with params
        app = MagicMock()
        middleware = RateLimitMiddleware(app, requests=10, window=60)
        assert middleware._requests == 10
        assert middleware._window == 60


# ── Adaptive Weights ───────────────────────────────────────────────────────────

class TestAdaptiveWeights:
    @pytest.mark.asyncio
    @patch("src.enrichment.adaptive_weights.ADAPTIVE_WEIGHTS_ENABLED", False)
    async def test_returns_none_when_disabled(self):
        from src.enrichment.adaptive_weights import compute_adaptive_weights
        db = AsyncMock()
        result = await compute_adaptive_weights(db)
        assert result is None

    @pytest.mark.asyncio
    @patch("src.enrichment.adaptive_weights.ADAPTIVE_WEIGHTS_ENABLED", True)
    @patch("src.enrichment.adaptive_weights.ADAPTIVE_MIN_SAMPLES", 2)
    async def test_returns_none_when_insufficient_samples(self):
        from src.enrichment.adaptive_weights import compute_adaptive_weights
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []  # 0 alerts
        db.execute = AsyncMock(return_value=mock_result)
        result = await compute_adaptive_weights(db)
        assert result is None

    @pytest.mark.asyncio
    @patch("src.enrichment.adaptive_weights.ADAPTIVE_WEIGHTS_ENABLED", True)
    @patch("src.enrichment.adaptive_weights.ADAPTIVE_MIN_SAMPLES", 1)
    async def test_computes_weights_from_feedback(self):
        from src.enrichment.adaptive_weights import compute_adaptive_weights

        # Create mock alerts
        alert1 = MagicMock()
        alert1.engine_scores = {"supervised": 0.8, "isolation_forest": 0.2, "lstm": 0.0, "rules": 0.0}
        alert1.notes = None
        alert1.acknowledged = True

        alert2 = MagicMock()
        alert2.engine_scores = {"supervised": 0.9, "isolation_forest": 0.1, "lstm": 0.0, "rules": 0.5}
        alert2.notes = "false positive"
        alert2.acknowledged = True

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [alert1, alert2]
        db.execute = AsyncMock(return_value=mock_result)

        result = await compute_adaptive_weights(db)
        assert result is not None
        assert set(result.keys()) == {"supervised", "isolation_forest", "lstm", "rules"}
        assert abs(sum(result.values()) - 1.0) < 1e-6


# ── Confidence Decay ───────────────────────────────────────────────────────────

class TestConfidenceDecay:
    def test_first_alert_no_decay(self):
        from src.enrichment.confidence_decay import apply_decay, _hits, _lock
        # Use a unique IP to avoid cross-test contamination
        ip = "99.99.99.1"
        with _lock:
            _hits.pop(ip, None)
        result = apply_decay(ip, 0.9)
        assert result == 0.9
        with _lock:
            _hits.pop(ip, None)

    def test_repeated_alerts_decay(self):
        from src.enrichment.confidence_decay import apply_decay, _hits, _lock
        ip = "99.99.99.2"
        with _lock:
            _hits.pop(ip, None)
        apply_decay(ip, 0.9)  # first: no decay
        result = apply_decay(ip, 0.9)  # second: 1 repeat → 0.9 * 0.9
        assert result == pytest.approx(0.81)
        with _lock:
            _hits.pop(ip, None)

    def test_recent_alert_count(self):
        from src.enrichment.confidence_decay import apply_decay, recent_alert_count, _hits, _lock
        ip = "99.99.99.3"
        with _lock:
            _hits.pop(ip, None)
        apply_decay(ip, 0.8)
        apply_decay(ip, 0.8)
        assert recent_alert_count(ip) == 2
        with _lock:
            _hits.pop(ip, None)


# ── IP Lists ──────────────────────────────────────────────────────────────────

class TestIPLists:
    @patch("src.enrichment.ip_lists.IP_ALLOWLIST", {"10.0.0.1"})
    def test_allowlisted(self):
        from src.enrichment.ip_lists import is_allowlisted
        assert is_allowlisted("10.0.0.1") is True
        assert is_allowlisted("10.0.0.2") is False

    @patch("src.enrichment.ip_lists.IP_BLOCKLIST", {"192.168.1.100"})
    def test_blocklisted(self):
        from src.enrichment.ip_lists import is_blocklisted
        assert is_blocklisted("192.168.1.100") is True
        assert is_blocklisted("192.168.1.101") is False
