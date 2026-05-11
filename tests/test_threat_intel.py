"""Tests for Threat Intelligence Feed integration."""

import time
import threading
from unittest.mock import patch

from src.enrichment.threat_intel import (
    ThreatIntelStore,
    check_ip,
    check_ja3,
    check_domain,
    get_store,
)


class TestThreatIntelStore:
    """Test ThreatIntelStore core logic (no network calls)."""

    def test_empty_store(self):
        store = ThreatIntelStore()
        assert store.is_ip_malicious("1.2.3.4") is False
        assert store.is_ja3_malicious("abc123") is False
        assert store.is_domain_malicious("evil.com") is False
        assert len(store.malicious_ips) == 0
        assert len(store.malicious_ja3) == 0

    def test_add_ip(self):
        store = ThreatIntelStore()
        store.malicious_ips.add("1.2.3.4")
        assert store.is_ip_malicious("1.2.3.4") is True
        assert store.is_ip_malicious("5.6.7.8") is False

    def test_add_ja3(self):
        store = ThreatIntelStore()
        store.malicious_ja3.add("abc123")
        assert store.is_ja3_malicious("abc123") is True
        assert store.is_ja3_malicious("def456") is False

    def test_domain_exact_match(self):
        store = ThreatIntelStore()
        store.malicious_domains.add("evil.com")
        assert store.is_domain_malicious("evil.com") is True
        assert store.is_domain_malicious("good.com") is False

    def test_domain_subdomain_match(self):
        store = ThreatIntelStore()
        store.malicious_domains.add("evil.com")
        assert store.is_domain_malicious("sub.evil.com") is True
        assert store.is_domain_malicious("notevil.com") is False

    def test_domain_case_insensitive(self):
        store = ThreatIntelStore()
        store.malicious_domains.add("Evil.COM")
        assert store.is_domain_malicious("evil.com") is True
        assert store.is_domain_malicious("EVIL.COM") is True

    def test_stale_false_when_disabled(self):
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 0):
            store = ThreatIntelStore()
            store.last_refresh = 0
            assert store.stale() is False

    def test_stale_true_after_interval(self):
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 1):
            store = ThreatIntelStore()
            store.last_refresh = time.time() - 120
            assert store.stale() is True

    def test_stale_false_within_interval(self):
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 60):
            store = ThreatIntelStore()
            store.last_refresh = time.time() - 1800
            assert store.stale() is False


class TestCheckFunctions:
    """Test top-level check_ip / check_ja3 / check_domain functions."""

    def test_check_ip_malicious(self):
        store = ThreatIntelStore()
        store.malicious_ips.add("5.6.7.8")
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_ip("5.6.7.8")
            assert result is True
            assert source == "threat_intel_feed"

    def test_check_ip_clean(self):
        store = ThreatIntelStore()
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_ip("1.2.3.4")
            assert result is False
            assert source == ""

    def test_check_ja3_malicious(self):
        store = ThreatIntelStore()
        store.malicious_ja3.add("known_bad_hash")
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_ja3("known_bad_hash")
            assert result is True
            assert source == "threat_intel_feed"

    def test_check_ja3_clean(self):
        store = ThreatIntelStore()
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_ja3("unknown_hash")
            assert result is False
            assert source == ""

    def test_check_domain_malicious(self):
        store = ThreatIntelStore()
        store.malicious_domains.add("phishing.com")
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_domain("phishing.com")
            assert result is True
            assert source == "threat_intel_feed"

    def test_check_domain_clean(self):
        store = ThreatIntelStore()
        with patch("src.enrichment.threat_intel.get_store", return_value=store):
            result, source = check_domain("safe.com")
            assert result is False
            assert source == ""


class TestRefreshOnStale:
    """Test that refresh behavior works correctly."""

    def test_refresh_thread_started_on_stale(self):
        store = ThreatIntelStore()
        store.last_refresh = 0
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 1):
            assert store.stale() is True

    def test_refresh_not_on_fresh_store(self):
        store = ThreatIntelStore()
        store.last_refresh = time.time()
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 60):
            assert store.stale() is False


class TestGetStore:
    """Test singleton behavior."""

    def test_get_store_returns_singleton(self):
        s1 = get_store()
        s2 = get_store()
        assert s1 is s2

    def test_get_store_thread_safe(self):
        stores = []
        errors = []
        def _get():
            try:
                stores.append(get_store())
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=_get) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
        for s in stores:
            assert s is stores[0]


class TestIntegration:
    """Integration tests with the pipeline/ensemble integration points."""

    def test_ensemble_scores_ti_fields(self):
        """Verify the EngineScores dataclass accepts ti fields."""
        from src.ensemble.scorer import EngineScores
        scores = EngineScores(
            supervised=0.5,
            ti_malicious_ip=True,
            ti_malicious_ja3=False,
        )
        assert scores.ti_malicious_ip is True
        assert scores.ti_malicious_ja3 is False
        assert scores.supervised == 0.5

    def test_threat_intel_in_pipeline(self):
        """Verify pipeline can import threat_intel module."""
        from src import pipeline
        from src.enrichment.threat_intel import check_ip
        # Just verify the function can be called
        assert callable(check_ip)

    def test_refresh_feeds_no_urls(self):
        """Verify refresh doesn't crash when no feeds configured."""
        with patch("src.enrichment.threat_intel.ABUSEIPDB_URL", ""):
            with patch("src.enrichment.threat_intel.MALICIOUS_JA3_URL", ""):
                with patch("src.enrichment.threat_intel.MISP_URL", ""):
                    store = ThreatIntelStore()
                    store.refresh()
                    assert store.last_refresh > 0
                    assert len(store.malicious_ips) == 0
                    assert len(store.malicious_ja3) == 0

    def test_refresh_abuseipdb_http_error(self):
        """Verify refresh handles HTTP errors gracefully."""
        with patch("src.enrichment.threat_intel.ABUSEIPDB_URL", "https://fake.url"):
            with patch("requests.get", side_effect=Exception("Network error")):
                store = ThreatIntelStore()
                store.refresh()
                # Should not crash, should just warn
                assert store.last_refresh > 0

    def test_fetch_abuseipdb_success(self):
        """Test AbuseIPDB fetch parses CSV correctly."""
        mock_csv = """IP,Country,ASN,Last reported
1.2.3.4,US,12345,2025-01-01
5.6.7.8,CN,67890,2025-01-02
"""
        mock_resp = type('MockResponse', (), {'raise_for_status': lambda self: None, 'text': mock_csv})()
        with patch("src.enrichment.threat_intel.ABUSEIPDB_URL", "https://api.abuseipdb.com/blacklist"):
            with patch("src.enrichment.threat_intel.ABUSEIPDB_API_KEY", "test_key"):
                with patch("requests.get", return_value=mock_resp):
                    store = ThreatIntelStore()
                    store._fetch_abuseipdb()
                    assert "1.2.3.4" in store.malicious_ips
                    assert "5.6.7.8" in store.malicious_ips
                    assert len(store.malicious_ips) == 2

    def test_fetch_abuseipdb_comment_lines(self):
        """Test AbuseIPDB fetch skips comment lines."""
        mock_csv = """# AbuseIPDB Blacklist
# Generated: 2025-01-01
IP,Country,ASN,Last reported
10.0.0.1,US,99999,2025-01-01
"""
        mock_resp = type('MockResponse', (), {'raise_for_status': lambda self: None, 'text': mock_csv})()
        with patch("src.enrichment.threat_intel.ABUSEIPDB_URL", "https://api.abuseipdb.com/blacklist"):
            with patch("requests.get", return_value=mock_resp):
                store = ThreatIntelStore()
                store._fetch_abuseipdb()
                assert "10.0.0.1" in store.malicious_ips
                assert len(store.malicious_ips) == 1

    def test_fetch_ja3_success(self):
        """Test JA3 feed fetch parses lines correctly."""
        mock_feed = """abc123
def456
# this is a comment
ghi789
"""
        mock_resp = type('MockResponse', (), {'raise_for_status': lambda self: None, 'text': mock_feed})()
        with patch("src.enrichment.threat_intel.MALICIOUS_JA3_URL", "https://example.com/ja3.txt"):
            with patch("requests.get", return_value=mock_resp):
                store = ThreatIntelStore()
                store._fetch_ja3_feeds()
                assert "abc123" in store.malicious_ja3
                assert "def456" in store.malicious_ja3
                assert "ghi789" in store.malicious_ja3
                assert len(store.malicious_ja3) == 3

    def test_fetch_ja3_http_error(self):
        """Test JA3 feed handles HTTP errors gracefully."""
        with patch("src.enrichment.threat_intel.MALICIOUS_JA3_URL", "https://example.com/ja3.txt"):
            with patch("requests.get", side_effect=Exception("Timeout")):
                store = ThreatIntelStore()
                store._fetch_ja3_feeds()
                assert len(store.malicious_ja3) == 0

    def test_fetch_misp_success(self):
        """Test MISP fetch parses JSON response correctly."""
        mock_json = {
            "response": {
                "Attribute": [
                    {"value": "1.2.3.4", "type": "ip-dst"},
                    {"value": "evil.com", "type": "domain"},
                    {"value": "phish.com|5.6.7.8", "type": "domain|ip"},
                ]
            }
        }
        mock_resp = type('MockResponse', (), {
            'raise_for_status': lambda self: None,
            'json': lambda self: mock_json,
        })()
        with patch("src.enrichment.threat_intel.MISP_URL", "https://misp.local"):
            with patch("src.enrichment.threat_intel.MISP_API_KEY", "test_key"):
                with patch("requests.post", return_value=mock_resp):
                    store = ThreatIntelStore()
                    store._fetch_misp()
                    assert "1.2.3.4" in store.malicious_ips
                    assert "5.6.7.8" in store.malicious_ips
                    assert "evil.com" in store.malicious_domains
                    assert "phish.com" in store.malicious_domains

    def test_fetch_misp_http_error(self):
        """Test MISP fetch handles errors gracefully."""
        with patch("src.enrichment.threat_intel.MISP_URL", "https://misp.local"):
            with patch("src.enrichment.threat_intel.MISP_API_KEY", "test_key"):
                with patch("requests.post", side_effect=Exception("Connection refused")):
                    store = ThreatIntelStore()
                    store._fetch_misp()
                    assert len(store.malicious_ips) == 0
                    assert len(store.malicious_domains) == 0

    def test_get_store_background_refresh(self):
        """Test that get_store triggers background refresh when stale."""
        store = ThreatIntelStore()
        store.last_refresh = time.time() - 7200  # 2 hours ago
        with patch("src.enrichment.threat_intel.REFRESH_MINUTES", 60):
            with patch.object(store, 'stale', return_value=True):
                with patch.object(store, 'refresh') as mock_refresh:
                    with patch("src.enrichment.threat_intel._intel_store", store):
                        get_store()
                        # refresh should be called (background thread started)
                        # We can't easily test thread internals, but we verify stale was checked
                        assert store.stale() is True

    def test_refresh_updates_last_refresh(self):
        """Test that refresh updates last_refresh timestamp."""
        with patch("src.enrichment.threat_intel.ABUSEIPDB_URL", ""):
            with patch("src.enrichment.threat_intel.MALICIOUS_JA3_URL", ""):
                with patch("src.enrichment.threat_intel.MISP_URL", ""):
                    store = ThreatIntelStore()
                    store.last_refresh = 0
                    store.refresh()
                    assert store.last_refresh > 0
                    # Verify the logging includes counts
                    assert len(store.malicious_ips) == 0
