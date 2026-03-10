"""Tests for the CEF syslog forwarder."""

import pytest
from siem.syslog.forwarder import alert_to_cef


@pytest.fixture
def sample_alert():
    return {
        "id": 42,
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 443,
        "severity": "high",
        "attack_type": "DoS Hulk",
        "ensemble_score": 0.87,
        "triggered_rules": ["icmp_flood", "large_payload"],
        "ja3_hash": "abc123def456",
        "mitre_techniques": [
            {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        ],
    }


class TestAlertToCEF:
    def test_cef_format(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert cef.startswith("CEF:0|CNDS|CognitiveNDS|1.0|")

    def test_contains_attack_type(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert "DoS Hulk" in cef

    def test_severity_mapping(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        # high → 8
        assert "|8|" in cef

    def test_contains_src_dst(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert "src=10.0.0.5" in cef
        assert "dst=192.168.1.1" in cef

    def test_contains_ja3(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert "cs2=abc123def456" in cef
        assert "cs2Label=JA3Hash" in cef

    def test_contains_mitre(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert "T1498" in cef
        assert "cs3Label=MITRETechniques" in cef

    def test_contains_rules(self, sample_alert):
        cef = alert_to_cef(sample_alert)
        assert "icmp_flood" in cef
        assert "large_payload" in cef

    def test_missing_fields_handled(self):
        minimal = {"id": 1, "src_ip": "1.2.3.4"}
        cef = alert_to_cef(minimal)
        assert cef.startswith("CEF:0|CNDS|")
        assert "src=1.2.3.4" in cef

    def test_critical_severity(self):
        alert = {"severity": "critical", "src_ip": "1.1.1.1"}
        cef = alert_to_cef(alert)
        assert "|10|" in cef

    def test_low_severity(self):
        alert = {"severity": "low", "src_ip": "1.1.1.1"}
        cef = alert_to_cef(alert)
        assert "|3|" in cef
