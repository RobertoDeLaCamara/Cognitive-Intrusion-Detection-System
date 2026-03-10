"""Tests for MITRE ATT&CK mapping enrichment."""

import pytest
from src.enrichment.mitre import map_attack_type, map_rules, enrich


class TestMapAttackType:
    def test_benign_returns_empty(self):
        assert map_attack_type("BENIGN") == []

    def test_none_returns_empty(self):
        assert map_attack_type(None) == []

    def test_empty_returns_empty(self):
        assert map_attack_type("") == []

    def test_exact_match_dos(self):
        result = map_attack_type("DoS Hulk")
        assert len(result) >= 1
        assert result[0]["id"] == "T1498"
        assert result[0]["tactic"] == "Impact"

    def test_exact_match_portscan(self):
        result = map_attack_type("PortScan")
        assert result[0]["id"] == "T1046"

    def test_exact_match_brute_force(self):
        result = map_attack_type("FTP-Patator")
        assert result[0]["id"] == "T1110.001"
        assert result[0]["tactic"] == "Credential Access"

    def test_exact_match_sqli(self):
        result = map_attack_type("Web Attack – Sql Injection")
        assert result[0]["id"] == "T1190"

    def test_partial_match(self):
        result = map_attack_type("DoS")
        assert len(result) >= 1
        # Should partial-match one of the DoS variants
        assert any(t["id"] == "T1498" or t["id"] == "T1498.001" for t in result)

    def test_infiltration_multiple_techniques(self):
        result = map_attack_type("Infiltration")
        assert len(result) == 2
        ids = {t["id"] for t in result}
        assert "T1041" in ids
        assert "T1071" in ids

    def test_unknown_attack_returns_empty(self):
        assert map_attack_type("CompletelyUnknownAttack") == []


class TestMapRules:
    def test_none_returns_empty(self):
        assert map_rules(None) == []

    def test_empty_list_returns_empty(self):
        assert map_rules([]) == []

    def test_icmp_flood(self):
        result = map_rules(["icmp_flood"])
        assert result[0]["id"] == "T1498.001"

    def test_syn_scan(self):
        result = map_rules(["syn_scan"])
        assert result[0]["id"] == "T1046"

    def test_payload_sqli(self):
        result = map_rules(["payload:sql_injection"])
        assert result[0]["id"] == "T1190"

    def test_malicious_ja3(self):
        result = map_rules(["malicious_ja3"])
        ids = {t["id"] for t in result}
        assert "T1071" in ids
        assert "T1573" in ids

    def test_multiple_rules_deduped(self):
        # icmp_flood and syn_scan map to different techniques
        result = map_rules(["icmp_flood", "syn_scan"])
        ids = [t["id"] for t in result]
        assert len(ids) == len(set(ids))  # no duplicates

    def test_unknown_rule_returns_empty(self):
        assert map_rules(["nonexistent_rule"]) == []


class TestEnrich:
    def test_combines_attack_and_rules(self):
        result = enrich("PortScan", ["icmp_flood"])
        ids = {t["id"] for t in result}
        assert "T1046" in ids      # from PortScan
        assert "T1498.001" in ids   # from icmp_flood

    def test_deduplicates_across_sources(self):
        # Both "PortScan" and "syn_scan" map to T1046
        result = enrich("PortScan", ["syn_scan"])
        t1046_count = sum(1 for t in result if t["id"] == "T1046")
        assert t1046_count == 1

    def test_none_inputs(self):
        assert enrich(None, None) == []

    def test_benign_with_rules(self):
        result = enrich("BENIGN", ["icmp_flood"])
        assert len(result) >= 1
        assert result[0]["id"] == "T1498.001"
