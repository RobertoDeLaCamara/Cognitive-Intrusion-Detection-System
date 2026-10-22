"""Smoke tests: each dashboard view renders against a fake API without exceptions."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard"
sys.path.insert(0, str(DASHBOARD))
import common  # noqa: E402


ALERT = {
    "id": 7, "timestamp": "2026-10-22T10:00:00", "src_ip": "203.0.113.5", "dst_ip": "192.168.1.10",
    "src_port": 50000, "dst_port": 22, "protocol": 6, "attack_type": "SSH-Patator", "severity": "critical",
    "ensemble_score": 0.93, "engine_scores": {"supervised": 0.9, "rules": 1.0, "iforest": None},
    "triggered_rules": ["ssh_bruteforce"], "acknowledged": False, "label": None, "notes": None,
    "incident_id": None, "src_geo": {"country": "NL", "city": "Amsterdam", "lat": 52.3, "lon": 4.9},
    "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "ja3_hash": None, "source": "detector", "src_asset_type": None,
    "payload_matches": ["union select"], "ja3_string": None,
    "flow_features": [0.1, 0.2], "host_features": None,
    "flow_feature_names": ["flow_duration", "tot_fwd_pkts"], "host_feature_names": None,
}


class Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def json(self):
        return self._payload


class FakeApi:
    def get(self, path, **kw):
        if path == "/api/stats":
            return Resp({"total_alerts": 1, "unacknowledged": 1, "by_severity": {"critical": 1}})
        if path == "/api/alerts/trends":
            return Resp({"data": {"2026-10-22T10:00:00Z": {"total": 1, "by_severity": {"critical": 1}}}})
        if path == "/api/alerts":
            return Resp([ALERT])
        if path == "/api/incidents":
            return Resp([])
        if path == "/api/alerts/7":
            return Resp(ALERT)
        return Resp({}, 404)

    def patch(self, path, **kw):
        return Resp(ALERT)


@pytest.fixture(autouse=True)
def fake_api(monkeypatch):
    monkeypatch.setattr(common, "get_api", lambda: FakeApi())
    common.fetch_alerts.clear()
    common.fetch_alert.clear()
    common.fetch_stats.clear()
    common.fetch_trends.clear()
    common.fetch_incidents.clear()
    common.fetch_related.clear()


def run(view):
    at = AppTest.from_file(str(DASHBOARD / "views" / view), default_timeout=20)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def test_overview_renders_kpis_and_table():
    at = run("overview.py")
    assert [m.label for m in at.metric][:2] == ["Total alerts", "Unacknowledged"]
    assert at.dataframe, "alert table missing"


def test_alert_detail_renders_all_sections():
    at = AppTest.from_file(str(DASHBOARD / "views" / "alert_detail.py"), default_timeout=20)
    at.session_state["alert_id"] = 7
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert "SSH-Patator" in at.header[0].value
    assert any(m.label == "Ensemble score" and m.value == "93.0%" for m in at.metric)


def test_alert_detail_handles_unknown_id():
    at = AppTest.from_file(str(DASHBOARD / "views" / "alert_detail.py"), default_timeout=20)
    at.session_state["alert_id"] = 999
    at.run()
    assert not at.exception and at.warning


def test_analytics_renders():
    run("analytics.py")
