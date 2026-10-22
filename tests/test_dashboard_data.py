"""Pure helpers behind the dashboard overview (filtering, KPIs, trends)."""

import pandas as pd

from dashboard import data

NOW = pd.Timestamp("2026-10-22T12:00:00", tz="UTC")


def alert(id, minutes_ago=5, **kw):
    base = {
        "id": id,
        "timestamp": (NOW - pd.Timedelta(minutes=minutes_ago)).isoformat(),
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 4444, "dst_port": 22,
        "attack_type": "SSH-Patator", "severity": "high", "ensemble_score": 0.9,
        "engine_scores": {"supervised": 0.9, "rules": 0.4, "iforest": None},
        "triggered_rules": ["ssh_bruteforce"], "acknowledged": False,
        "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
        "src_geo": {"country": "Spain"}, "source": "detector",
    }
    base.update(kw)
    return base


def test_empty_input_gives_empty_frame_with_columns():
    df = data.alerts_to_frame(None)
    assert df.empty and list(df.columns) == data.FRAME_COLUMNS


def test_frame_derives_display_columns():
    row = data.alerts_to_frame([alert(1)]).iloc[0]
    assert row["flow"] == "10.0.0.1:4444 → 10.0.0.2:22"
    assert row["top_engine"] == "supervised"
    assert row["mitre"] == "T1110" and row["tactics"] == "Credential Access"
    assert row["country"] == "Spain" and row["rules"] == "ssh_bruteforce"


def test_frame_tolerates_missing_optional_fields():
    row = data.alerts_to_frame([{"id": 1, "timestamp": NOW.isoformat(), "src_ip": "1.1.1.1"}]).iloc[0]
    assert row["flow"] == "1.1.1.1 → ?" and row["severity"] == "low" and row["top_engine"] == ""


def test_filters_combine():
    df = data.alerts_to_frame([
        alert(1, severity="critical"),
        alert(2, severity="low", acknowledged=True, src_ip="9.9.9.9"),
        alert(3, minutes_ago=60 * 30, severity="critical"),
    ])
    out = data.apply_filters(df, severities=["critical"], status="Unacknowledged", hours=24, now=NOW)
    assert list(out["id"]) == [1]
    assert list(data.apply_filters(df, text="9.9.9").id) == [2]
    assert list(data.apply_filters(df, text="t1110").id) == [1, 2, 3]
    assert list(data.apply_filters(df, status="Acknowledged").id) == [2]


def test_kpis_compare_with_previous_24h():
    df = data.alerts_to_frame([
        alert(1), alert(2, severity="low"),
        alert(3, minutes_ago=60 * 30), alert(4, minutes_ago=60 * 31), alert(5, minutes_ago=60 * 32),
    ])
    k = data.kpis(df, now=NOW)
    assert (k["last_24h"], k["last_24h_delta"]) == (2, -1)
    assert k["crit_high"] == 4 and k["unacknowledged"] == 5 and k["unique_sources"] == 1


def test_top_values_splits_joined_cells():
    df = data.alerts_to_frame([alert(1, triggered_rules=["a", "b"]), alert(2, triggered_rules=["a"])])
    assert data.top_values(df, "rules", split=True).to_dict() == {"a": 2, "b": 1}


def test_relative_time():
    assert data.relative_time(NOW - pd.Timedelta(seconds=42), NOW) == "42s ago"
    assert data.relative_time(NOW - pd.Timedelta(hours=3), NOW) == "3h ago"
    assert data.relative_time(None, NOW) == ""


def test_trends_frame_fills_missing_severities():
    df = data.trends_frame({"data": {"2026-10-22T10:00:00Z": {"total": 2, "by_severity": {"high": 2}}}})
    assert list(df.columns) == data.SEVERITIES and df.iloc[0]["high"] == 2 and df.iloc[0]["low"] == 0
    assert data.trends_frame(None).empty
