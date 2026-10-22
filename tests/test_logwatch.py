"""logwatch: rule loading, the sliding-window engine, the Gitea parser and the shipped rules."""

import textwrap
from datetime import timezone, timedelta
from pathlib import Path

import pytest

from src.logwatch import engine as engine_mod, gitea
from src.logwatch.engine import LogRuleEngine, parse_networks
from src.logwatch.events import LogEvent
from src.logwatch.replay import DEFAULT_RULES_DIR, main as replay_main, replay
from src.logwatch.rules import RuleError, load_rules

ATTACKER = "203.0.113.7"       # RFC 5737 documentation addresses
OWNER = "198.51.100.20"
LAN = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]


def write_rules(tmp_path, body: str) -> Path:
    f = tmp_path / "r.yaml"
    f.write_text(textwrap.dedent(body))
    return f


def ev(ts, ip=ATTACKER, method="POST", path="/user/login", status=200, service="gitea", user=None):
    return LogEvent(ts=ts, service=service, ip=ip, user=user, method=method, path=path, status=status, raw=f"{ts} {ip} {method} {path} {status}")


def shipped_engine(extra_trusted=()):
    return LogRuleEngine(load_rules(DEFAULT_RULES_DIR), trusted=parse_networks(LAN + list(extra_trusted)))


def fire(eng, events):
    return [a for e in events for a in eng.feed(e)]


# ── rule loading ──────────────────────────────────────────────────────────────

def test_shipped_rules_load():
    names = {r.name for r in load_rules(DEFAULT_RULES_DIR)}
    assert {"gitea_signup_attempts", "gitea_signup_success", "gitea_login_bruteforce", "gitea_admin_untrusted",
            "gitea_persistence", "gitea_recon"} <= names


@pytest.mark.parametrize("snippet, message", [
    ("severity: urgent", "severity"),
    ("threshold: 0", "threshold"),
    ("window_secs: ten", "window_secs"),
    ("group_by: host", "group_by"),
    ("match: {path: '(['}", "invalid path regex"),
    ("match: {verb: GET}", "unknown match keys"),
    ("match: {status: [abc]}", "status"),
    ("match: []", "match"),
])
def test_invalid_rules_are_rejected(tmp_path, snippet, message):
    base = dict(line.split(": ", 1) for line in [
        "name: r", "service: s", "match: {path: x}", "threshold: 1", "window_secs: 60", "severity: low"])
    key = snippet.split(": ", 1)[0]
    base[key] = snippet.split(": ", 1)[1]
    f = write_rules(tmp_path, "rules:\n  - " + "\n    ".join(f"{k}: {v}" for k, v in base.items()) + "\n")
    with pytest.raises(RuleError, match=message):
        load_rules(f)


def test_missing_key_duplicate_name_and_empty_dir(tmp_path):
    with pytest.raises(RuleError, match="missing 'severity'"):
        load_rules(write_rules(tmp_path, """
            rules:
              - {name: r, service: s, match: {path: x}, threshold: 1, window_secs: 60}
            """))
    dup = """
        rules:
          - {name: r, service: s, match: {path: x}, threshold: 1, window_secs: 60, severity: low}
          - {name: r, service: s, match: {path: y}, threshold: 1, window_secs: 60, severity: low}
        """
    with pytest.raises(RuleError, match="duplicate rule name"):
        load_rules(write_rules(tmp_path, dup))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RuleError, match="no rules files"):
        load_rules(empty)


# ── engine ────────────────────────────────────────────────────────────────────

SIMPLE = """
    rules:
      - name: burst
        service: gitea
        description: Burst
        match: {method: POST, path: '^/user/login$', status: 200}
        group_by: ip
        threshold: 3
        window_secs: 60
        cooldown_secs: 300
        severity: high
        mitre: [{id: T1110, name: Brute Force, tactic: Credential Access}]
    """


def test_fires_at_threshold_within_window_only(tmp_path):
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    assert fire(eng, [ev(0), ev(10)]) == []
    alerts = fire(eng, [ev(20)])
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.rule, a.severity, a.key, a.count, a.first_ts, a.last_ts) == ("burst", "high", ATTACKER, 3, 0, 20)
    assert a.mitre[0]["id"] == "T1110" and len(a.samples) == 3


def test_events_outside_the_window_do_not_add_up(tmp_path):
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    assert fire(eng, [ev(0), ev(100), ev(200), ev(300)]) == []


def test_cooldown_collapses_a_flood_into_one_alert_then_rearms(tmp_path):
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    assert len(fire(eng, [ev(t) for t in range(0, 200, 5)])) == 1       # 40 events, one alert
    assert len(fire(eng, [ev(t) for t in range(400, 420, 5)])) == 1     # after cooldown it fires again


def test_keys_are_independent(tmp_path):
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    events = [ev(t, ip=f"203.0.113.{t}") for t in range(1, 7)]           # 6 IPs, 1 hit each
    assert fire(eng, events) == []


def test_non_matching_events_are_ignored(tmp_path):
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    events = [ev(t, status=303) for t in range(10)] + [ev(t, method="GET") for t in range(10)] \
        + [ev(t, service="nginx") for t in range(10)]
    assert fire(eng, events) == []


def test_untrusted_only_skips_trusted_networks(tmp_path):
    body = SIMPLE.replace("severity: high", "severity: high\n        untrusted_only: true")
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, body)), trusted=parse_networks(["192.168.0.0/16", OWNER]))
    assert fire(eng, [ev(t, ip="192.168.1.50") for t in range(5)]) == []
    assert fire(eng, [ev(t, ip=OWNER) for t in range(5)]) == []
    assert len(fire(eng, [ev(t) for t in range(3)])) == 1


def test_group_by_user_and_missing_key(tmp_path):
    body = SIMPLE.replace("group_by: ip", "group_by: user")
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, body)))
    assert fire(eng, [ev(t) for t in range(5)]) == []                    # no user -> nothing to count
    assert len(fire(eng, [ev(t, user="alice") for t in range(3)])) == 1


def test_any_of_conditions(tmp_path):
    body = """
        rules:
          - name: probe
            service: gitea
            match:
              - {path: '^/install'}
              - {status: 404}
            threshold: 2
            window_secs: 60
            severity: low
        """
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, body)))
    assert len(fire(eng, [ev(0, method="GET", path="/install", status=200), ev(1, method="GET", path="/x", status=404)])) == 1


def test_memory_stays_bounded_under_many_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_mod, "MAX_KEYS_PER_RULE", 50)
    eng = LogRuleEngine(load_rules(write_rules(tmp_path, SIMPLE)))
    for i in range(500):
        eng.feed(ev(i, ip=f"203.0.{i // 250}.{i % 250}"))
    assert len(eng._hits) <= 50


def test_trusted_check_handles_garbage():
    eng = LogRuleEngine([], trusted=parse_networks(["10.0.0.0/8"]))
    assert eng.is_trusted("10.1.2.3") and not eng.is_trusted("nonsense") and not eng.is_trusted(None)


# ── Gitea parser ──────────────────────────────────────────────────────────────

LINE = ("2026/10/22 17:13:02 HTTPRequest [I] router: completed POST /user/sign_up for 203.0.113.7:33978, "
        "403 Forbidden in 1.1ms @ auth/auth.go:538(auth.SignUpPost)")


def test_parse_gitea_line():
    e = gitea.parse_line(LINE, tz=timezone(timedelta(hours=2)))
    assert (e.service, e.ip, e.method, e.path, e.status) == ("gitea", ATTACKER, "POST", "/user/sign_up", 403)
    assert e.ts == 1792681982.0           # 2026-10-22 15:13:02 UTC
    assert e.raw == LINE


def test_parse_strips_query_ipv6_and_honours_explicit_ts():
    line = LINE.replace("/user/sign_up", "/api/v1/repos/search?limit=20&q=x").replace(ATTACKER + ":33978", "[2001:db8::7]:5555")
    e = gitea.parse_line(line, ts=123.0)
    assert (e.path, e.ip, e.ts) == ("/api/v1/repos/search", "2001:db8::7", 123.0)


@pytest.mark.parametrize("line", ["", "garbage", "2026/10/22 17:13:02 cmd/web.go:1 [I] Starting server",
                                  "2026/10/22 17:13:02 HTTPRequest [I] router: started GET / for 1.2.3.4:5"])
def test_parse_ignores_other_lines(line):
    assert gitea.parse_line(line) is None


# ── shipped Gitea rules, on synthetic traffic ─────────────────────────────────

def test_low_and_slow_signup_attempts_are_caught():
    """The real attacker made ~1 attempt per 30 minutes: invisible to a burst rule."""
    eng = shipped_engine()
    alerts = fire(eng, [ev(i * 1800, path="/user/sign_up", status=403) for i in range(5)])
    assert [a.rule for a in alerts] == ["gitea_signup_attempts"]
    assert alerts[0].severity == "medium"


def test_signup_burst_and_success():
    eng = shipped_engine()
    burst = fire(eng, [ev(i, path="/user/sign_up", status=403) for i in range(10)])
    assert {"gitea_signup_flood", "gitea_signup_attempts"} <= {a.rule for a in burst}
    created = fire(eng, [ev(5000, ip="203.0.113.99", path="/user/sign_up", status=303)])
    assert [(a.rule, a.severity) for a in created] == [("gitea_signup_success", "critical")]


def test_login_bruteforce_and_slow_failures():
    eng = shipped_engine()
    assert "gitea_login_bruteforce" in {a.rule for a in fire(eng, [ev(i) for i in range(5)])}
    slow = shipped_engine()
    assert [a.rule for a in fire(slow, [ev(i * 3600) for i in range(3)])] == ["gitea_login_failures"]


def test_admin_panel_persistence_and_recon_from_untrusted_ip():
    eng = shipped_engine()
    admin = fire(eng, [ev(0, ip=OWNER, method="GET", path="/-/admin/users", status=200)])
    assert [(a.rule, a.severity) for a in admin] == [("gitea_admin_untrusted", "critical")]
    token = fire(eng, [ev(10, ip=OWNER, path="/user/settings/applications", status=303),
                       ev(11, ip="203.0.113.50", path="/someone/repo/settings/hooks/gitea", status=303)])
    assert [a.rule for a in token].count("gitea_persistence") == 2
    scan = fire(eng, [ev(i, ip="203.0.113.60", method="GET", path="/api/v1/version", status=200) for i in range(10)])
    assert [(a.rule, a.severity) for a in scan] == [("gitea_recon", "low")]


def test_normal_use_by_the_owner_and_the_lan_stays_silent():
    eng = shipped_engine(extra_trusted=[OWNER])
    traffic = []
    for i in range(200):                      # git over HTTP, API polling, web UI, Jenkins webhooks
        traffic += [ev(i, ip=OWNER, method="POST", path="/roberto/cnds.git/git-upload-pack", status=200),
                    ev(i, ip="192.168.1.147", method="GET", path="/api/v1/version", status=200),
                    ev(i, ip="172.19.0.1", method="POST", path="/user/login", status=303),
                    ev(i, ip=OWNER, method="GET", path="/-/admin/users", status=200),
                    ev(i, ip=OWNER, method="POST", path="/user/settings/applications", status=303),
                    ev(i, ip="192.168.1.14", method="GET", path="/missing", status=404)]
    assert fire(eng, traffic) == []


# ── replay ────────────────────────────────────────────────────────────────────

def test_replay_orders_events_and_reports(tmp_path, capsys):
    lines = [LINE.replace("17:13:02", f"17:{m:02d}:00") for m in (59, 10, 30, 20, 40)]   # out of order
    log = tmp_path / "gitea.log"
    log.write_text("\n".join(lines) + "\nnot a gitea line\n")
    assert replay_main([str(log), "--tz", "UTC", "--trusted", "10.0.0.0/8"]) == 0
    out = capsys.readouterr()
    assert "gitea_signup_attempts" in out.out and ATTACKER in out.out and "1 alert(s)" in out.err


def test_replay_function_returns_alerts():
    eng = shipped_engine()
    lines = [LINE.replace("17:13:02", f"17:{m:02d}:00") for m in range(5)]
    assert [a.rule for a in replay(lines, "gitea", eng)] == ["gitea_signup_attempts"]
