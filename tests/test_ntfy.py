"""ntfy notification channel (fake server over httpx.MockTransport, no network)."""

import base64
import json
from unittest.mock import patch

import httpx
import pytest

from src.enrichment import notifications as n

REAL_CLIENT = httpx.AsyncClient     # patching httpx.AsyncClient is global; keep the real class for the fakes

ALERT = {"id": 7, "severity": "critical", "src_ip": "203.0.113.7", "dst_ip": "192.168.1.10",
         "attack_type": "Web Attack – Brute Force", "ensemble_score": 0.93,
         "triggered_rules": ["ssh_bruteforce", "syn_scan"], "source": "logwatch"}


class FakeNtfy:
    def __init__(self, status=200, error=None):
        self.requests, self.status, self.error = [], status, error

    def handler(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return httpx.Response(self.status, text="ok")

    def client_factory(self):
        return lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(self.handler))


def cfg(**over):
    base = dict(NTFY_URL="http://ntfy:2586", NTFY_TOPIC="cnds-alerts", NTFY_USER="", NTFY_PASSWORD="",
                NTFY_TOKEN="", DASHBOARD_URL="", WEBHOOK_URLS=[], TELEGRAM_BOT_TOKEN="", TELEGRAM_CHAT_ID="",
                NOTIFY_MIN_SEVERITY="high")
    base.update(over)
    return [patch(f"src.enrichment.notifications.{k}", v) for k, v in base.items()]


async def notify(fake, alert, **over):
    patches = cfg(**over)
    for p in patches:
        p.start()
    try:
        with patch("src.enrichment.notifications.httpx.AsyncClient", fake.client_factory()):
            await n.notify_alert(alert)
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_publishes_json_with_priority_tags_and_utf8_title():
    fake = FakeNtfy()
    await notify(fake, ALERT)
    assert len(fake.requests) == 1
    req = fake.requests[0]
    assert req.method == "POST" and req.url.host == "ntfy" and req.url.port == 2586 and req.url.path in ("", "/")
    body = json.loads(req.content)
    assert body["topic"] == "cnds-alerts" and body["priority"] == 5
    assert body["title"] == "CNDS CRITICAL: Web Attack – Brute Force"          # non-ASCII survives
    assert body["tags"] == ["rotating_light", "logwatch"]
    assert body["message"].splitlines() == ["203.0.113.7 -> 192.168.1.10", "Score 0.93", "Rules: ssh_bruteforce, syn_scan"]
    assert "click" not in body and "authorization" not in req.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("severity, priority", [("high", 4), ("critical", 5)])
async def test_priority_follows_severity(severity, priority):
    fake = FakeNtfy()
    await notify(fake, {**ALERT, "severity": severity})
    assert json.loads(fake.requests[0].content)["priority"] == priority


@pytest.mark.asyncio
async def test_click_link_points_to_the_alert_detail_page():
    fake = FakeNtfy()
    await notify(fake, ALERT, DASHBOARD_URL="http://dash:8511")
    assert json.loads(fake.requests[0].content)["click"] == "http://dash:8511/alert?id=7"
    fake2 = FakeNtfy()
    await notify(fake2, {k: v for k, v in ALERT.items() if k != "id"}, DASHBOARD_URL="http://dash:8511")
    assert "click" not in json.loads(fake2.requests[0].content)


@pytest.mark.asyncio
async def test_basic_auth_and_token_auth():
    fake = FakeNtfy()
    await notify(fake, ALERT, NTFY_USER="homelab-writer", NTFY_PASSWORD="s3cret")
    expected = "Basic " + base64.b64encode(b"homelab-writer:s3cret").decode()
    assert fake.requests[0].headers["authorization"] == expected

    tok = FakeNtfy()
    await notify(tok, ALERT, NTFY_USER="u", NTFY_PASSWORD="p", NTFY_TOKEN="tk_abc")
    assert tok.requests[0].headers["authorization"] == "Bearer tk_abc"          # token wins


@pytest.mark.asyncio
async def test_respects_min_severity_and_disabled_state():
    low = FakeNtfy()
    await notify(low, {**ALERT, "severity": "medium"})
    assert low.requests == []
    await notify(low, {**ALERT, "severity": "medium"}, NOTIFY_MIN_SEVERITY="medium")
    assert len(low.requests) == 1
    off = FakeNtfy()
    await notify(off, ALERT, NTFY_URL="")
    assert off.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fake", [FakeNtfy(status=503), FakeNtfy(error=httpx.ConnectError("down"))])
async def test_a_failing_ntfy_never_raises(fake):
    await notify(fake, ALERT)                       # must not raise
    assert len(fake.requests) == 1


@pytest.mark.asyncio
async def test_other_channels_still_fire_when_ntfy_is_down():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if "ntfy" in str(request.url):
            raise httpx.ConnectError("down")
        return httpx.Response(200)

    factory = lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler))   # noqa: E731
    patches = cfg(WEBHOOK_URLS=["http://hook.example/x"])
    for p in patches:
        p.start()
    try:
        with patch("src.enrichment.notifications.httpx.AsyncClient", factory):
            await n.notify_alert(ALERT)
    finally:
        for p in patches:
            p.stop()
    assert any("hook.example" in u for u in seen) and any("ntfy" in u for u in seen)


def test_payload_handles_sparse_alerts():
    with patch("src.enrichment.notifications.DASHBOARD_URL", ""):
        body = n._ntfy_payload({"severity": "high", "src_ip": "guardian", "dst_ip": "-"})
    assert body["message"] == "guardian" and body["title"] == "CNDS HIGH: unknown" and body["priority"] == 4
