"""Webhook/Slack/Telegram notifications for critical alerts (Phase 8)."""

import json
import logging
from typing import Dict

import httpx

from ..config import (
    WEBHOOK_URLS, NOTIFY_MIN_SEVERITY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    NTFY_URL, NTFY_TOPIC, NTFY_USER, NTFY_PASSWORD, NTFY_TOKEN, DASHBOARD_URL,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

# ntfy priorities: 1 min .. 5 max (5 bypasses do-not-disturb on the phone).
_NTFY_PRIORITY = {"low": 2, "medium": 3, "high": 4, "critical": 5}
_NTFY_TAG = {"low": "information_source", "medium": "eyes", "high": "warning", "critical": "rotating_light"}


def _format_message(alert_data: Dict) -> str:
    severity = alert_data.get("severity", "low")
    return (
        f"🚨 *CNDS Alert* \\[{severity.upper()}\\]\n"
        f"Source: `{alert_data.get('src_ip', '?')}` → `{alert_data.get('dst_ip', '?')}`\n"
        f"Score: {alert_data.get('ensemble_score', 0):.3f}\n"
        f"Type: {alert_data.get('attack_type', 'unknown')}\n"
        f"Rules: {', '.join(alert_data.get('triggered_rules', []))}"
    )


async def _send_telegram(client: httpx.AsyncClient, message: str) -> None:
    """Send a message via Telegram Bot API."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = _TELEGRAM_API.format(token=TELEGRAM_BOT_TOKEN)
    try:
        resp = await client.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "MarkdownV2",
        })
        if resp.status_code >= 400:
            logger.warning("Telegram returned %d: %s", resp.status_code, resp.text)
    except Exception as e:
        logger.error("Telegram notification failed: %s", e)


def _ntfy_payload(alert_data: Dict) -> Dict:
    """JSON publish body (UTF-8 safe, unlike header-based publishing)."""
    severity = alert_data.get("severity", "low")
    attack = alert_data.get("attack_type") or "unknown"
    src, dst = alert_data.get("src_ip", "?"), alert_data.get("dst_ip")
    lines = [f"{src} -> {dst}" if dst and dst != "-" else str(src)]
    if alert_data.get("ensemble_score") is not None:
        lines.append(f"Score {alert_data['ensemble_score']:.2f}")
    if alert_data.get("triggered_rules"):
        lines.append("Rules: " + ", ".join(alert_data["triggered_rules"]))
    tags = [_NTFY_TAG.get(severity, "warning")]
    if alert_data.get("source"):
        tags.append(str(alert_data["source"]))
    payload = {
        "topic": NTFY_TOPIC,
        "title": f"CNDS {severity.upper()}: {attack}",
        "message": "\n".join(lines),
        "priority": _NTFY_PRIORITY.get(severity, 3),
        "tags": tags,
    }
    if DASHBOARD_URL and alert_data.get("id"):
        payload["click"] = f"{DASHBOARD_URL}/alert?id={alert_data['id']}"
    return payload


async def _send_ntfy(client: httpx.AsyncClient, alert_data: Dict) -> None:
    """Publish to ntfy. Never raises: a down push server must not break alerting."""
    headers = {}
    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
    auth = (NTFY_USER, NTFY_PASSWORD) if NTFY_USER and not NTFY_TOKEN else None
    try:
        resp = await client.post(NTFY_URL, json=_ntfy_payload(alert_data), headers=headers, auth=auth)
        if resp.status_code >= 400:
            logger.warning("ntfy returned %d: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        logger.error("ntfy notification failed: %s", e)


async def notify_alert(alert_data: Dict) -> None:
    """Send alert to all configured channels if severity meets threshold."""
    severity = alert_data.get("severity", "low")
    if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(NOTIFY_MIN_SEVERITY, 2):
        return

    has_webhooks = bool(WEBHOOK_URLS)
    has_telegram = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    has_ntfy = bool(NTFY_URL)

    if not has_webhooks and not has_telegram and not has_ntfy:
        return

    message = _format_message(alert_data)

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Webhooks (Slack, generic) — only send safe summary fields
        if has_webhooks:
            payload = {
                "text": message,
                "src_ip": alert_data.get("src_ip"),
                "dst_ip": alert_data.get("dst_ip"),
                "severity": alert_data.get("severity"),
                "attack_type": alert_data.get("attack_type"),
                "ensemble_score": alert_data.get("ensemble_score"),
                "timestamp": alert_data.get("timestamp"),
            }
            for url in WEBHOOK_URLS:
                try:
                    resp = await client.post(
                        url, json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code >= 400:
                        logger.warning("Webhook %s returned %d", url, resp.status_code)
                except Exception as e:
                    logger.error("Webhook %s failed: %s", url, e)

        # Telegram
        if has_telegram:
            await _send_telegram(client, message)

        if has_ntfy:
            await _send_ntfy(client, alert_data)
