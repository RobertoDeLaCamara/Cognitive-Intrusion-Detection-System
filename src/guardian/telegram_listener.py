"""Telegram inline-button listener for guardian mitigation actions (Phase 10).

Only runs when TELEGRAM_BOT_TOKEN is set. Uses long-polling against
getUpdates rather than a webhook: this homelab has no public HTTPS endpoint
reachable from Telegram's servers (WSL2/consumer-router constraints), but
outbound HTTPS to api.telegram.org works fine, so polling is the only
viable transport here.
"""

import asyncio
import logging

import httpx
from sqlalchemy import select

from ..api.database import AsyncSessionLocal
from ..api.models import MitigationAction, MitigationStatus
from ..config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
from ..timeutils import utcnow
from .backends import AdGuardBackend

logger = logging.getLogger(__name__)

_API = "https://api.telegram.org/bot{token}/{method}"
_backend = AdGuardBackend()


async def send_action_notice(action: MitigationAction) -> None:
    """Notify about a new auto-block with inline Confirm/Undo buttons."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    text = (
        f"🛡 *Guardian auto\\-block*\n"
        f"IP: `{action.src_ip}`\n"
        f"Reason: {action.reason}\n"
        f"Auto\\-rollback in {int((action.expires_at - utcnow()).total_seconds() // 60)} min "
        f"unless confirmed"
    )
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "MarkdownV2",
        "reply_markup": {
            "inline_keyboard": [[
                {"text": "✅ Confirm (make permanent)", "callback_data": f"confirm:{action.id}"},
                {"text": "↩️ Undo now", "callback_data": f"undo:{action.id}"},
            ]]
        },
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(_API.format(token=TELEGRAM_BOT_TOKEN, method="sendMessage"), json=payload)
            if resp.status_code >= 400:
                logger.warning("Telegram sendMessage returned %d: %s", resp.status_code, resp.text)
        except Exception as e:
            logger.error("Telegram sendMessage failed: %s", e)


async def _answer_callback(client: httpx.AsyncClient, callback_id: str, text: str) -> None:
    try:
        await client.post(
            _API.format(token=TELEGRAM_BOT_TOKEN, method="answerCallbackQuery"),
            json={"callback_query_id": callback_id, "text": text},
        )
    except Exception as e:
        logger.error("Telegram answerCallbackQuery failed: %s", e)


async def _handle_callback(client: httpx.AsyncClient, callback: dict) -> None:
    data = callback.get("data", "")
    callback_id = callback.get("id", "")
    if ":" not in data:
        return
    op, _, raw_id = data.partition(":")
    try:
        action_id = int(raw_id)
    except ValueError:
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(MitigationAction).where(MitigationAction.id == action_id))
        action = result.scalar_one_or_none()
        if action is None or action.status != MitigationStatus.PENDING:
            await _answer_callback(client, callback_id, "No longer pending.")
            return

        if op == "confirm":
            action.status = MitigationStatus.CONFIRMED
            action.expires_at = None
            action.resolved_at = utcnow()
            await db.commit()
            await _answer_callback(client, callback_id, f"Confirmed — {action.src_ip} stays blocked.")
        elif op == "undo":
            try:
                await _backend.unblock(action.src_ip)
            except Exception as e:
                logger.error("Telegram undo: unblock(%s) failed: %s", action.src_ip, e)
                await _answer_callback(client, callback_id, "Undo failed, see logs.")
                return
            action.status = MitigationStatus.UNDONE
            action.resolved_at = utcnow()
            await db.commit()
            await _answer_callback(client, callback_id, f"Undone — {action.src_ip} unblocked.")


async def telegram_listener_loop() -> None:
    if not TELEGRAM_BOT_TOKEN:
        return
    logger.info("Telegram listener started")
    offset = 0
    async with httpx.AsyncClient(timeout=35.0) as client:
        while True:
            try:
                resp = await client.get(
                    _API.format(token=TELEGRAM_BOT_TOKEN, method="getUpdates"),
                    params={"offset": offset, "timeout": 30, "allowed_updates": '["callback_query"]'},
                )
                resp.raise_for_status()
                updates = resp.json().get("result", [])
                for update in updates:
                    offset = update["update_id"] + 1
                    callback = update.get("callback_query")
                    if callback:
                        await _handle_callback(client, callback)
            except Exception as e:
                logger.error("Telegram listener error: %s", e)
                await asyncio.sleep(5)
