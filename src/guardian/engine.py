"""Guardian auto-response engine (Phase 10).

Two background asyncio tasks, started from src/api/main.py's lifespan when
GUARDIAN_ENABLED=true:

  guardian_loop()        — polls for new high-severity alerts and blocks the
                            offending src_ip via a MitigationBackend, unless
                            it's whitelisted, already has an active action,
                            or the circuit breaker has tripped.
  guardian_expiry_loop() — auto-unblocks any pending action past expires_at.

Deliberately does NOT hook into src/pipeline.py's capture path — it only
reads src_ip out of the alerts table that pipeline.py already writes to, so
the packet-capture worker threads are never touched.
"""

import asyncio
import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy import select, func

from ..api.database import AsyncSessionLocal
from ..api.models import Alert, MitigationAction, MitigationStatus
from ..enrichment.ip_lists import _matches
from ..enrichment.notifications import notify_alert
from ..timeutils import utcnow
from ..config import (
    GUARDIAN_MIN_SEVERITY,
    GUARDIAN_POLL_INTERVAL_SECS,
    GUARDIAN_BLOCK_MINUTES,
    GUARDIAN_WHITELIST,
    GUARDIAN_CIRCUIT_MAX_ACTIONS,
    GUARDIAN_CIRCUIT_WINDOW_SECS,
    TELEGRAM_BOT_TOKEN,
)
from .backends import AdGuardBackend
from .telegram_listener import send_action_notice

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_backend = AdGuardBackend()
_last_seen_alert_id: Optional[int] = None
_circuit_paused_notified = False


def _severity_value(severity) -> int:
    raw = severity.value if hasattr(severity, "value") else severity
    return _SEVERITY_ORDER.get(raw, 0)


async def _init_last_seen_id() -> None:
    """On first run, skip every alert that already exists — only react to new ones."""
    global _last_seen_alert_id
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(func.max(Alert.id)))
        _last_seen_alert_id = result.scalar() or 0


async def _has_active_action(db, src_ip: str) -> bool:
    result = await db.execute(
        select(MitigationAction.id).where(
            MitigationAction.src_ip == src_ip,
            MitigationAction.status == MitigationStatus.PENDING,
        ).limit(1)
    )
    return result.scalar() is not None


async def _circuit_breaker_tripped(db) -> bool:
    global _circuit_paused_notified
    since = utcnow() - timedelta(seconds=GUARDIAN_CIRCUIT_WINDOW_SECS)
    result = await db.execute(
        select(func.count(MitigationAction.id)).where(MitigationAction.created_at > since)
    )
    count = result.scalar() or 0
    if count >= GUARDIAN_CIRCUIT_MAX_ACTIONS:
        if not _circuit_paused_notified:
            logger.warning(
                "Guardian circuit breaker tripped: %d actions in the last %ds — pausing auto-block",
                count, GUARDIAN_CIRCUIT_WINDOW_SECS,
            )
            await notify_alert({
                "severity": "critical",
                "src_ip": "guardian",
                "dst_ip": "-",
                "attack_type": (
                    f"Guardian paused: {count} auto-blocks in the last "
                    f"{GUARDIAN_CIRCUIT_WINDOW_SECS}s (threshold {GUARDIAN_CIRCUIT_MAX_ACTIONS})"
                ),
                "ensemble_score": 1.0,
                "triggered_rules": [],
            })
            _circuit_paused_notified = True
        return True
    _circuit_paused_notified = False
    return False


async def guardian_loop() -> None:
    global _last_seen_alert_id
    await _init_last_seen_id()
    logger.info("Guardian loop started (last_seen_alert_id=%s)", _last_seen_alert_id)
    while True:
        await asyncio.sleep(GUARDIAN_POLL_INTERVAL_SECS)
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(Alert).where(Alert.id > _last_seen_alert_id).order_by(Alert.id)
                )
                alerts = list(result.scalars().all())
                if not alerts:
                    continue
                _last_seen_alert_id = alerts[-1].id

                # Advancing _last_seen_alert_id above even when paused is intentional:
                # once the breaker trips, this batch is deliberately not replayed later.
                if await _circuit_breaker_tripped(db):
                    continue

                for alert in alerts:
                    if _severity_value(alert.severity) < _SEVERITY_ORDER.get(GUARDIAN_MIN_SEVERITY, 3):
                        continue
                    if not alert.src_ip:
                        continue
                    if _matches(alert.src_ip, GUARDIAN_WHITELIST):
                        logger.debug("Guardian: %s is whitelisted, skipping", alert.src_ip)
                        continue
                    if await _has_active_action(db, alert.src_ip):
                        continue

                    reason = f"{alert.attack_type or 'unknown'} (score={alert.ensemble_score})"
                    try:
                        await _backend.block(alert.src_ip, reason)
                    except Exception as e:
                        logger.error("Guardian: block(%s) failed: %s", alert.src_ip, e)
                        continue

                    action = MitigationAction(
                        src_ip=alert.src_ip,
                        action_type="dns_block",
                        backend="adguard",
                        status=MitigationStatus.PENDING,
                        reason=reason,
                        alert_id=alert.id,
                        expires_at=utcnow() + timedelta(minutes=GUARDIAN_BLOCK_MINUTES),
                    )
                    db.add(action)
                    await db.commit()
                    logger.info(
                        "Guardian: blocked %s for %d min (alert #%d, %s)",
                        alert.src_ip, GUARDIAN_BLOCK_MINUTES, alert.id, reason,
                    )

                    if TELEGRAM_BOT_TOKEN:
                        await send_action_notice(action)
                    else:
                        await notify_alert({
                            "severity": "critical",
                            "src_ip": alert.src_ip,
                            "dst_ip": alert.dst_ip,
                            "attack_type": f"Guardian auto-block: {reason}",
                            "ensemble_score": alert.ensemble_score,
                            "triggered_rules": [],
                        })
        except Exception as e:
            logger.error("Guardian loop error: %s", e)


async def guardian_expiry_loop() -> None:
    while True:
        await asyncio.sleep(GUARDIAN_POLL_INTERVAL_SECS)
        try:
            async with AsyncSessionLocal() as db:
                now = utcnow()
                result = await db.execute(
                    select(MitigationAction).where(
                        MitigationAction.status == MitigationStatus.PENDING,
                        MitigationAction.expires_at.is_not(None),
                        MitigationAction.expires_at < now,
                    )
                )
                for action in result.scalars().all():
                    try:
                        await _backend.unblock(action.src_ip)
                    except Exception as e:
                        logger.error("Guardian: unblock(%s) failed: %s", action.src_ip, e)
                        continue
                    action.status = MitigationStatus.EXPIRED
                    action.resolved_at = now
                    logger.info("Guardian: auto-unblocked %s (action #%d expired)", action.src_ip, action.id)
                await db.commit()
        except Exception as e:
            logger.error("Guardian expiry loop error: %s", e)
