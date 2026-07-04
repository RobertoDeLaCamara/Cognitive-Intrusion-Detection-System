"""Alert suppression rules (Phase 8).

Analysts can create temporary suppression filters to silence alerts
during maintenance windows or known-benign activity.

Rules are cached in memory and refreshed periodically to avoid
querying the database on every alert.
"""

import asyncio
import logging
import time
from typing import List

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert, SuppressionRule
from ..timeutils import utcnow

logger = logging.getLogger(__name__)

_cache: List[SuppressionRule] = []
_cache_ts: float = 0.0
_CACHE_TTL = 10.0  # seconds
_cache_lock = asyncio.Lock()


async def _refresh_cache(db: AsyncSession) -> None:
    global _cache, _cache_ts
    async with _cache_lock:
        now = time.time()
        if now - _cache_ts < _CACHE_TTL:
            return
        result = await db.execute(
            select(SuppressionRule).where(
                SuppressionRule.expires_at > utcnow()
            )
        )
        _cache = list(result.scalars().all())
        _cache_ts = now


def invalidate_cache() -> None:
    """Force cache refresh on next check (call after create/delete)."""
    global _cache_ts
    _cache_ts = 0.0


async def is_suppressed(alert: Alert, db: AsyncSession) -> bool:
    """Check if an alert matches any active suppression rule."""
    await _refresh_cache(db)

    for rule in _cache:
        if rule.src_ip and rule.src_ip != alert.src_ip:
            continue
        if rule.dst_ip and rule.dst_ip != alert.dst_ip:
            continue
        if rule.attack_type and rule.attack_type != alert.attack_type:
            continue
        if rule.min_severity:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            alert_sev = severity_order.get(
                alert.severity.value if hasattr(alert.severity, 'value') else alert.severity, 0
            )
            rule_sev = severity_order.get(rule.min_severity, 0)
            if alert_sev > rule_sev:
                continue
        logger.debug("Alert suppressed by rule #%d: %s", rule.id, rule.reason)
        return True
    return False


async def cleanup_expired(db: AsyncSession) -> int:
    """Remove expired suppression rules. Returns count deleted."""
    now = utcnow()
    result = await db.execute(
        delete(SuppressionRule).where(SuppressionRule.expires_at <= now)
    )
    await db.commit()
    invalidate_cache()
    return result.rowcount
