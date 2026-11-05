"""Alert suppression rules (Phase 8).

Analysts can create temporary suppression filters to silence alerts
during maintenance windows or known-benign activity.

Rules are cached in memory and refreshed periodically to avoid
querying the database on every alert.
"""

import asyncio
import logging
import time
from typing import List, Optional

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
    return await find_suppressing_rule(alert, db) is not None


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def rule_matches(rule, src_ip, dst_ip, attack_type, severity, dst_port=None, src_port=None) -> bool:
    """True if ``rule`` covers an alert with these fields (unset rule fields match anything)."""
    if rule.src_ip and rule.src_ip != src_ip:
        return False
    if rule.dst_ip and rule.dst_ip != dst_ip:
        return False
    rule_port = getattr(rule, "dst_port", None)
    if rule_port is not None and rule_port != dst_port:
        return False
    rule_src_port = getattr(rule, "src_port", None)
    if rule_src_port is not None and rule_src_port != src_port:
        return False
    if rule.attack_type and rule.attack_type != attack_type:
        return False
    if rule.min_severity:
        sev = severity.value if hasattr(severity, "value") else severity
        if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(rule.min_severity, 0):
            return False
    return True


async def find_suppressing_rule(alert: Alert, db: AsyncSession) -> Optional[SuppressionRule]:
    """Return the first active suppression rule the alert matches, or None."""
    await _refresh_cache(db)

    for rule in _cache:
        if rule_matches(rule, alert.src_ip, alert.dst_ip, alert.attack_type, alert.severity,
                        getattr(alert, "dst_port", None), getattr(alert, "src_port", None)):
            logger.debug("Alert suppressed by rule #%d: %s", rule.id, rule.reason)
            return rule
    return None


async def cleanup_expired(db: AsyncSession) -> int:
    """Remove expired suppression rules. Returns count deleted."""
    now = utcnow()
    result = await db.execute(
        delete(SuppressionRule).where(SuppressionRule.expires_at <= now)
    )
    await db.commit()
    invalidate_cache()
    return result.rowcount
