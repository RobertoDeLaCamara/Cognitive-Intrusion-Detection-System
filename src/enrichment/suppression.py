"""Alert suppression rules (Phase 8).

Analysts can create temporary suppression filters to silence alerts
during maintenance windows or known-benign activity.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert, SuppressionRule

logger = logging.getLogger(__name__)


async def is_suppressed(alert: Alert, db: AsyncSession) -> bool:
    """Check if an alert matches any active suppression rule."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(SuppressionRule).where(SuppressionRule.expires_at > now)
    )
    rules = result.scalars().all()

    for rule in rules:
        if rule.src_ip and rule.src_ip != alert.src_ip:
            continue
        if rule.dst_ip and rule.dst_ip != alert.dst_ip:
            continue
        if rule.attack_type and rule.attack_type != alert.attack_type:
            continue
        if rule.min_severity:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            alert_sev = severity_order.get(alert.severity.value if hasattr(alert.severity, 'value') else alert.severity, 0)
            rule_sev = severity_order.get(rule.min_severity, 0)
            # Skip this rule if alert severity exceeds the suppression ceiling
            if alert_sev > rule_sev:
                continue
        logger.debug("Alert suppressed by rule #%d: %s", rule.id, rule.reason)
        return True
    return False


async def cleanup_expired(db: AsyncSession) -> int:
    """Remove expired suppression rules. Returns count deleted."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        delete(SuppressionRule).where(SuppressionRule.expires_at <= now)
    )
    await db.commit()
    return result.rowcount
