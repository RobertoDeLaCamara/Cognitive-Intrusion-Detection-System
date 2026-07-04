"""Alert correlation — groups related alerts into auto-incidents (Phase 8)."""

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert, Incident, SeverityLevel, IncidentStatus
from ..config import CORRELATION_WINDOW_SECS, CORRELATION_THRESHOLD
from ..timeutils import utcnow

logger = logging.getLogger(__name__)


async def correlate_alert(alert: Alert, db: AsyncSession) -> Optional[int]:
    """Check if this alert should be grouped into an existing or new incident.

    Returns incident_id if correlated, None otherwise.
    """
    cutoff = utcnow() - timedelta(seconds=CORRELATION_WINDOW_SECS)

    # Count recent alerts from same src_ip
    result = await db.execute(
        select(Alert).where(
            Alert.src_ip == alert.src_ip,
            Alert.timestamp >= cutoff,
            Alert.id != alert.id,
        )
    )
    recent = result.scalars().all()

    if len(recent) < CORRELATION_THRESHOLD - 1:
        return None

    # Check if there's already an open incident for this IP
    inc_result = await db.execute(
        select(Incident).where(
            Incident.title.contains(alert.src_ip),
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]),
        ).order_by(desc(Incident.created_at)).limit(1)
    )
    existing = inc_result.scalar_one_or_none()

    if existing:
        alert.incident_id = existing.id
        return existing.id

    # Create new auto-incident
    incident = Incident(
        title=f"Correlated attack from {alert.src_ip}",
        description=f"Auto-created: {len(recent) + 1} alerts from {alert.src_ip} within {CORRELATION_WINDOW_SECS}s",
        severity=alert.severity,
    )
    db.add(incident)
    await db.flush()

    # Link all recent alerts + current
    alert.incident_id = incident.id
    for a in recent:
        if a.incident_id is None:
            a.incident_id = incident.id

    logger.info("Auto-incident #%d created for %s (%d alerts)",
                incident.id, alert.src_ip, len(recent) + 1)
    return incident.id
