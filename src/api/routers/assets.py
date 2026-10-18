"""GET /api/assets — LAN asset inventory with classification and risk (cnds#13)."""

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ...timeutils import utcnow
from ..auth import require_role
from ..database import get_db
from ..models import Alert, HostProfile

router = APIRouter(prefix="/api", tags=["assets"])

NEW_HOST_WINDOW = timedelta(hours=24)
# Points per alert by severity; the sum is capped at 100.
_SEVERITY_POINTS = {"low": 1, "medium": 3, "high": 7, "critical": 15}


def risk_score(severity_counts: dict) -> int:
    return min(100, sum(_SEVERITY_POINTS.get(sev, 0) * n for sev, n in severity_counts.items()))


async def alert_stats_for(db: AsyncSession, ips) -> dict:
    """{ip: {severity: count}} for the given source IPs."""
    if not ips:
        return {}
    rows = (await db.execute(
        select(Alert.src_ip, Alert.severity, func.count(Alert.id))
        .where(Alert.src_ip.in_(list(ips))).group_by(Alert.src_ip, Alert.severity)
    )).all()
    out: dict = {}
    for ip, sev, n in rows:
        out.setdefault(ip, {})[sev.value if hasattr(sev, "value") else sev] = n
    return out


@router.get("/assets", dependencies=[Depends(require_role("admin", "analyst", "viewer"))])
async def list_assets(
    classification: Optional[str] = Query(None, pattern="^(server|workstation|iot|unknown)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = select(HostProfile)
    count_q = select(func.count(HostProfile.id))
    if classification:
        q = q.where(HostProfile.classification == classification)
        count_q = count_q.where(HostProfile.classification == classification)
    total = (await db.execute(count_q)).scalar() or 0
    hosts = (await db.execute(q.order_by(desc(HostProfile.last_seen)).offset(offset).limit(limit))).scalars().all()
    stats = await alert_stats_for(db, [h.ip for h in hosts])
    now = utcnow()
    return {
        "total": total,
        "assets": [
            {
                "ip": h.ip,
                "classification": h.classification,
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
                "is_new": now - h.first_seen <= NEW_HOST_WINDOW,
                "alert_count": sum(stats.get(h.ip, {}).values()),
                "risk_score": risk_score(stats.get(h.ip, {})),
                "flows_out": h.flows_out,
                "flows_in": h.flows_in,
            }
            for h in hosts
        ],
    }
