"""Alert and incident CRUD endpoints."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Alert, Incident, SeverityLevel, IncidentStatus, SuppressionRule
from ..schemas import (
    AlertOut, AlertUpdate, IncidentCreate, IncidentOut, IncidentUpdate,
    SuppressionRuleCreate, SuppressionRuleOut,
)
from ..auth import require_role
from ...timeutils import utcnow

router = APIRouter(prefix="/api", tags=["alerts"])

# Role policy when JWT auth is enabled (a no-op otherwise, see auth.require_role):
#   read routes  -> any authenticated role
#   write routes -> analyst or admin; destructive/admin routes -> admin
_READ = Depends(require_role("admin", "analyst", "viewer"))
_WRITE = Depends(require_role("admin", "analyst"))

# Upper bound for `hours` filters (10 years); larger values overflow timedelta/datetime.
MAX_HOURS = 24 * 365 * 10

# Spreadsheets run cells that start with these characters as formulas (CWE-1236).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise CSV/formula injection: prefix a quote to text a spreadsheet would execute.

    Only strings are touched; numbers and booleans pass through unchanged.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalise to naive UTC (naive input is assumed UTC)."""
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@router.get("/alerts", response_model=List[AlertOut], dependencies=[_READ])
async def list_alerts(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    src_ip: Optional[str] = None,
    start: Optional[datetime] = Query(
        None, description="Inclusive lower bound (ISO 8601). Naive values are UTC."),
    end: Optional[datetime] = Query(
        None, description="Inclusive upper bound (ISO 8601). Naive values are UTC."),
    hours: Optional[int] = Query(
        None, ge=1, le=MAX_HOURS,
        description=f"Only alerts from the last N hours (max {MAX_HOURS})."),
    db: AsyncSession = Depends(get_db),
):
    start = _to_naive_utc(start)
    end = _to_naive_utc(end)
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")

    q = select(Alert).order_by(desc(Alert.timestamp))
    if severity:
        q = q.where(Alert.severity == severity)
    if acknowledged is not None:
        q = q.where(Alert.acknowledged == acknowledged)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    if start is not None:
        q = q.where(Alert.timestamp >= start)
    if end is not None:
        q = q.where(Alert.timestamp <= end)
    if hours:
        q = q.where(Alert.timestamp >= utcnow() - timedelta(hours=hours))
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/alerts/export", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_alerts(
    format: str = Query("json", pattern="^(json|csv)$"),
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    hours: Optional[int] = Query(None, ge=1, le=MAX_HOURS),
    limit: int = Query(1000, le=10000),
    db: AsyncSession = Depends(get_db),
):
    """Export alerts as JSON or CSV for analyst reporting."""
    from datetime import timedelta
    from fastapi.responses import StreamingResponse
    import csv
    import io
    import json

    q = select(Alert).order_by(desc(Alert.timestamp)).limit(limit)
    if severity:
        q = q.where(Alert.severity == severity)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    if hours:
        cutoff = utcnow() - timedelta(hours=hours)
        q = q.where(Alert.timestamp >= cutoff)

    result = await db.execute(q)
    alerts = result.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                         "protocol", "attack_type", "severity", "ensemble_score",
                         "triggered_rules", "acknowledged"])
        for a in alerts:
            writer.writerow([_csv_safe(cell) for cell in [
                a.id, a.timestamp.isoformat() if a.timestamp else "",
                a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.protocol,
                a.attack_type, a.severity.value if a.severity else "",
                a.ensemble_score, ";".join(a.triggered_rules or []), a.acknowledged,
            ]])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )

    # JSON format
    data = [{
        "id": a.id,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "src_port": a.src_port,
        "dst_port": a.dst_port,
        "protocol": a.protocol,
        "attack_type": a.attack_type,
        "severity": a.severity.value if a.severity else None,
        "ensemble_score": a.ensemble_score,
        "engine_scores": a.engine_scores,
        "triggered_rules": a.triggered_rules,
        "acknowledged": a.acknowledged,
        "notes": a.notes,
        "src_geo": a.src_geo,
        "mitre_techniques": a.mitre_techniques,
    } for a in alerts]

    output = io.StringIO()
    json.dump(data, output, indent=2, default=str)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=alerts.json"},
    )


@router.get("/alerts/trends", dependencies=[_READ])
async def alert_trends(
    hours: int = Query(24, ge=1, le=168),
    bucket: str = Query("hour", pattern="^(hour|day)$"),
    db: AsyncSession = Depends(get_db),
):
    """Return alert counts bucketed by hour or day."""
    from datetime import timedelta
    cutoff = utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(Alert.timestamp, Alert.severity).where(Alert.timestamp >= cutoff)
    )
    rows = result.all()

    buckets: dict = {}
    for ts, sev in rows:
        if bucket == "hour":
            key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        else:
            key = ts.strftime("%Y-%m-%dT00:00:00Z")
        if key not in buckets:
            buckets[key] = {"total": 0, "by_severity": {}}
        buckets[key]["total"] += 1
        sev_val = sev.value if hasattr(sev, "value") else sev
        buckets[key]["by_severity"][sev_val] = buckets[key]["by_severity"].get(sev_val, 0) + 1

    return {"bucket": bucket, "hours": hours, "data": buckets}


@router.get("/alerts/{alert_id}", response_model=AlertOut, dependencies=[_READ])
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut, dependencies=[_WRITE])
async def update_alert(
    alert_id: int,
    body: AlertUpdate,
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.acknowledged is not None:
        alert.acknowledged = body.acknowledged
    if body.label is not None:
        alert.label = body.label
    if body.notes is not None:
        alert.notes = body.notes
    if body.incident_id is not None:
        alert.incident_id = body.incident_id
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/incidents", response_model=List[IncidentOut], dependencies=[_READ])
async def list_incidents(
    limit: int = Query(20, le=200),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident).order_by(desc(Incident.created_at)).limit(limit)
    if status:
        q = q.where(Incident.status == status)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/incidents", response_model=IncidentOut, status_code=201,
              dependencies=[Depends(require_role("admin", "analyst"))])
async def create_incident(body: IncidentCreate, db: AsyncSession = Depends(get_db)):
    inc = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        assigned_to=body.assigned_to,
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)
    return inc


# open -> investigating -> resolved -> closed; a status may only move forward (skipping steps is fine).
_INCIDENT_ORDER = {s: i for i, s in enumerate(
    (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED))}


@router.patch("/incidents/{incident_id}", response_model=IncidentOut, dependencies=[_WRITE])
async def update_incident(incident_id: int, body: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    inc = await db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body.status is not None:
        new = IncidentStatus(body.status)
        current = inc.status or IncidentStatus.OPEN
        if _INCIDENT_ORDER[new] < _INCIDENT_ORDER[current]:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot move an incident from {current.value} back to {new.value}",
            )
        inc.status = new
        if _INCIDENT_ORDER[new] >= _INCIDENT_ORDER[IncidentStatus.RESOLVED] and inc.resolved_at is None:
            inc.resolved_at = utcnow()
    if body.notes is not None:
        inc.notes = body.notes
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    await db.commit()
    await db.refresh(inc)
    return inc


@router.get("/stats", dependencies=[_READ])
async def stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func, case
    result = await db.execute(
        select(
            func.count(Alert.id).label("total"),
            func.count(case((Alert.acknowledged == False, 1))).label("unacked"),
            *[
                func.count(case((Alert.severity == sev, 1))).label(sev.value)
                for sev in SeverityLevel
            ],
        )
    )
    row = result.one()
    return {
        "total_alerts": row.total,
        "unacknowledged": row.unacked,
        "by_severity": {sev.value: getattr(row, sev.value) for sev in SeverityLevel},
    }


# ── Suppression Rules (Phase 8) ───────────────────────────────────────────────

@router.get("/suppression-rules", response_model=List[SuppressionRuleOut], dependencies=[_READ])
async def list_suppression_rules(db: AsyncSession = Depends(get_db)):
    now = utcnow()
    result = await db.execute(
        select(SuppressionRule).where(SuppressionRule.expires_at > now)
    )
    return result.scalars().all()


@router.post("/suppression-rules", response_model=SuppressionRuleOut, status_code=201,
              dependencies=[Depends(require_role("admin", "analyst"))])
async def create_suppression_rule(
    body: SuppressionRuleCreate,
    db: AsyncSession = Depends(get_db),
):
    from datetime import timedelta
    from ...enrichment.suppression import invalidate_cache
    rule = SuppressionRule(
        src_ip=body.src_ip,
        dst_ip=body.dst_ip,
        attack_type=body.attack_type,
        min_severity=body.min_severity,
        reason=body.reason,
        expires_at=utcnow() + timedelta(minutes=body.duration_minutes),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    invalidate_cache()
    return rule


@router.delete("/suppression-rules/{rule_id}", status_code=204,
               dependencies=[Depends(require_role("admin"))])
async def delete_suppression_rule(rule_id: int, db: AsyncSession = Depends(get_db)):
    from ...enrichment.suppression import invalidate_cache
    rule = await db.get(SuppressionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    await db.delete(rule)
    await db.commit()
    invalidate_cache()


# ── Adaptive Weights (Phase 8) ────────────────────────────────────────────────

@router.get("/adaptive-weights", dependencies=[_READ])
async def get_adaptive_weights(db: AsyncSession = Depends(get_db)):
    from ...enrichment.adaptive_weights import compute_adaptive_weights
    weights = await compute_adaptive_weights(db)
    if weights is None:
        return {"status": "insufficient_data", "weights": None}
    return {"status": "ok", "weights": weights}


# ── DNS Logs (Phase 8) ────────────────────────────────────────────────────────

@router.get("/dns-log", dependencies=[_READ])
async def get_dns_logs(src_ip: Optional[str] = None):
    from ...enrichment.dns_logger import get_dns_log, get_all_logs
    if src_ip:
        return {"src_ip": src_ip, "queries": get_dns_log(src_ip)}
    return get_all_logs()
