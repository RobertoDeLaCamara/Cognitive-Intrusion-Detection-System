"""Triage loop: pick pending alerts, ask the backend, guard, persist.

The runner is the only component that writes, and it writes exactly one
thing: rows in ``triage_annotations``. It never touches ``alerts``
(acknowledgement stays human), ``mitigation_actions`` (the Guardian is the
actuator) or ``suppression_rules``.
"""

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert, SeverityLevel, TriageAnnotation
from ..mcp_server import queries
from ..mcp_server.queries import QueryError
from ..timeutils import utcnow
from .backends import TriageBackend
from .policy import apply_guards
from .prompt import build_prompt
from .schema import validate

logger = logging.getLogger(__name__)

_ORDER = ["low", "medium", "high", "critical"]


def severities_at_least(min_severity: str) -> List[SeverityLevel]:
    if min_severity not in _ORDER:
        raise ValueError(f"invalid severity {min_severity!r}")
    return [SeverityLevel(s) for s in _ORDER[_ORDER.index(min_severity):]]


async def pending_alert_ids(
    db: AsyncSession, min_severity: str, lookback_hours: int, limit: int
) -> List[int]:
    """Unacknowledged alerts at/above ``min_severity`` with no annotation yet, newest first."""
    already = exists().where(TriageAnnotation.alert_id == Alert.id)
    q = (
        select(Alert.id)
        .where(Alert.severity.in_(severities_at_least(min_severity)))
        .where(Alert.acknowledged.is_(False))
        .where(Alert.timestamp >= utcnow() - timedelta(hours=lookback_hours))
        .where(~already)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .limit(limit)
    )
    result = await db.execute(q)
    return [row[0] for row in result.all()]


async def spent_last_24h(db: AsyncSession) -> float:
    q = select(func.coalesce(func.sum(TriageAnnotation.cost_usd), 0.0)).where(
        TriageAnnotation.created_at >= utcnow() - timedelta(hours=24)
    )
    return float((await db.execute(q)).scalar() or 0.0)


async def build_context(db: AsyncSession, alert_id: int) -> Dict[str, Any]:
    """Alert detail plus source-IP profile, through the sanitising MCP query layer."""
    alert = await queries.get_alert(db, alert_id, include_triage=False)
    context: Dict[str, Any] = {"alert": alert}
    src_ip = alert.get("src_ip")
    if src_ip:
        try:
            context["ip_profile"] = await queries.get_ip_profile(db, src_ip, hours=168)
        except QueryError as exc:
            context["ip_profile_error"] = str(exc)
    return context


async def triage_alert(
    db: AsyncSession,
    alert_id: int,
    backend: TriageBackend,
    mode: str,
    min_confidence: float,
) -> TriageAnnotation:
    """Triage one alert and persist the annotation (also on failure)."""
    context = await build_context(db, alert_id)
    prompt = build_prompt(alert_id, mode, context if mode == "workflow" else None)
    result = await backend.run(prompt, mode)

    row = TriageAnnotation(
        alert_id=alert_id,
        mode=mode,
        model=result.model,
        cost_usd=result.cost_usd,
        duration_ms=result.duration_ms,
    )

    if result.output is None:
        row.status = "backend_error"
        row.verdict = "needs_human"
        row.error = (result.error or "no output")[:1000]
    else:
        clean, errors = validate(result.output)
        if errors:
            row.status = "invalid_output"
            row.verdict = "needs_human"
            row.error = "; ".join(errors)[:1000]
        else:
            stored, notes = apply_guards(clean, context, min_confidence)
            row.status = "ok"
            row.model_verdict = clean["verdict"]
            row.verdict = stored["verdict"]
            row.confidence = stored["confidence"]
            row.recommendation = stored["recommendation"]
            row.summary = stored["summary"]
            row.evidence = {
                "facts": stored["evidence"],
                "mitre_techniques": stored.get("mitre_techniques", []),
                "missing_information": stored.get("missing_information", []),
            }
            row.policy_notes = notes or None

    db.add(row)
    await db.commit()
    return row


@dataclass
class RunSummary:
    considered: int = 0
    annotated: int = 0
    errors: int = 0
    skipped_budget: bool = False
    spent_before_usd: float = 0.0
    spent_this_run_usd: float = 0.0
    verdicts: Dict[str, int] = field(default_factory=dict)


async def run_once(
    session_factory,
    backend: TriageBackend,
    mode: str,
    min_severity: str,
    lookback_hours: int,
    batch_size: int,
    min_confidence: float,
    daily_budget_usd: float,
    alert_ids: Optional[List[int]] = None,
) -> RunSummary:
    """One pass over pending alerts, bounded by batch size and the daily budget."""
    summary = RunSummary()
    async with session_factory() as db:
        summary.spent_before_usd = await spent_last_24h(db)
        ids = alert_ids or await pending_alert_ids(db, min_severity, lookback_hours, batch_size)
        summary.considered = len(ids)

        for alert_id in ids:
            if summary.spent_before_usd + summary.spent_this_run_usd >= daily_budget_usd:
                summary.skipped_budget = True
                logger.warning(
                    "triage budget reached (%.2f USD in 24 h); %d alerts left for the next window",
                    daily_budget_usd, summary.considered - summary.annotated - summary.errors,
                )
                break
            try:
                row = await triage_alert(db, alert_id, backend, mode, min_confidence)
            except QueryError as exc:
                logger.warning("alert %s skipped: %s", alert_id, exc)
                summary.errors += 1
                continue
            summary.spent_this_run_usd += row.cost_usd or 0.0
            if row.status == "ok":
                summary.annotated += 1
            else:
                summary.errors += 1
            summary.verdicts[row.verdict] = summary.verdicts.get(row.verdict, 0) + 1
            logger.info(
                "alert %s -> %s (%s, conf=%s, rec=%s, $%.4f)",
                alert_id, row.verdict, row.status, row.confidence, row.recommendation,
                row.cost_usd or 0.0,
            )
    return summary
