"""Turn a ``LogAlert`` into a stored ``Alert`` (same table and enrichment as the other sources)."""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert, SeverityLevel
from ..enrichment import geoip
from ..enrichment.notifications import notify_alert
from .events import LogAlert

logger = logging.getLogger(__name__)

SOURCE = "logwatch"

# Rules carry an explicit severity; the score only has to sort consistently with it and sit
# inside the bands used by ensemble.scorer.severity_from_score.
SEVERITY_SCORE = {"low": 0.30, "medium": 0.60, "high": 0.80, "critical": 1.00}


async def persist_alert(db: AsyncSession, la: LogAlert, notify: bool = True) -> Alert:
    """Store ``la`` and (best effort) notify. Evidence lines go in ``payload_matches``."""
    score = SEVERITY_SCORE[la.severity]
    evidence = [f"{la.count} event(s) in {la.window_secs}s for {la.key} ({la.service})", *la.samples]
    alert = Alert(
        timestamp=datetime.fromtimestamp(la.last_ts, timezone.utc).replace(tzinfo=None),
        src_ip=la.ip or la.key,
        attack_type=la.description,
        severity=SeverityLevel(la.severity),
        ensemble_score=score,
        engine_scores={"logwatch": score},
        triggered_rules=[la.rule],
        source=SOURCE,
        payload_matches=evidence,
        src_geo=geoip.lookup(la.ip) if la.ip else None,
        mitre_techniques=la.mitre or None,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    if notify:
        try:
            await notify_alert({
                "src_ip": alert.src_ip, "dst_ip": la.service, "severity": la.severity,
                "ensemble_score": score, "attack_type": la.description, "triggered_rules": [la.rule],
            })
        except Exception as exc:   # a broken webhook must never lose the alert
            logger.warning("logwatch notification failed: %s", exc)
    return alert


async def already_alerted(db: AsyncSession, la: LogAlert) -> bool:
    """True when a logwatch alert for the same rule and source is already stored inside the
    rule's cooldown. Makes restarts and backfill replays idempotent."""
    since = datetime.fromtimestamp(la.last_ts - la.cooldown_secs, timezone.utc).replace(tzinfo=None)
    rows = await db.execute(
        select(Alert.triggered_rules).where(
            Alert.source == SOURCE, Alert.src_ip == (la.ip or la.key), Alert.timestamp >= since))
    return any(la.rule in (rules or []) for (rules,) in rows)
