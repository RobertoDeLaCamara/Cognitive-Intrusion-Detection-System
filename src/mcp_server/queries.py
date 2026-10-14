"""Read-only query functions backing the MCP tools.

Every function takes an :class:`~sqlalchemy.ext.asyncio.AsyncSession` and
returns plain JSON-serialisable data. No function imports the MCP SDK, opens a
session, or writes — which keeps them unit-testable against the ordinary
``test_db`` fixture and keeps the read-only guarantee a property of the caller's
session (see :mod:`src.mcp_server.db`).

Attacker-influenced fields are routed through :mod:`src.mcp_server.sanitize`
and the resulting payloads are tagged so the consuming model knows which values
came off the wire.
"""

import ipaddress
import logging
from collections import Counter
from datetime import timedelta
from typing import Any, Optional

from sqlalchemy import case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import (
    Alert,
    Incident,
    MitigationAction,
    SeverityLevel,
    SuppressionRule,
    TriageAnnotation,
)
from ..timeutils import utcnow
from . import sanitize

logger = logging.getLogger(__name__)

#: Hard ceiling on rows returned by any single tool call. Prevents a broad
#: query from flooding the model context (and the client's token budget).
MAX_ROWS = 200

#: Ceiling on rows *scanned* when aggregating an IP profile. Aggregation happens
#: in Python because triggered_rules is a JSON column, so this bounds both
#: memory and latency on a busy sensor.
MAX_PROFILE_SCAN = 2000

#: Untrusted keys present in an alert summary / detail payload.
_ALERT_UNTRUSTED = ["src_ip", "dst_ip", "attack_type", "ja3_hash", "ja3_string", "notes"]


class QueryError(ValueError):
    """Invalid tool argument. Surfaced to the client as a readable message."""


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _validate_severity(severity: Optional[str]) -> Optional[str]:
    if severity is None:
        return None
    valid = {s.value for s in SeverityLevel}
    if severity not in valid:
        raise QueryError(
            f"Unknown severity {severity!r}. Expected one of: {', '.join(sorted(valid))}"
        )
    return severity


def _clamp(value: Optional[int], default: int, low: int, high: int) -> int:
    if value is None:
        return default
    return max(low, min(int(value), high))


def _validate_ip(value: Optional[str], field: str = "src_ip") -> Optional[str]:
    """Reject a malformed IP instead of silently returning an empty result.

    An unparseable IP can only ever match zero rows, and an empty result is
    indistinguishable from "this host is known and clean" — a mistyped or
    hallucinated address would otherwise read as an all-clear. Fail loudly so
    the caller corrects the address.
    """
    if value is None:
        return None
    text = str(value).strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise QueryError(
            f"{field} must be a valid IPv4 or IPv6 address, got {value!r}"
        ) from None
    return text


def _alert_summary(alert: Alert) -> dict:
    """Compact alert view — the triage list row."""
    payload = {
        "id": alert.id,
        "timestamp": _iso(alert.timestamp),
        "src_ip": sanitize.scrub_ip(alert.src_ip),
        "dst_ip": sanitize.scrub_ip(alert.dst_ip),
        "dst_port": alert.dst_port,
        "protocol": alert.protocol,
        "attack_type": sanitize.scrub_text(alert.attack_type, max_len=100),
        "severity": _enum_value(alert.severity),
        "ensemble_score": alert.ensemble_score,
        "triggered_rules": alert.triggered_rules or [],
        "acknowledged": bool(alert.acknowledged),
        "incident_id": alert.incident_id,
    }
    return sanitize.tag_untrusted(payload, _ALERT_UNTRUSTED)


def _alert_detail(alert: Alert, include_features: bool = False) -> dict:
    """Full alert view — per-engine scores, enrichment and TLS fingerprint."""
    payload = {
        "id": alert.id,
        "timestamp": _iso(alert.timestamp),
        "src_ip": sanitize.scrub_ip(alert.src_ip),
        "dst_ip": sanitize.scrub_ip(alert.dst_ip),
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "protocol": alert.protocol,
        "attack_type": sanitize.scrub_text(alert.attack_type, max_len=100),
        "severity": _enum_value(alert.severity),
        "ensemble_score": alert.ensemble_score,
        "engine_scores": alert.engine_scores or {},
        "triggered_rules": alert.triggered_rules or [],
        "payload_matches": alert.payload_matches or [],
        "mitre_techniques": alert.mitre_techniques or [],
        "src_geo": alert.src_geo,
        "ja3_hash": sanitize.scrub_ja3_hash(alert.ja3_hash),
        "ja3_string": sanitize.scrub_ja3_string(alert.ja3_string),
        "acknowledged": bool(alert.acknowledged),
        "notes": sanitize.scrub_text(alert.notes),
        "incident_id": alert.incident_id,
    }

    # Feature vectors are 76 + 18 floats. Useful for model debugging, pure
    # noise for triage, so they are opt-in.
    if include_features:
        payload["flow_features"] = alert.flow_features
        payload["host_features"] = alert.host_features

    return sanitize.tag_untrusted(payload, _ALERT_UNTRUSTED)


# ── Alert queries ─────────────────────────────────────────────────────────────


async def list_alerts(
    db: AsyncSession,
    limit: Optional[int] = 50,
    offset: Optional[int] = 0,
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    hours: Optional[int] = None,
    attack_type: Optional[str] = None,
    min_score: Optional[float] = None,
) -> dict:
    """List alerts newest first, with the usual triage filters."""
    _validate_severity(severity)
    src_ip = _validate_ip(src_ip)
    limit = _clamp(limit, 50, 1, MAX_ROWS)
    offset = max(0, int(offset or 0))

    q = select(Alert).order_by(desc(Alert.timestamp), desc(Alert.id))
    if severity:
        q = q.where(Alert.severity == severity)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    if acknowledged is not None:
        q = q.where(Alert.acknowledged == acknowledged)
    if attack_type:
        q = q.where(Alert.attack_type == attack_type)
    if min_score is not None:
        q = q.where(Alert.ensemble_score >= float(min_score))
    if hours:
        q = q.where(Alert.timestamp >= utcnow() - timedelta(hours=int(hours)))

    result = await db.execute(q.offset(offset).limit(limit))
    alerts = list(result.scalars().all())

    return {
        "count": len(alerts),
        "limit": limit,
        "offset": offset,
        "filters": {
            "severity": severity,
            "src_ip": src_ip,
            "acknowledged": acknowledged,
            "hours": hours,
            "attack_type": attack_type,
            "min_score": min_score,
        },
        "alerts": [_alert_summary(a) for a in alerts],
    }


async def get_alert(
    db: AsyncSession,
    alert_id: int,
    include_features: bool = False,
    include_triage: bool = True,
) -> dict:
    """Return one alert in full, plus any Guardian actions it triggered.

    ``include_triage`` adds the latest triage-agent annotation. The triage
    runner itself passes False so a re-triage is not anchored on the previous
    model opinion.
    """
    alert = await db.get(Alert, int(alert_id))
    if alert is None:
        raise QueryError(f"No alert with id {alert_id}")

    detail = _alert_detail(alert, include_features=include_features)

    actions = await db.execute(
        select(MitigationAction)
        .where(MitigationAction.alert_id == alert.id)
        .order_by(desc(MitigationAction.created_at))
    )
    detail["mitigation_actions"] = [
        _mitigation_summary(a) for a in actions.scalars().all()
    ]

    if include_triage:
        latest = await db.execute(
            select(TriageAnnotation)
            .where(TriageAnnotation.alert_id == alert.id)
            .order_by(desc(TriageAnnotation.created_at), desc(TriageAnnotation.id))
            .limit(1)
        )
        row = latest.scalars().first()
        detail["agent_triage"] = _triage_summary(row) if row else None
    return detail


def _triage_summary(row: TriageAnnotation) -> dict:
    """Latest triage-agent annotation. Model-generated and advisory."""
    return {
        "_advisory": "Generated by the CNDS triage agent (an LLM). Advisory only; "
                     "verify before acting.",
        "created_at": _iso(row.created_at),
        "status": row.status,
        "mode": row.mode,
        "verdict": row.verdict,
        "model_verdict": row.model_verdict,
        "confidence": row.confidence,
        "recommendation": row.recommendation,
        "summary": sanitize.scrub_text(row.summary, max_len=1200),
        "policy_notes": row.policy_notes or [],
        "model": row.model,
    }


async def get_ip_profile(
    db: AsyncSession, src_ip: str, hours: Optional[int] = 168
) -> dict:
    """Aggregate everything known about one source IP.

    The primary triage tool: instead of reading alerts one by one, an analyst
    asks whether this host has a history, whether its alerts were previously
    acknowledged (a proxy for past false-positive judgements), and whether the
    Guardian is even allowed to act on it.
    """
    if not src_ip:
        raise QueryError("src_ip is required")
    src_ip = _validate_ip(src_ip)
    hours = _clamp(hours, 168, 1, 24 * 90)
    cutoff = utcnow() - timedelta(hours=hours)

    result = await db.execute(
        select(Alert)
        .where(Alert.src_ip == src_ip, Alert.timestamp >= cutoff)
        .order_by(desc(Alert.timestamp))
        .limit(MAX_PROFILE_SCAN)
    )
    alerts = list(result.scalars().all())

    by_severity: Counter = Counter()
    by_attack_type: Counter = Counter()
    rule_counts: Counter = Counter()
    ja3_hashes: Counter = Counter()
    dst_ports: Counter = Counter()
    scores = []
    acked = 0
    geo = None

    for a in alerts:
        by_severity[_enum_value(a.severity)] += 1
        if a.attack_type:
            by_attack_type[a.attack_type] += 1
        for rule in a.triggered_rules or []:
            rule_counts[str(rule)] += 1
        if a.ja3_hash:
            ja3_hashes[a.ja3_hash] += 1
        if a.dst_port is not None:
            dst_ports[a.dst_port] += 1
        if a.ensemble_score is not None:
            scores.append(a.ensemble_score)
        if a.acknowledged:
            acked += 1
        if geo is None and a.src_geo:
            geo = a.src_geo

    timestamps = [a.timestamp for a in alerts if a.timestamp is not None]

    actions = await db.execute(
        select(MitigationAction)
        .where(MitigationAction.src_ip == src_ip)
        .order_by(desc(MitigationAction.created_at))
        .limit(MAX_ROWS)
    )
    action_rows = list(actions.scalars().all())

    profile = {
        "src_ip": sanitize.scrub_ip(src_ip),
        "window_hours": hours,
        "scan_truncated": len(alerts) >= MAX_PROFILE_SCAN,
        "total_alerts": len(alerts),
        "first_seen": _iso(min(timestamps)) if timestamps else None,
        "last_seen": _iso(max(timestamps)) if timestamps else None,
        "by_severity": dict(by_severity),
        "top_attack_types": [
            {"attack_type": sanitize.scrub_text(k, max_len=100), "count": v}
            for k, v in by_attack_type.most_common(10)
        ],
        "top_triggered_rules": [
            {"rule": sanitize.scrub_text(k, max_len=100), "count": v}
            for k, v in rule_counts.most_common(10)
        ],
        "top_dst_ports": [
            {"port": k, "count": v} for k, v in dst_ports.most_common(10)
        ],
        "distinct_ja3_hashes": [
            {"ja3_hash": sanitize.scrub_ja3_hash(k), "count": v}
            for k, v in ja3_hashes.most_common(10)
        ],
        "score": {
            "max": max(scores) if scores else None,
            "mean": round(sum(scores) / len(scores), 4) if scores else None,
        },
        "acknowledged_alerts": acked,
        "unacknowledged_alerts": len(alerts) - acked,
        "src_geo": geo,
        "mitigation_actions": [_mitigation_summary(a) for a in action_rows],
        "policy": _ip_policy(src_ip),
    }
    return sanitize.tag_untrusted(profile, ["src_ip"])


def _ip_policy(src_ip: str) -> dict:
    """Static policy that applies to this IP — why the Guardian may not act.

    Answers, without the analyst reading .env, whether an IP is Guardian-
    whitelisted (never blocked), detection-allowlisted (never even scored) or
    blocklisted (auto-flagged critical).
    """
    from ..config import GUARDIAN_ENABLED, GUARDIAN_MIN_SEVERITY, GUARDIAN_WHITELIST
    from ..enrichment.ip_lists import _matches, is_allowlisted, is_blocklisted

    return {
        "guardian_enabled": GUARDIAN_ENABLED,
        "guardian_min_severity": GUARDIAN_MIN_SEVERITY,
        "guardian_whitelisted": _matches(src_ip, GUARDIAN_WHITELIST),
        "detection_allowlisted": is_allowlisted(src_ip),
        "detection_blocklisted": is_blocklisted(src_ip),
    }


async def alert_trends(
    db: AsyncSession, hours: Optional[int] = 24, bucket: str = "hour"
) -> dict:
    """Alert counts bucketed by hour or day, for spotting bursts."""
    if bucket not in ("hour", "day"):
        raise QueryError(f"bucket must be 'hour' or 'day', got {bucket!r}")
    hours = _clamp(hours, 24, 1, 24 * 30)
    cutoff = utcnow() - timedelta(hours=hours)

    result = await db.execute(
        select(Alert.timestamp, Alert.severity).where(Alert.timestamp >= cutoff)
    )

    # A NULL timestamp cannot satisfy the cutoff predicate in SQL, so every row
    # reaching this loop is dated — no None guard is needed here.
    buckets: dict = {}
    fmt = "%Y-%m-%dT%H:00:00Z" if bucket == "hour" else "%Y-%m-%dT00:00:00Z"
    for ts, sev in result.all():
        key = ts.strftime(fmt)
        entry = buckets.setdefault(key, {"total": 0, "by_severity": {}})
        entry["total"] += 1
        sev_val = _enum_value(sev)
        entry["by_severity"][sev_val] = entry["by_severity"].get(sev_val, 0) + 1

    return {
        "bucket": bucket,
        "hours": hours,
        "data": dict(sorted(buckets.items())),
    }


async def get_stats(db: AsyncSession) -> dict:
    """Total, unacknowledged and per-severity alert counts."""
    result = await db.execute(
        select(
            func.count(Alert.id).label("total"),
            func.count(case((Alert.acknowledged == False, 1))).label("unacked"),  # noqa: E712
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


# ── Incidents ─────────────────────────────────────────────────────────────────


async def list_incidents(
    db: AsyncSession, limit: Optional[int] = 20, status: Optional[str] = None
) -> dict:
    """List incidents newest first, with their linked alert counts."""
    limit = _clamp(limit, 20, 1, MAX_ROWS)

    q = select(Incident).order_by(desc(Incident.created_at)).limit(limit)
    if status:
        q = q.where(Incident.status == status)
    result = await db.execute(q)
    incidents = list(result.scalars().all())

    counts: dict = {}
    if incidents:
        rows = await db.execute(
            select(Alert.incident_id, func.count(Alert.id))
            .where(Alert.incident_id.in_([i.id for i in incidents]))
            .group_by(Alert.incident_id)
        )
        counts = dict(rows.all())

    return {
        "count": len(incidents),
        "incidents": [
            {
                "id": i.id,
                "title": sanitize.scrub_text(i.title, max_len=255),
                "description": sanitize.scrub_text(i.description),
                "status": _enum_value(i.status),
                "severity": _enum_value(i.severity),
                "assigned_to": sanitize.scrub_text(i.assigned_to, max_len=100),
                "created_at": _iso(i.created_at),
                "updated_at": _iso(i.updated_at),
                "resolved_at": _iso(i.resolved_at),
                "alert_count": counts.get(i.id, 0),
            }
            for i in incidents
        ],
    }


# ── Guardian mitigation history ───────────────────────────────────────────────


def _mitigation_summary(action: MitigationAction) -> dict:
    return {
        "id": action.id,
        "src_ip": sanitize.scrub_ip(action.src_ip),
        "action_type": action.action_type,
        "backend": action.backend,
        "status": _enum_value(action.status),
        "reason": sanitize.scrub_text(action.reason),
        "alert_id": action.alert_id,
        "created_at": _iso(action.created_at),
        "expires_at": _iso(action.expires_at),
        "resolved_at": _iso(action.resolved_at),
    }


async def list_mitigation_actions(
    db: AsyncSession,
    limit: Optional[int] = 50,
    src_ip: Optional[str] = None,
    status: Optional[str] = None,
    hours: Optional[int] = None,
) -> dict:
    """Guardian audit trail: what was blocked, why, and whether it rolled back."""
    src_ip = _validate_ip(src_ip)
    limit = _clamp(limit, 50, 1, MAX_ROWS)

    q = select(MitigationAction).order_by(desc(MitigationAction.created_at)).limit(limit)
    if src_ip:
        q = q.where(MitigationAction.src_ip == src_ip)
    if status:
        q = q.where(MitigationAction.status == status)
    if hours:
        q = q.where(MitigationAction.created_at >= utcnow() - timedelta(hours=int(hours)))

    result = await db.execute(q)
    actions = list(result.scalars().all())
    return {
        "count": len(actions),
        "actions": [_mitigation_summary(a) for a in actions],
    }


# ── Suppression rules ─────────────────────────────────────────────────────────


async def list_suppression_rules(
    db: AsyncSession, include_expired: bool = False
) -> dict:
    """Active alert suppression rules — why an expected alert may be missing."""
    now = utcnow()
    q = select(SuppressionRule).order_by(desc(SuppressionRule.created_at)).limit(MAX_ROWS)
    if not include_expired:
        q = q.where(SuppressionRule.expires_at > now)

    result = await db.execute(q)
    rules = list(result.scalars().all())
    return {
        "count": len(rules),
        "include_expired": include_expired,
        "rules": [
            {
                "id": r.id,
                "src_ip": sanitize.scrub_ip(r.src_ip),
                "dst_ip": sanitize.scrub_ip(r.dst_ip),
                "attack_type": sanitize.scrub_text(r.attack_type, max_len=100),
                "min_severity": r.min_severity,
                "reason": sanitize.scrub_text(r.reason),
                "created_at": _iso(r.created_at),
                "expires_at": _iso(r.expires_at),
                "expired": r.expires_at is not None and r.expires_at <= now,
            }
            for r in rules
        ],
    }


# ── Detection configuration ───────────────────────────────────────────────────


async def get_detection_config(db: Optional[AsyncSession] = None) -> dict:
    """Thresholds and weights currently in force.

    Without these an ``ensemble_score`` of 0.6 is uninterpretable — the agent
    cannot tell a marginal alert from an emphatic one, nor explain why a
    critical rule fired an alert the weighted blend would have missed. Reads
    ``src/config.py`` only; no secret is exposed.
    """
    from .. import config as cfg

    return {
        "ensemble": {
            "threshold": cfg.ENSEMBLE_THRESHOLD,
            "weights": {
                "supervised": cfg.WEIGHT_SUPERVISED,
                "iforest": cfg.WEIGHT_IFOREST,
                "lstm": cfg.WEIGHT_LSTM,
                "rules": cfg.WEIGHT_RULES,
                "baseline": cfg.WEIGHT_BASELINE,
            },
            "calibration_temperature": cfg.CALIBRATION_TEMPERATURE,
            "note": (
                "Weights of unavailable engines are redistributed proportionally "
                "across the active ones. Any rule in critical_rules forces an "
                "alert regardless of the weighted blend."
            ),
        },
        "critical_rules": sorted(cfg.CRITICAL_RULES),
        "rule_thresholds": {
            "icmp_flood_threshold": cfg.ICMP_FLOOD_THRESHOLD,
            "port_scan_threshold": cfg.PORT_SCAN_THRESHOLD,
            "large_payload_bytes": cfg.LARGE_PAYLOAD_BYTES,
            "rate_spike_multiplier": cfg.RATE_SPIKE_MULTIPLIER,
        },
        "alerting": {
            "alert_cooldown_secs": cfg.ALERT_COOLDOWN_SECS,
            "dedup_window_secs": cfg.DEDUP_WINDOW_SECS,
            "confidence_decay_factor": cfg.CONFIDENCE_DECAY_FACTOR,
            "confidence_decay_window": cfg.CONFIDENCE_DECAY_WINDOW,
            "min_packets_for_ml": cfg.MIN_PACKETS_FOR_ML,
        },
        "correlation": {
            "window_secs": cfg.CORRELATION_WINDOW_SECS,
            "threshold": cfg.CORRELATION_THRESHOLD,
        },
        "guardian": {
            "enabled": cfg.GUARDIAN_ENABLED,
            "min_severity": cfg.GUARDIAN_MIN_SEVERITY,
            "block_minutes": cfg.GUARDIAN_BLOCK_MINUTES,
            "whitelist": sorted(cfg.GUARDIAN_WHITELIST),
            "circuit_max_actions": cfg.GUARDIAN_CIRCUIT_MAX_ACTIONS,
            "circuit_window_secs": cfg.GUARDIAN_CIRCUIT_WINDOW_SECS,
        },
        "ip_lists": {
            "allowlist": sorted(cfg.IP_ALLOWLIST),
            "blocklist": sorted(cfg.IP_BLOCKLIST),
        },
    }
