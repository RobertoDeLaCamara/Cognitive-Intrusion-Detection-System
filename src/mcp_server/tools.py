"""MCP tool catalogue and dispatch.

Kept free of the MCP SDK so the catalogue, the schemas and the dispatch logic
are testable without the optional ``mcp`` dependency installed.
:mod:`src.mcp_server.server` adapts :data:`TOOLS` into SDK ``Tool`` objects.

Every tool is read-only. There is intentionally no tool that blocks, unblocks,
acknowledges, suppresses or otherwise mutates state: the Guardian remains the
only component that actuates mitigation, and it stays deterministic and
auditable. See ``doc/mcp-server.md`` for the rationale.
"""

import logging
from typing import Any, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from . import queries
from .queries import QueryError

logger = logging.getLogger(__name__)

_SEVERITIES = ["low", "medium", "high", "critical"]

TOOLS: list = [
    {
        "name": "list_alerts",
        "description": (
            "List CNDS intrusion alerts, newest first. The starting point for "
            "triage: filter by severity, source IP, acknowledgement state, "
            "attack type, minimum ensemble score, or a recent time window. "
            "Returns compact summaries; call get_alert for per-engine detail."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": f"Max alerts to return (1-{queries.MAX_ROWS}).",
                    "default": 50,
                },
                "offset": {
                    "type": "integer",
                    "description": "Rows to skip, for paging through results.",
                    "default": 0,
                },
                "severity": {
                    "type": "string",
                    "enum": _SEVERITIES,
                    "description": "Return only alerts at exactly this severity.",
                },
                "src_ip": {
                    "type": "string",
                    "description": "Exact source IP match.",
                },
                "acknowledged": {
                    "type": "boolean",
                    "description": "false returns only alerts nobody has triaged yet.",
                },
                "hours": {
                    "type": "integer",
                    "description": "Only alerts from the last N hours.",
                },
                "attack_type": {
                    "type": "string",
                    "description": "Exact attack-type label match, e.g. 'Reconnaissance'.",
                },
                "min_score": {
                    "type": "number",
                    "description": (
                        "Minimum ensemble score (0-1). Compare against the "
                        "threshold from get_detection_config to judge severity."
                    ),
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_alert",
        "description": (
            "Full detail for one alert: per-engine scores, triggered rules, "
            "payload pattern matches, MITRE ATT&CK techniques, GeoIP, JA3 TLS "
            "fingerprint, and any Guardian mitigation action it caused. Use "
            "this to explain why an alert fired."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "integer", "description": "Alert id."},
                "include_features": {
                    "type": "boolean",
                    "description": (
                        "Include the raw 76-element flow and 18-element host "
                        "feature vectors. Verbose; only useful for model debugging."
                    ),
                    "default": False,
                },
            },
            "required": ["alert_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_ip_profile",
        "description": (
            "Aggregate history for one source IP: alert totals, severity and "
            "attack-type breakdown, most frequent triggered rules, targeted "
            "ports, JA3 fingerprints, score statistics, how many of its past "
            "alerts were acknowledged, its Guardian mitigation history, and "
            "the policy applying to it (Guardian whitelist, detection "
            "allowlist/blocklist). The fastest way to tell a recurring false "
            "positive from a real intruder."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "src_ip": {"type": "string", "description": "Source IP to profile."},
                "hours": {
                    "type": "integer",
                    "description": "Look-back window in hours (default 168 = 7 days).",
                    "default": 168,
                },
            },
            "required": ["src_ip"],
            "additionalProperties": False,
        },
    },
    {
        "name": "alert_trends",
        "description": (
            "Alert counts bucketed by hour or day, broken down by severity. "
            "Use to spot bursts, scan campaigns or a detector that started "
            "over-firing after a config change."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Look-back window in hours (max 720).",
                    "default": 24,
                },
                "bucket": {
                    "type": "string",
                    "enum": ["hour", "day"],
                    "default": "hour",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_stats",
        "description": (
            "Total alert count, how many are unacknowledged, and the "
            "per-severity breakdown across the whole store. Cheap overview."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_incidents",
        "description": (
            "List correlated incidents (auto-created when one IP exceeds the "
            "correlation threshold, or opened by an analyst), each with its "
            "linked alert count."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "status": {
                    "type": "string",
                    "enum": ["open", "investigating", "resolved", "closed"],
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_mitigation_actions",
        "description": (
            "Guardian audit trail: which source IPs were auto-blocked, the "
            "reason, the backend used, and whether the block is still pending, "
            "was confirmed permanent, undone by a human, or auto-expired on "
            "rollback. Use to check whether a block is currently in force."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 50},
                "src_ip": {"type": "string", "description": "Exact source IP match."},
                "status": {
                    "type": "string",
                    "enum": ["pending", "confirmed", "undone", "expired"],
                },
                "hours": {
                    "type": "integer",
                    "description": "Only actions created in the last N hours.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_suppression_rules",
        "description": (
            "Active alert suppression rules. Check this before concluding that "
            "traffic went undetected — a matching rule silences alerts until "
            "it expires."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_expired": {
                    "type": "boolean",
                    "description": "Also return rules that have already expired.",
                    "default": False,
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_detection_config",
        "description": (
            "Detection thresholds and engine weights currently in force: "
            "ensemble threshold and per-engine weights, the critical rules that "
            "force an alert regardless of the weighted blend, rule thresholds, "
            "dedup/cooldown windows, correlation settings, Guardian policy and "
            "IP allow/block lists. Fetch this before interpreting any "
            "ensemble_score — a score is only meaningful against its threshold. "
            "Exposes no credentials."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]

#: Tool name -> query coroutine.
HANDLERS: dict = {
    "list_alerts": queries.list_alerts,
    "get_alert": queries.get_alert,
    "get_ip_profile": queries.get_ip_profile,
    "alert_trends": queries.alert_trends,
    "get_stats": queries.get_stats,
    "list_incidents": queries.list_incidents,
    "list_mitigation_actions": queries.list_mitigation_actions,
    "list_suppression_rules": queries.list_suppression_rules,
    "get_detection_config": queries.get_detection_config,
}


def tool_names() -> list:
    return [t["name"] for t in TOOLS]


def _allowed_args(tool_name: str) -> set:
    for tool in TOOLS:
        if tool["name"] == tool_name:
            return set(tool["inputSchema"].get("properties", {}))
    return set()


def get_handler(tool_name: str) -> Callable:
    handler = HANDLERS.get(tool_name)
    if handler is None:
        raise QueryError(
            f"Unknown tool {tool_name!r}. Available: {', '.join(sorted(HANDLERS))}"
        )
    return handler


async def dispatch(
    tool_name: str, arguments: Optional[dict], db: AsyncSession
) -> Any:
    """Route an MCP tool call to its query function.

    Arguments not declared in the tool's schema are dropped rather than passed
    through: a client sending an unexpected key gets its call served instead of
    a ``TypeError``, and no undeclared keyword can reach a query function.
    """
    handler = get_handler(tool_name)
    allowed = _allowed_args(tool_name)
    supplied = arguments or {}

    kwargs = {k: v for k, v in supplied.items() if k in allowed and v is not None}
    if dropped := set(supplied) - allowed:
        logger.warning("Tool %s: ignoring undeclared arguments %s", tool_name, sorted(dropped))

    return await handler(db, **kwargs)
