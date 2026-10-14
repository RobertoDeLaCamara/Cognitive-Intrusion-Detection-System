"""Deterministic guards applied to every model answer before it is stored.

The model proposes; this module decides what is written. Each guard that
changes the answer leaves a note in ``policy_notes`` so the analyst (and the
agreement metrics) can see both the raw model opinion and the stored one.
"""

from typing import Any, Dict, List, Tuple

from ..mcp_server import sanitize
from .schema import MAX_FACT, MAX_SUMMARY

_MITIGATION_RECS = ("confirm_block", "undo_block")


def apply_guards(
    output: Dict[str, Any], context: Dict[str, Any], min_confidence: float
) -> Tuple[Dict[str, Any], List[str]]:
    """Return ``(stored_output, notes)`` for a schema-valid model answer."""
    out = dict(output)
    notes: List[str] = []

    alert = context.get("alert") or {}
    profile = context.get("ip_profile") or {}
    policy = profile.get("policy") or {}
    has_action = bool(alert.get("mitigation_actions"))

    if out["confidence"] < min_confidence and out["verdict"] != "needs_human":
        notes.append(
            f"confidence {out['confidence']:.2f} below {min_confidence:.2f}: "
            f"verdict {out['verdict']} -> needs_human"
        )
        out["verdict"] = "needs_human"

    if out["recommendation"] in _MITIGATION_RECS and not has_action:
        notes.append(
            f"recommendation {out['recommendation']} without a Guardian action on this alert -> escalate"
        )
        out["recommendation"] = "escalate"

    if out["recommendation"] == "confirm_block" and policy.get("guardian_whitelisted"):
        notes.append("confirm_block on a Guardian-whitelisted source -> escalate")
        out["recommendation"] = "escalate"

    if out["verdict"] == "likely_benign" and out["recommendation"] == "confirm_block":
        notes.append("likely_benign contradicts confirm_block -> needs_human / escalate")
        out["verdict"] = "needs_human"
        out["recommendation"] = "escalate"

    # Model text can echo attacker-influenced values: bound and strip it the
    # same way the MCP layer does before it reaches a dashboard or another model.
    out["summary"] = sanitize.scrub_text(out["summary"], max_len=MAX_SUMMARY)
    out["evidence"] = [
        {"source": e["source"], "fact": sanitize.scrub_text(e["fact"], max_len=MAX_FACT)}
        for e in out.get("evidence", [])
    ]
    return out, notes
