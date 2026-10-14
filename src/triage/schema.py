"""Output contract for the triage agent.

The model must answer with an object matching :data:`OUTPUT_SCHEMA`. The same
schema is passed to ``claude -p --json-schema`` so the CLI enforces it, and
:func:`validate` re-checks it here: the persisted row never depends on the
backend having honoured the contract.
"""

import re
from typing import Any, Dict, List, Tuple

VERDICTS = ("likely_malicious", "likely_benign", "needs_human")
RECOMMENDATIONS = (
    "confirm_block",    # Guardian already blocked: a human should make it permanent
    "undo_block",       # Guardian already blocked: a human should undo it early
    "suppress_source",  # expected/benign traffic: a human should add a suppression rule
    "monitor",          # keep watching, no action yet
    "escalate",         # needs an analyst now
    "no_action",
)
EVIDENCE_SOURCES = ("alert", "ip_profile", "incidents", "mitigation", "suppression", "config")

MAX_SUMMARY = 1200
MAX_FACT = 300
MAX_EVIDENCE = 8
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "confidence", "summary", "evidence", "recommendation"],
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string", "maxLength": MAX_SUMMARY},
        "evidence": {
            "type": "array",
            "maxItems": MAX_EVIDENCE,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "fact"],
                "properties": {
                    "source": {"type": "string", "enum": list(EVIDENCE_SOURCES)},
                    "fact": {"type": "string", "maxLength": MAX_FACT},
                },
            },
        },
        "recommendation": {"type": "string", "enum": list(RECOMMENDATIONS)},
        "mitre_techniques": {
            "type": "array",
            "maxItems": 5,
            "items": {"type": "string", "pattern": _MITRE_RE.pattern},
        },
        "missing_information": {
            "type": "array",
            "maxItems": 5,
            "items": {"type": "string", "maxLength": MAX_FACT},
        },
    },
}


def validate(obj: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Return ``(clean, errors)``. ``clean`` is only meaningful when ``errors`` is empty.

    Hand-rolled on purpose: CNDS does not depend on ``jsonschema`` and the
    contract is small. Unknown keys are an error, not silently dropped, so a
    drifting prompt is visible in the ``invalid_output`` rows.
    """
    errors: List[str] = []
    if not isinstance(obj, dict):
        return {}, ["output is not an object"]

    allowed = set(OUTPUT_SCHEMA["properties"])
    for key in obj:
        if key not in allowed:
            errors.append(f"unexpected key {key!r}")
    for key in OUTPUT_SCHEMA["required"]:
        if key not in obj:
            errors.append(f"missing key {key!r}")
    if errors:
        return {}, errors

    clean: Dict[str, Any] = {}

    if obj["verdict"] not in VERDICTS:
        errors.append(f"invalid verdict {obj['verdict']!r}")
    clean["verdict"] = obj["verdict"]

    conf = obj["confidence"]
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        errors.append(f"confidence must be a number in [0, 1], got {conf!r}")
    else:
        clean["confidence"] = float(conf)

    summary = obj["summary"]
    if not isinstance(summary, str) or not summary.strip():
        errors.append("summary must be a non-empty string")
    elif len(summary) > MAX_SUMMARY:
        errors.append(f"summary longer than {MAX_SUMMARY} chars")
    clean["summary"] = summary

    evidence = obj["evidence"]
    if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE:
        errors.append(f"evidence must be a list of at most {MAX_EVIDENCE} items")
    else:
        clean_ev = []
        for i, item in enumerate(evidence):
            if (
                not isinstance(item, dict)
                or set(item) != {"source", "fact"}
                or item.get("source") not in EVIDENCE_SOURCES
                or not isinstance(item.get("fact"), str)
                or len(item["fact"]) > MAX_FACT
            ):
                errors.append(f"evidence[{i}] is malformed")
            else:
                clean_ev.append({"source": item["source"], "fact": item["fact"]})
        clean["evidence"] = clean_ev

    if obj["recommendation"] not in RECOMMENDATIONS:
        errors.append(f"invalid recommendation {obj['recommendation']!r}")
    clean["recommendation"] = obj["recommendation"]

    techniques = obj.get("mitre_techniques", [])
    if not isinstance(techniques, list) or len(techniques) > 5 or not all(
        isinstance(t, str) and _MITRE_RE.match(t) for t in techniques
    ):
        errors.append("mitre_techniques must be up to 5 ATT&CK ids like T1046")
    else:
        clean["mitre_techniques"] = techniques

    missing = obj.get("missing_information", [])
    if not isinstance(missing, list) or len(missing) > 5 or not all(
        isinstance(m, str) and len(m) <= MAX_FACT for m in missing
    ):
        errors.append("missing_information must be up to 5 short strings")
    else:
        clean["missing_information"] = missing

    return clean, errors
