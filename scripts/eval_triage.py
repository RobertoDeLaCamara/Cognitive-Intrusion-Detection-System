#!/usr/bin/env python3
"""Measure how well the triage agent agrees with the analyst.

Ground truth comes from the analyst, not from the model: when you acknowledge
an alert, start its ``notes`` with ``[tp]`` (real attack) or ``[fp]`` (false
positive). This script joins those labels with the latest triage annotation
of each alert and reports:

  - coverage: labelled alerts that have an annotation
  - deferral rate: share of needs_human verdicts
  - precision / recall of likely_malicious on the decided alerts
  - agreement on decided alerts, and how often the policy guards fired
  - mean cost and latency per annotation

Usage:
    python scripts/eval_triage.py [--hours 720] [--json]

Start with ~20 labelled alerts: big prompt or model changes show up even on a
small set, and the set grows as you keep labelling.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from src.api.database import AsyncSessionLocal  # noqa: E402
from src.api.models import Alert, TriageAnnotation  # noqa: E402
from src.timeutils import utcnow  # noqa: E402


def label_of(notes):
    if not notes:
        return None
    head = notes.strip().lower()
    if head.startswith("[tp]"):
        return "tp"
    if head.startswith("[fp]"):
        return "fp"
    return None


def compute(rows):
    """rows: list of (label, verdict, status, policy_notes, cost_usd, duration_ms)."""
    n = len(rows)
    decided = [r for r in rows if r[1] in ("likely_malicious", "likely_benign")]
    tp = sum(1 for r in decided if r[0] == "tp" and r[1] == "likely_malicious")
    fp = sum(1 for r in decided if r[0] == "fp" and r[1] == "likely_malicious")
    fn = sum(1 for r in decided if r[0] == "tp" and r[1] == "likely_benign")
    tn = sum(1 for r in decided if r[0] == "fp" and r[1] == "likely_benign")
    costs = [r[4] for r in rows if r[4] is not None]
    lat = [r[5] for r in rows if r[5] is not None]
    return {
        "labelled_and_annotated": n,
        "deferral_rate": round(1 - len(decided) / n, 3) if n else None,
        "decided": len(decided),
        "confusion_on_decided": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision_malicious": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall_malicious": round(tp / (tp + fn), 3) if tp + fn else None,
        "agreement_on_decided": round((tp + tn) / len(decided), 3) if decided else None,
        "invalid_or_error": sum(1 for r in rows if r[2] != "ok"),
        "guards_fired": sum(1 for r in rows if r[3]),
        "mean_cost_usd": round(sum(costs) / len(costs), 4) if costs else None,
        "mean_latency_ms": int(sum(lat) / len(lat)) if lat else None,
    }


async def collect(hours):
    cutoff = utcnow() - timedelta(hours=hours)
    async with AsyncSessionLocal() as db:
        alerts = (await db.execute(
            select(Alert).where(Alert.acknowledged.is_(True), Alert.timestamp >= cutoff)
        )).scalars().all()
        labelled = {a.id: label_of(a.notes) for a in alerts if label_of(a.notes)}
        rows = []
        for alert_id, label in labelled.items():
            ann = (await db.execute(
                select(TriageAnnotation)
                .where(TriageAnnotation.alert_id == alert_id)
                .order_by(TriageAnnotation.created_at.desc(), TriageAnnotation.id.desc())
                .limit(1)
            )).scalars().first()
            if ann:
                rows.append((label, ann.verdict, ann.status, ann.policy_notes,
                             ann.cost_usd, ann.duration_ms))
        return len(labelled), rows


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--hours", type=int, default=720)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    n_labelled, rows = asyncio.run(collect(args.hours))
    report = compute(rows)
    report["labelled_alerts"] = n_labelled
    report["coverage"] = round(len(rows) / n_labelled, 3) if n_labelled else None
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for k, v in report.items():
            print(f"{k:24s} {v}")


if __name__ == "__main__":
    main()
