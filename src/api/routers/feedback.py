"""Analyst feedback (tp/fp labels) as a training signal (cnds#7)."""

import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import FEEDBACK_RETRAIN_THRESHOLD
from ...features.flow_extractor import FLOW_FEATURE_NAMES
from ..auth import require_role
from ..database import get_db
from ..models import Alert

router = APIRouter(prefix="/api", tags=["feedback"])


@router.get("/feedback-stats", dependencies=[Depends(require_role("admin", "analyst", "viewer"))])
async def feedback_stats(db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(Alert.label, func.count(Alert.id)).where(Alert.label.is_not(None)).group_by(Alert.label)
    )).all()
    counts = {label: n for label, n in rows}
    tp, fp = counts.get("tp", 0), counts.get("fp", 0)
    # A JSON column stores Python None as JSON null, not SQL NULL, so count in Python.
    labeled = (await db.execute(select(Alert.flow_features).where(Alert.label.in_(("tp", "fp"))))).scalars()
    exportable = sum(1 for f in labeled if isinstance(f, list) and len(f) == len(FLOW_FEATURE_NAMES))
    return {
        "tp_count": tp,
        "fp_count": fp,
        "unknown_count": counts.get("unknown", 0),
        "exportable_rows": exportable,
        "next_retrain_threshold": FEEDBACK_RETRAIN_THRESHOLD,
        "retrain_ready": tp + fp >= FEEDBACK_RETRAIN_THRESHOLD,
    }


@router.get("/feedback-export", dependencies=[Depends(require_role("admin", "analyst"))])
async def feedback_export(limit: int = Query(10000, ge=1, le=100000), db: AsyncSession = Depends(get_db)):
    """Labeled alerts as a training CSV: the 76 flow features, `label` (1 = tp, 0 = fp) and the predicted `attack_type`.

    Only alerts labeled tp or fp that kept their flow features are included; `unknown` is skipped.
    """
    result = await db.execute(
        select(Alert).where(Alert.label.in_(("tp", "fp"))).order_by(Alert.id).limit(limit)
    )
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([*FLOW_FEATURE_NAMES, "label", "attack_type", "alert_id"])
    for a in result.scalars():
        if not isinstance(a.flow_features, list) or len(a.flow_features) != len(FLOW_FEATURE_NAMES):
            continue
        writer.writerow([*a.flow_features, 1 if a.label == "tp" else 0, a.attack_type or "", a.id])
    return StreamingResponse(
        iter([out.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=feedback.csv"},
    )
