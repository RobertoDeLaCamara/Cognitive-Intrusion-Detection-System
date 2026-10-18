"""Adaptive ensemble weights based on alert feedback (Phase 8).

Reads acknowledged alerts (true positives) and false positives (acknowledged
with notes containing 'false positive') to adjust engine weights.
"""

import logging
from typing import Dict, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.models import Alert
from ..config import ADAPTIVE_WEIGHTS_ENABLED, ADAPTIVE_MIN_SAMPLES

logger = logging.getLogger(__name__)


async def compute_adaptive_weights(db: AsyncSession) -> Optional[Dict[str, float]]:
    """Compute engine weights from alert feedback. Returns None if insufficient data."""
    if not ADAPTIVE_WEIGHTS_ENABLED:
        return None

    result = await db.execute(
        select(Alert).where(Alert.acknowledged == True)  # noqa: E712
    )
    alerts = result.scalars().all()

    if len(alerts) < ADAPTIVE_MIN_SAMPLES:
        return None

    # Score each engine: how often was it the top contributor in true positives
    # vs false positives (notes containing 'false positive')
    engine_names = ["supervised", "isolation_forest", "lstm", "rules"]
    tp_contrib = {e: 0.0 for e in engine_names}
    fp_contrib = {e: 0.0 for e in engine_names}

    for alert in alerts:
        if not alert.engine_scores:
            continue
        is_fp = alert.label == "fp" or bool(alert.notes and "false positive" in alert.notes.lower())
        scores = alert.engine_scores
        total = sum(scores.get(e, 0.0) for e in engine_names) or 1.0

        for e in engine_names:
            contribution = scores.get(e, 0.0) / total
            if is_fp:
                fp_contrib[e] += contribution
            else:
                tp_contrib[e] += contribution

    # Weight = tp_rate / (tp_rate + fp_rate), normalized
    weights = {}
    for e in engine_names:
        tp = tp_contrib[e] + 1.0  # Laplace smoothing
        fp = fp_contrib[e] + 1.0
        weights[e] = tp / (tp + fp)

    # Normalize to sum to 1.0
    total = sum(weights.values())
    weights = {e: w / total for e, w in weights.items()}

    logger.info("Adaptive weights computed from %d samples: %s", len(alerts), weights)
    return weights
