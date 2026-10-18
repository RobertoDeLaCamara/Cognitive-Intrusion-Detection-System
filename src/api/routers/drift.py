"""GET /api/drift-status — live flow features vs the supervised model's training baseline."""

from fastapi import APIRouter, Depends

from ..auth import require_role

router = APIRouter(prefix="/api", tags=["drift"])


@router.get("/drift-status", dependencies=[Depends(require_role("admin", "analyst", "viewer"))])
def drift_status():
    """Per-feature drift for all 76 flow features.

    `status` is `ok`, `warming_up` (too few flows yet) or `no_baseline` (no FT-Transformer
    scaler loaded, e.g. the RF fallback is active). Like `/api/baseline/status`, this reads
    the capture pipeline's in-process state, so it is only populated when the API and the
    detector run in the same process (`main.py --api`).
    """
    from ...config import DRIFT_ENABLED
    if not DRIFT_ENABLED:
        return {"status": "disabled"}
    from ...pipeline import feature_drift_monitor
    return feature_drift_monitor.status()
