"""GET /api/engines — registered detection engines and their weights."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import require_role
from ..database import get_db

router = APIRouter(prefix="/api", tags=["engines"])


@router.get("/engines", dependencies=[Depends(require_role("admin", "analyst", "viewer"))])
async def list_engines(db: AsyncSession = Depends(get_db)):
    from ...engines.registry import describe_engines
    from ...enrichment.adaptive_weights import compute_adaptive_weights
    adaptive = await compute_adaptive_weights(db)  # None until enough acknowledged alerts
    return {"engines": describe_engines(adaptive)}
