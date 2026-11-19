"""Dashboard summary computed from the stored records at request time."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep
from app.schemas.events import DashboardSummary
from app.services import event_query_service as queries

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: DbDep, user: CurrentUser) -> DashboardSummary:
    """Access-decision counts and active incidents, from SQL over real rows.

    An empty database returns zeros. Members get counts of their own access
    decisions only, and no incident or security-event figures.
    """
    audience = queries.audience_for(db, user)
    return DashboardSummary.model_validate(queries.dashboard_summary(db, audience))
