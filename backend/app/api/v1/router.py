"""v1 API router aggregation."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    auth,
    dashboard,
    events,
    health,
    incidents,
    members,
    monitoring,
    notifications,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(members.router)
api_router.include_router(events.router)
api_router.include_router(incidents.router)
api_router.include_router(dashboard.router)
api_router.include_router(monitoring.router)
api_router.include_router(notifications.router)

__all__ = ["api_router"]
