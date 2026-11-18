"""Health-check endpoints.

Unauthenticated by design (SR-AUTHZ-01 exempts health), and deliberately
free of version or dependency detail so it cannot aid fingerprinting
(SR-STORE-17).
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

from app.core.logging import get_logger
from app.database.session import healthcheck

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


class HealthResponse(BaseModel):
    status: str
    database: str


@router.get("/health", status_code=status.HTTP_200_OK)
def health() -> HealthResponse:
    """Liveness probe. Returns 200 if the process is serving."""
    return HealthResponse(status="ok", database="not_checked")


@router.get("/health/ready", status_code=status.HTTP_200_OK)
def readiness() -> HealthResponse:
    """Readiness probe. Verifies the database actually answers a query."""
    try:
        reachable = healthcheck()
    except Exception:
        # Never leak the driver error to the client.
        logger.warning("readiness check failed: database unreachable")
        return HealthResponse(status="degraded", database="unreachable")
    return HealthResponse(
        status="ok" if reachable else "degraded",
        database="ok" if reachable else "unreachable",
    )
