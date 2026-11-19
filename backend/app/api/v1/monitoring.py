"""Submitting activity records for suspicious-activity monitoring.

``POST /monitoring/events`` accepts one visitor or activity record from a
component outside the server (for example the camera client). The record is
untrusted input: it is validated, its claims are checked against the
server's own tables, and a rejected record is itself recorded so repeated
probing is detected. Storing a record never changes the door, the
AccessEngine or any permission; an ``access.allowed`` record is only a claim
and is flagged when no matching AccessEngine decision exists.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Body, Request, status

from app.api.deps import AdminUser, DbDep, NotifierDep, SettingsDep, client_ip
from app.core.errors import ValidationError
from app.schemas.events import FindingPublic, IngestResponse
from app.services import monitoring_service

router = APIRouter(prefix="/monitoring", tags=["monitoring"])

#: Largest accepted record, serialised. Bigger payloads are refused unread.
MAX_RECORD_BYTES = 16 * 1024


@router.post(
    "/events", response_model=IngestResponse, status_code=status.HTTP_201_CREATED
)
def submit_activity_record(
    db: DbDep,
    admin: AdminUser,
    settings: SettingsDep,
    notifier: NotifierDep,
    request: Request,
    record: dict[str, Any] = Body(...),  # noqa: B008 - FastAPI body declaration
) -> IngestResponse:
    """Store one activity record and run detection on it. Admin only.

    The response lists every incident the record created or joined. A
    rejected record returns ``status: rejected`` with the reason; the
    rejection itself is stored and monitored.
    """
    if len(json.dumps(record, default=str)) > MAX_RECORD_BYTES:
        raise ValidationError("activity record too large")
    result = monitoring_service.record_and_detect(
        db,
        record,
        trusted=False,
        settings=settings,
        submitter_ip=client_ip(request),
    )
    db.commit()
    findings = []
    for outcome in result.incidents:
        queued = outcome.notify_trigger is not None
        if queued:
            notifier.incident(outcome.incident_id, outcome.notify_trigger or "")
        findings.append(
            FindingPublic(
                incident_id=outcome.incident_id,
                incident_uid=outcome.incident_uid,
                rule=outcome.rule,
                severity=outcome.severity,  # type: ignore[arg-type]
                reason=outcome.reason,
                created=outcome.created,
                notification_queued=queued,
            )
        )
    return IngestResponse(
        status=result.status,  # type: ignore[arg-type]
        event_uid=result.event_uid,
        error=result.error,
        warnings=list(result.warnings),
        findings=findings,
    )
