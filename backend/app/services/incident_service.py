"""Incident case management by an admin: status, notes, assignment.

Incidents are never deleted (database trigger, SR-AUDIT-08). Every change is
audited with before and after values. This service only manages the case; it
has no access to the door or the AccessEngine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.errors import NotFoundError, ValidationError
from app.models.audit_log import ACTION_INCIDENT_UPDATE
from app.models.incident import IncidentRecord
from app.models.user import ROLE_ADMIN, User
from app.services import audit_service

CLOSED_STATUSES = ("resolved", "false_positive")

#: Allowed status changes. A closed case can be reopened, which clears
#: ``closed_at``; the earlier resolution stays in the audit log.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("investigating", "resolved", "false_positive"),
    "investigating": ("open", "resolved", "false_positive"),
    "resolved": ("open",),
    "false_positive": ("open",),
}

_UNSET: Any = object()


def get_incident(db: Session, incident_id: int) -> IncidentRecord:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def _snapshot(incident: IncidentRecord) -> dict[str, Any]:
    return {
        "status": incident.status,
        "assigned_to_user_id": incident.assigned_to_user_id,
        "resolution_notes": incident.resolution_notes,
    }


def update_incident(
    db: Session,
    incident_id: int,
    *,
    actor: User,
    status: str | None = None,
    resolution_notes: str | None = None,
    assigned_to_user_id: Any = _UNSET,
    actor_ip: str | None = None,
    now: datetime | None = None,
) -> IncidentRecord:
    """Apply an admin's change.

    Raises ``ValidationError`` for an empty change, a disallowed transition,
    closing without resolution notes, or assigning to anyone other than an
    active admin.
    """
    if actor.role != ROLE_ADMIN:  # defence in depth; the route requires admin
        raise ValidationError("only an admin can change an incident")
    incident = get_incident(db, incident_id)
    before = _snapshot(incident)
    now = now or utc_now()

    if status is None and resolution_notes is None and assigned_to_user_id is _UNSET:
        raise ValidationError("no changes requested")

    if resolution_notes is not None:
        incident.resolution_notes = resolution_notes.strip() or None

    if assigned_to_user_id is not _UNSET:
        if assigned_to_user_id is not None:
            assignee = db.get(User, assigned_to_user_id)
            if (
                assignee is None
                or not assignee.is_active
                or assignee.role != ROLE_ADMIN
            ):
                raise ValidationError(
                    "incidents can only be assigned to an active admin"
                )
        incident.assigned_to_user_id = assigned_to_user_id

    if status is not None and status != incident.status:
        if status not in TRANSITIONS.get(incident.status, ()):
            raise ValidationError(
                f"cannot change an incident from {incident.status} to {status}"
            )
        if status in CLOSED_STATUSES:
            if not incident.resolution_notes:
                raise ValidationError("resolution_notes are required to close")
            incident.closed_at = now
            incident.resolved_by_user_id = actor.id
        else:
            incident.closed_at = None
            incident.resolved_by_user_id = None
        incident.status = status

    after = _snapshot(incident)
    if after == before:
        raise ValidationError("no changes requested")

    db.flush()
    audit_service.record(
        db,
        action=ACTION_INCIDENT_UPDATE,
        entity_type="incident",
        entity_id=incident.id,
        actor_user_id=actor.id,
        actor_ip=actor_ip,
        before=before,
        after=after,
    )
    return incident
