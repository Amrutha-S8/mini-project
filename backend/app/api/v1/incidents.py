"""Incident management.

Admins and viewers may read incidents; members may not (owner decision R-1).
Only admins change them. Viewers get the case summary without the attack
chain or AI advisory content, which can reference individual members.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request

from app.api.deps import (
    HOUSEHOLD_READERS,
    AdminUser,
    CurrentUser,
    DbDep,
    client_ip,
    ensure_role,
)
from app.models.incident import IncidentRecord
from app.models.user import ROLE_ADMIN, User
from app.schemas.events import (
    AiAdvisory,
    IncidentDetail,
    IncidentSummary,
    IncidentUpdate,
)
from app.services import event_query_service as queries
from app.services import incident_service
from app.services.event_query_service import MAX_PAGE_SIZE

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _summary_fields(incident: IncidentRecord) -> dict[str, Any]:
    return {
        "id": incident.id,
        "incident_uid": incident.incident_uid,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "status": incident.status,
        "opened_at": incident.opened_at,
        "closed_at": incident.closed_at,
        "event_count": incident.event_count,
        "first_event_at": incident.first_event_at,
        "last_event_at": incident.last_event_at,
        "notify_recommended": bool(incident.notify_recommended),
        "assigned_to_user_id": incident.assigned_to_user_id,
    }


def _json_or_none(raw: str | None) -> Any | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _detail(incident: IncidentRecord, user: User) -> IncidentDetail:
    fields = _summary_fields(incident)
    fields["resolution_notes"] = incident.resolution_notes
    fields["resolved_by_user_id"] = incident.resolved_by_user_id
    if user.role == ROLE_ADMIN:
        fields["attack_chain"] = _json_or_none(incident.attack_chain)
        fields["attack_chain_generated_at"] = incident.attack_chain_generated_at
        if (
            incident.is_ai_enriched
            and incident.ai_summary
            and incident.ai_model_version
            and incident.ai_generated_at
        ):
            fields["ai_advisory"] = AiAdvisory(
                summary=incident.ai_summary,
                recommendations=_json_or_none(incident.ai_recommendations),
                model_version=incident.ai_model_version,
                generated_at=incident.ai_generated_at,
            )
    return IncidentDetail(**fields)


@router.get("", response_model=list[IncidentSummary])
def list_incidents(
    db: DbDep,
    user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    status: Literal["open", "investigating", "resolved", "false_positive"]
    | None = None,
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None,
) -> list[IncidentSummary]:
    """Incidents, newest first. Admin and viewer only."""
    ensure_role(user, *HOUSEHOLD_READERS)
    rows = queries.list_incidents(
        db, limit=limit, before_id=before_id, status=status, severity=severity
    )
    return [IncidentSummary(**_summary_fields(i)) for i in rows]


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: DbDep, user: CurrentUser) -> IncidentDetail:
    ensure_role(user, *HOUSEHOLD_READERS)
    return _detail(incident_service.get_incident(db, incident_id), user)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> IncidentDetail:
    """Change status, resolution notes or assignee. Audited.

    Closing (``resolved`` or ``false_positive``) requires resolution notes,
    sent now or earlier. A closed incident can only be reopened.
    """
    changes: dict[str, Any] = {}
    if "assigned_to_user_id" in payload.model_fields_set:
        changes["assigned_to_user_id"] = payload.assigned_to_user_id
    incident = incident_service.update_incident(
        db,
        incident_id,
        actor=admin,
        status=payload.status,
        resolution_notes=payload.resolution_notes,
        actor_ip=client_ip(request),
        **changes,
    )
    return _detail(incident, admin)
