"""Incident management.

Admins and viewers may read incidents; members may not (owner decision R-1).
Only admins acknowledge, investigate, resolve, edit or re-notify, and every
change is audited. Viewers get the case summary and the detection reasons
(which never name members) but not the attack chain, AI advisory content or
notification records.

Nothing here touches the virtual door, the AccessEngine or permissions.
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
    NotifierDep,
    client_ip,
    ensure_role,
)
from app.models.audit_log import ACTION_NOTIFICATION_MANUAL
from app.models.incident import IncidentRecord
from app.models.incident_detection import IncidentDetection
from app.models.notification import NotificationRecord
from app.models.user import ROLE_ADMIN, User
from app.notifications.types import delivery_confirmed
from app.schemas.events import (
    AiAdvisory,
    DetectionPublic,
    IncidentDetail,
    IncidentResolve,
    IncidentSummary,
    IncidentUpdate,
    NotificationPublic,
    NotifyResponse,
)
from app.services import audit_service, incident_service, notification_service
from app.services import event_query_service as queries
from app.services.event_query_service import MAX_PAGE_SIZE

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _summary_fields(
    incident: IncidentRecord, latest_reason: str | None = None
) -> dict[str, Any]:
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
        "acknowledged_at": incident.acknowledged_at,
        "acknowledged_by_user_id": incident.acknowledged_by_user_id,
        "latest_reason": latest_reason,
    }


def _json_or_none(raw: str | None) -> Any | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _detection(row: IncidentDetection) -> DetectionPublic:
    uids = _json_or_none(row.event_uids)
    return DetectionPublic(
        id=row.id,
        detector_rule=row.detector_rule,
        severity=row.severity,  # type: ignore[arg-type]
        reason=row.reason,
        detected_at=row.detected_at,
        security_event_id=row.security_event_id,
        event_uids=[str(u) for u in uids] if isinstance(uids, list) else [],
    )


def _detail(db: DbDep, incident: IncidentRecord, user: User) -> IncidentDetail:
    detections = [_detection(d) for d in queries.detections_for(db, incident.id)]
    fields = _summary_fields(incident, detections[-1].reason if detections else None)
    fields["resolution_notes"] = incident.resolution_notes
    fields["resolved_by_user_id"] = incident.resolved_by_user_id
    fields["detections"] = detections
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


def notification_public(row: NotificationRecord) -> NotificationPublic:
    return NotificationPublic(
        id=row.id,
        incident_id=row.incident_id,
        channel=row.channel,  # type: ignore[arg-type]
        provider=row.provider,
        recipient_masked=row.recipient_masked,
        trigger_reason=row.trigger_reason,
        status=row.status,
        delivery_confirmed=delivery_confirmed(row.status),
        provider_message_id=row.provider_message_id,
        provider_status=row.provider_status,
        error_code=row.error_code,
        error_message=row.error_message,
        created_at=row.created_at,
        sent_at=row.sent_at,
        delivered_at=row.delivered_at,
        failed_at=row.failed_at,
        status_checked_at=row.status_checked_at,
    )


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
    """Incidents, newest first, with the latest detection reason. Admin and
    viewer only."""
    ensure_role(user, *HOUSEHOLD_READERS)
    rows = queries.list_incidents(
        db, limit=limit, before_id=before_id, status=status, severity=severity
    )
    reasons = queries.latest_reasons(db, [i.id for i in rows])
    return [IncidentSummary(**_summary_fields(i, reasons.get(i.id))) for i in rows]


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: DbDep, user: CurrentUser) -> IncidentDetail:
    """One incident with every detection (rule, severity, reason, event)."""
    ensure_role(user, *HOUSEHOLD_READERS)
    return _detail(db, incident_service.get_incident(db, incident_id), user)


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
    return _detail(db, incident, admin)


@router.post("/{incident_id}/acknowledge", response_model=IncidentDetail)
def acknowledge_incident(
    incident_id: int, db: DbDep, admin: AdminUser, request: Request
) -> IncidentDetail:
    """Mark as seen. Stops automatic re-notification; status is unchanged."""
    incident = incident_service.acknowledge_incident(
        db, incident_id, actor=admin, actor_ip=client_ip(request)
    )
    return _detail(db, incident, admin)


@router.post("/{incident_id}/investigate", response_model=IncidentDetail)
def investigate_incident(
    incident_id: int, db: DbDep, admin: AdminUser, request: Request
) -> IncidentDetail:
    """Move to ``investigating`` (also acknowledges it). Audited."""
    incident = incident_service.acknowledge_incident(
        db, incident_id, actor=admin, actor_ip=client_ip(request)
    )
    if incident.status != "investigating":
        incident = incident_service.update_incident(
            db,
            incident_id,
            actor=admin,
            status="investigating",
            actor_ip=client_ip(request),
        )
    return _detail(db, incident, admin)


@router.post("/{incident_id}/resolve", response_model=IncidentDetail)
def resolve_incident(
    incident_id: int,
    payload: IncidentResolve,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> IncidentDetail:
    """Close as ``resolved`` or ``false_positive`` with notes. Audited."""
    incident_service.acknowledge_incident(
        db, incident_id, actor=admin, actor_ip=client_ip(request)
    )
    incident = incident_service.update_incident(
        db,
        incident_id,
        actor=admin,
        status=payload.resolution,
        resolution_notes=payload.resolution_notes,
        actor_ip=client_ip(request),
    )
    return _detail(db, incident, admin)


@router.get("/{incident_id}/notifications", response_model=list[NotificationPublic])
def incident_notifications(
    incident_id: int, db: DbDep, admin: AdminUser
) -> list[NotificationPublic]:
    """Every notification attempt for the incident, with provider status."""
    incident_service.get_incident(db, incident_id)
    return [
        notification_public(r)
        for r in notification_service.list_for_incident(db, incident_id)
    ]


@router.post("/{incident_id}/notify", response_model=NotifyResponse, status_code=202)
def notify_incident(
    incident_id: int,
    db: DbDep,
    admin: AdminUser,
    notifier: NotifierDep,
    request: Request,
) -> NotifyResponse:
    """Send the homeowner notification again (WhatsApp, then SMS fallback).

    Returns 202: the attempt runs in the background and its result appears in
    ``GET /incidents/{id}/notifications``. This response never says the
    message was delivered.
    """
    incident_service.get_incident(db, incident_id)
    audit_service.record(
        db,
        action=ACTION_NOTIFICATION_MANUAL,
        entity_type="incident",
        entity_id=incident_id,
        actor_user_id=admin.id,
        actor_ip=client_ip(request),
    )
    db.commit()
    notifier.incident(incident_id, notification_service.TRIGGER_MANUAL)
    return NotifyResponse(
        queued=True,
        message=(
            "Notification attempt started. Check the notification list for the "
            "provider's answer; delivery is shown only once the provider confirms it."
        ),
    )
