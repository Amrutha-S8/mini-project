"""Event history: AccessEngine decisions and security events (read-only).

Every role may call these routes; what each role receives is decided in
``event_query_service`` (owner decisions R-1 and D-3). There is no write
route: events are written only by the server-side pipeline.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbDep
from app.models.access_event import AccessEvent
from app.models.security_event import SecurityEventRecord
from app.schemas.events import AccessEventPublic, SecurityEventPublic
from app.services import event_query_service as queries
from app.services.event_query_service import MAX_PAGE_SIZE, Audience

router = APIRouter(prefix="/events", tags=["events"])

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]
BeforeId = Annotated[int | None, Query(ge=1)]


def _access_public(
    event: AccessEvent, member_name: str | None, audience: Audience
) -> AccessEventPublic:
    show = audience.sees_identities
    return AccessEventPublic(
        id=event.id,
        decision_id=event.decision_id,
        occurred_at=event.occurred_at,
        door_id=event.door_id,
        camera_id=event.camera_id,
        source=event.source,  # type: ignore[arg-type]
        decision=event.decision,  # type: ignore[arg-type]
        rule_name=event.rule_name,
        reason_code=event.reason_code,
        match_confidence=event.match_confidence,
        identity="registered" if event.family_member_id is not None else "unknown",
        family_member_id=event.family_member_id if show else None,
        member_name=member_name if show else None,
    )


def _security_public(
    event: SecurityEventRecord, audience: Audience
) -> SecurityEventPublic:
    show = audience.sees_identities
    return SecurityEventPublic(
        id=event.id,
        event_uid=event.event_uid,
        event_type=event.event_type,
        modality=event.modality,
        severity=event.severity,  # type: ignore[arg-type]
        outcome=event.outcome,  # type: ignore[arg-type]
        suspicious=bool(event.suspicious),
        occurred_at=event.occurred_at,
        source_module=event.source_module,
        detector_rule=event.detector_rule,
        confidence=event.confidence,
        door_id=event.door_id,
        camera_id=event.camera_id,
        incident_id=event.incident_id,
        family_member_id=event.family_member_id if show else None,
        user_id=event.user_id if show else None,
        ip_address=event.ip_address if audience.is_admin else None,
        details=queries.parse_details(event.details) if audience.is_admin else None,
    )


@router.get("/access", response_model=list[AccessEventPublic])
def list_access_events(
    db: DbDep,
    user: CurrentUser,
    limit: Limit = 50,
    before_id: BeforeId = None,
    decision: Literal["allow", "deny", "hold"] | None = None,
) -> list[AccessEventPublic]:
    """AccessEngine decisions, newest first.

    Page with ``before_id`` = the smallest ``id`` of the previous page.
    Viewers get ``identity`` but never ``family_member_id`` or ``member_name``.
    Members get only decisions about their own family-member record.
    """
    audience = queries.audience_for(db, user)
    rows = queries.list_access_events(
        db, audience, limit=limit, before_id=before_id, decision=decision
    )
    return [_access_public(event, name, audience) for event, name in rows]


@router.get("/security", response_model=list[SecurityEventPublic])
def list_security_events(
    db: DbDep,
    user: CurrentUser,
    limit: Limit = 50,
    before_id: BeforeId = None,
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None,
    suspicious_only: bool = False,
) -> list[SecurityEventPublic]:
    """Security events, newest first.

    Admins also get ``ip_address`` and the redacted ``details``. Members get
    only events about their own record or account.
    """
    audience = queries.audience_for(db, user)
    rows = queries.list_security_events(
        db,
        audience,
        limit=limit,
        before_id=before_id,
        severity=severity,
        suspicious_only=suspicious_only,
    )
    return [_security_public(event, audience) for event in rows]
