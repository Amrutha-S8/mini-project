"""Recording security events in ``security_events`` (module M11, persistent).

The database counterpart of ``app.domain.pipeline``: validate and normalise
with ``normalise_event``, reject impossible timestamps, de-duplicate by
``event_uid`` (an idempotent retry is stored once, a reused id with different
content is stored under a new id and flagged), then insert.

Records from outside the server (``trusted=False``) are untrusted input:

* their ``source_module`` is prefixed with ``ingest.`` so they can never pose
  as an internal module;
* a rejected record is not stored, but the rejection itself is recorded as an
  internal ``api.invalid_input`` event, so repeated probing is detectable;
* claimed member and user ids that do not exist are not stored as foreign
  keys; the claim is kept in ``details`` and the detector flags it.

Nothing here makes or changes an access decision.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.domain.events import (
    EventValidationError,
    Modality,
    SecurityEvent,
    Severity,
    normalise_event,
)
from app.domain.pipeline import content_digest
from app.models.family_member import FamilyMember
from app.models.security_event import SecurityEventRecord
from app.models.user import User

#: Same bound as ``EventPipeline``: further ahead than this is rejected.
MAX_FUTURE_SKEW = timedelta(minutes=5)
INGEST_PREFIX = "ingest."
REJECTION_SOURCE = "monitoring.ingest"
_SOURCE = re.compile(r"[a-z][a-z0-9_.]{0,63}")

STATUS_STORED = "stored"
STATUS_DUPLICATE = "duplicate"
STATUS_REJECTED = "rejected"


@dataclass
class RecordResult:
    status: str
    #: The stored row: the event itself, the existing row for a duplicate, or
    #: the internal ``api.invalid_input`` row describing a rejection.
    record: SecurityEventRecord | None = None
    #: The event as the detector must see it, including unverified claims.
    event: SecurityEvent | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


def row_to_event(row: SecurityEventRecord) -> SecurityEvent:
    """Rebuild the domain event from a stored row (claims restored from details)."""
    try:
        details = json.loads(row.details or "{}")
    except ValueError:
        details = {}
    if not isinstance(details, dict):
        details = {}
    member_id = row.family_member_id
    user_id = row.user_id
    claimed_member = details.get("claimed_member_id")
    claimed_user = details.get("claimed_user_id")
    if member_id is None and isinstance(claimed_member, int):
        member_id = claimed_member
    if user_id is None and isinstance(claimed_user, int):
        user_id = claimed_user
    return SecurityEvent(
        event_id=row.event_uid,
        event_type=row.event_type,
        modality=Modality(row.modality),
        severity=Severity.parse(row.severity),
        occurred_at=row.occurred_at,
        received_at=row.received_at,
        source_module=row.source_module,
        outcome=row.outcome,
        suspicious=bool(row.suspicious),
        member_id=member_id,
        user_id=user_id,
        visitor_key=row.visitor_key,
        session_id=row.session_id,
        request_id=row.request_id,
        correlation_id=row.correlation_id,
        ip_address=row.ip_address,
        door_id=row.door_id,
        camera_id=row.camera_id,
        decision_id=row.decision_id,
        evidence_ref=row.evidence_ref,
        details={
            k: v
            for k, v in details.items()
            if k not in ("claimed_member_id", "claimed_user_id")
        },
        timestamp_assumed_utc=bool(row.timestamp_assumed_utc),
    )


def _existing(db: Session, event_uid: str) -> SecurityEventRecord | None:
    return db.execute(
        select(SecurityEventRecord).where(SecurityEventRecord.event_uid == event_uid)
    ).scalar_one_or_none()


def _insert(db: Session, event: SecurityEvent) -> SecurityEventRecord:
    """Insert, keeping unverifiable member/user claims out of foreign keys."""
    details: dict[str, Any] = dict(event.details)
    member_id = event.member_id
    if member_id is not None and db.get(FamilyMember, member_id) is None:
        details["claimed_member_id"] = member_id
        member_id = None
    user_id = event.user_id
    if user_id is not None and db.get(User, user_id) is None:
        details["claimed_user_id"] = user_id
        user_id = None
    row = SecurityEventRecord(
        event_uid=event.event_id,
        event_type=event.event_type,
        modality=event.modality.value,
        severity=event.severity.name.lower(),
        outcome=event.outcome,
        suspicious=int(event.suspicious),
        occurred_at=event.occurred_at,
        received_at=event.received_at,
        timestamp_assumed_utc=int(event.timestamp_assumed_utc),
        source_module=event.source_module,
        family_member_id=member_id,
        user_id=user_id,
        visitor_key=event.visitor_key,
        session_id=event.session_id,
        request_id=event.request_id,
        correlation_id=event.correlation_id,
        ip_address=event.ip_address,
        door_id=event.door_id,
        camera_id=event.camera_id,
        decision_id=event.decision_id,
        evidence_ref=event.evidence_ref,
        details=json.dumps(details, sort_keys=True, default=str),
    )
    db.add(row)
    db.flush()
    return row


def _record_rejection(
    db: Session,
    *,
    reason: str,
    raw: Mapping[str, Any],
    submitter_ip: str | None,
    now: datetime,
) -> RecordResult:
    claimed_source = str(raw.get("source_module", ""))[:64]
    event = normalise_event(
        {
            "event_type": "api.invalid_input",
            "source_module": REJECTION_SOURCE,
            "occurred_at": now,
            "outcome": "blocked",
            "ip_address": submitter_ip,
            "details": {
                "reason": reason[:200],
                "claimed_source_module": claimed_source,
            },
        },
        received_at=now,
    )
    row = _insert(db, event)
    return RecordResult(STATUS_REJECTED, record=row, event=event, error=reason)


def record_event(
    db: Session,
    raw: Mapping[str, Any],
    *,
    trusted: bool,
    submitter_ip: str | None = None,
    now: datetime | None = None,
) -> RecordResult:
    """Validate and store one event. The caller owns the transaction."""
    now = now or utc_now()
    data = dict(raw)
    if not trusted:
        given = str(data.get("source_module", "")).strip()
        if not _SOURCE.fullmatch(given):
            return _record_rejection(
                db,
                reason="source_module is required (lowercase identifier)",
                raw=raw,
                submitter_ip=submitter_ip,
                now=now,
            )
        data["source_module"] = (INGEST_PREFIX + given)[:64]
    try:
        event = normalise_event(data, received_at=now)
    except EventValidationError as exc:
        if trusted:
            raise
        return _record_rejection(
            db, reason=str(exc), raw=raw, submitter_ip=submitter_ip, now=now
        )

    if event.occurred_at > event.received_at + MAX_FUTURE_SKEW:
        if trusted:
            raise EventValidationError("timestamp too far in the future")
        return _record_rejection(
            db,
            reason="too_far_in_future",
            raw=raw,
            submitter_ip=submitter_ip,
            now=now,
        )

    warnings: list[str] = []
    existing = _existing(db, event.event_id)
    if existing is not None:
        if content_digest(row_to_event(existing)) == content_digest(event):
            return RecordResult(
                STATUS_DUPLICATE, record=existing, event=row_to_event(existing)
            )
        details = dict(event.details)
        details["event_id_conflict"] = event.event_id
        event = replace(event, event_id=uuid.uuid4().hex, details=details)
        warnings.append("event_id_conflict_rekeyed")
    if event.timestamp_assumed_utc:
        warnings.append("naive_timestamp_assumed_utc")

    row = _insert(db, event)
    return RecordResult(STATUS_STORED, record=row, event=event, warnings=warnings)


def recent_events(
    db: Session, *, around: datetime, window: timedelta, exclude_id: int | None
) -> list[SecurityEvent]:
    """Stored events from ``window`` before ``around`` up to ``around``."""
    stmt = (
        select(SecurityEventRecord)
        .where(SecurityEventRecord.occurred_at >= around - window)
        .where(SecurityEventRecord.occurred_at <= around)
        .order_by(SecurityEventRecord.occurred_at)
        .limit(2000)
    )
    if exclude_id is not None:
        stmt = stmt.where(SecurityEventRecord.id != exclude_id)
    return [row_to_event(r) for r in db.execute(stmt).scalars()]
