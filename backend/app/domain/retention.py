"""Retention extensions for incident evidence (owner-approved policy, stdlib only).

Original retention deadlines are never modified (``incident_evidence``
triggers make ``retention_expires_at`` immutable). When an incident needs its
evidence kept longer, an authorised admin approves a separate, append-only
``retention_extensions`` record. The effective deadline is the latest
approved extension, or the original deadline when there is none.

There is no automatic extension. ``approve_extension`` needs an explicit
approver and returns the record to store; nothing here writes or schedules.

Rules (each failure raises ``RetentionExtensionError`` with a code):

* approver: an active admin; by default not the requester (two-person rule,
  ``allow_self_approval=False``);
* evidence: exists, belongs to the stated incident, not purged, has an
  original deadline; incident is ``open`` or ``investigating``;
* timing: the request is at most ``REQUEST_TTL`` old and not from the future;
  approval happens before the current effective deadline (an expired
  retention cannot be revived);
* deadline: strictly later than the current effective deadline, by at most
  ``MAX_EXTENSION``;
* reason: 10 to 1000 printable characters.

The database enforces the same essentials independently (migration 0003).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

MAX_EXTENSION = timedelta(days=365)
REQUEST_TTL = timedelta(days=7)
MIN_REASON = 10
MAX_REASON = 1000
OPEN_STATUSES = frozenset({"open", "investigating"})


class RetentionExtensionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EvidenceRetention:
    """Current state of one evidence row and its incident, read from SQLite."""

    evidence_id: int
    incident_id: int
    incident_status: str
    original_deadline: datetime | None
    purged: bool


@dataclass(frozen=True)
class Approver:
    user_id: int
    role: str
    is_active: bool


@dataclass(frozen=True)
class ExtensionRequest:
    evidence_id: int
    incident_id: int
    requested_by_user_id: int
    requested_at: datetime
    reason: str
    extended_deadline: datetime


@dataclass(frozen=True)
class RetentionExtension:
    """One approved extension. Stored as-is; never updated or deleted."""

    evidence_id: int
    incident_id: int
    requested_by_user_id: int
    approved_by_user_id: int
    reason: str
    original_deadline: datetime
    previous_deadline: datetime
    extended_deadline: datetime
    requested_at: datetime
    approved_at: datetime


def _aware(*values: datetime | None) -> None:
    for v in values:
        if v is not None and (v.tzinfo is None or v.utcoffset() is None):
            raise RetentionExtensionError("naive_datetime")


def effective_deadline(
    original: datetime | None, extensions: Sequence[RetentionExtension]
) -> datetime | None:
    """The deadline a purge job must respect."""
    if original is None:
        return None
    return max([original, *(e.extended_deadline for e in extensions)])


def approve_extension(
    request: ExtensionRequest,
    evidence: EvidenceRetention,
    approver: Approver,
    existing: Sequence[RetentionExtension],
    *,
    now: datetime,
    allow_self_approval: bool = False,
    max_extension: timedelta = MAX_EXTENSION,
) -> RetentionExtension:
    _aware(now, request.requested_at, request.extended_deadline)
    _aware(evidence.original_deadline, *(e.extended_deadline for e in existing))

    if not approver.is_active or approver.role != "admin":
        raise RetentionExtensionError("approver_not_authorised")
    if approver.user_id == request.requested_by_user_id and not allow_self_approval:
        raise RetentionExtensionError("self_approval_not_allowed")

    if evidence.evidence_id != request.evidence_id:
        raise RetentionExtensionError("evidence_mismatch")
    if evidence.incident_id != request.incident_id:
        raise RetentionExtensionError("incident_mismatch")
    if evidence.incident_status not in OPEN_STATUSES:
        raise RetentionExtensionError("incident_not_open")
    if evidence.purged:
        raise RetentionExtensionError("evidence_purged")
    if evidence.original_deadline is None:
        raise RetentionExtensionError("no_retention_deadline")
    if any(e.evidence_id != evidence.evidence_id for e in existing):
        raise RetentionExtensionError("foreign_extension_supplied")

    reason = request.reason.strip()
    if not MIN_REASON <= len(reason) <= MAX_REASON or not reason.isprintable():
        raise RetentionExtensionError("reason_invalid")

    if request.requested_at > now:
        raise RetentionExtensionError("request_from_the_future")
    if now - request.requested_at > REQUEST_TTL:
        raise RetentionExtensionError("request_expired")

    current = effective_deadline(evidence.original_deadline, existing)
    assert current is not None
    if now >= current:
        raise RetentionExtensionError("retention_already_expired")
    if request.extended_deadline <= current:
        raise RetentionExtensionError("not_an_extension")
    if request.extended_deadline - current > max_extension:
        raise RetentionExtensionError("extension_too_long")

    return RetentionExtension(
        evidence_id=evidence.evidence_id,
        incident_id=evidence.incident_id,
        requested_by_user_id=request.requested_by_user_id,
        approved_by_user_id=approver.user_id,
        reason=reason,
        original_deadline=evidence.original_deadline,
        previous_deadline=current,
        extended_deadline=request.extended_deadline,
        requested_at=request.requested_at,
        approved_at=now,
    )
