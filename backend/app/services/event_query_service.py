"""Read-only queries over stored history: access decisions, security events,
incidents and the dashboard summary.

Role visibility is decided here, once, so every endpoint applies the same
rules (finding S5, owner decisions R-1 and D-3):

* ``admin``  — the whole household, including member identities.
* ``viewer`` — household-wide records, but never which member was involved.
* ``member`` — only records about their own linked family-member record(s)
  or their own operator account. No incidents.

Nothing here writes. Counts come from SQL over the real tables; an empty
database gives zeros, never sample numbers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.models.access_event import AccessEvent
from app.models.family_member import FamilyMember
from app.models.incident import IncidentRecord
from app.models.security_event import SecurityEventRecord
from app.models.user import ROLE_ADMIN, ROLE_MEMBER, ROLE_VIEWER, User
from app.services import identity_service

MAX_PAGE_SIZE = 200
ACTIVE_INCIDENT_STATUSES = ("open", "investigating")


@dataclass(frozen=True)
class Audience:
    """Who is asking, resolved from the database user row."""

    role: str
    user_id: int
    #: Family-member records linked to this account (members only).
    member_ids: tuple[int, ...] = ()

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def is_member(self) -> bool:
        return self.role == ROLE_MEMBER

    @property
    def sees_identities(self) -> bool:
        """Admins see every identity; members see their own. Viewers never."""
        return self.role in (ROLE_ADMIN, ROLE_MEMBER)

    @property
    def sees_household(self) -> bool:
        return self.role in (ROLE_ADMIN, ROLE_VIEWER)


def audience_for(db: Session, user: User) -> Audience:
    member_ids: tuple[int, ...] = ()
    if user.role == ROLE_MEMBER:
        member_ids = tuple(identity_service.member_ids_for_user(db, user.id))
    return Audience(role=user.role, user_id=user.id, member_ids=member_ids)


def _page(stmt: Select[Any], column: Any, *, limit: int, before_id: int | None) -> Any:
    if before_id is not None:
        stmt = stmt.where(column < before_id)
    return stmt.order_by(column.desc()).limit(max(1, min(limit, MAX_PAGE_SIZE)))


# --- access decisions ----------------------------------------------------------


def _scope_access(stmt: Select[Any], audience: Audience) -> Select[Any] | None:
    """Restrict to the audience. ``None`` means the result is certainly empty."""
    if audience.is_member:
        if not audience.member_ids:
            return None
        return stmt.where(AccessEvent.family_member_id.in_(audience.member_ids))
    return stmt


def list_access_events(
    db: Session,
    audience: Audience,
    *,
    limit: int = 50,
    before_id: int | None = None,
    decision: str | None = None,
) -> list[tuple[AccessEvent, str | None]]:
    """Newest first, with the member's name for audiences allowed to see it."""
    stmt: Select[Any] | None = select(AccessEvent, FamilyMember.full_name).outerjoin(
        FamilyMember, AccessEvent.family_member_id == FamilyMember.id
    )
    stmt = _scope_access(stmt, audience)
    if stmt is None:
        return []
    if decision is not None:
        stmt = stmt.where(AccessEvent.decision == decision)
    rows = db.execute(_page(stmt, AccessEvent.id, limit=limit, before_id=before_id))
    return [(event, name) for event, name in rows]


# --- security events -----------------------------------------------------------


def list_security_events(
    db: Session,
    audience: Audience,
    *,
    limit: int = 50,
    before_id: int | None = None,
    severity: str | None = None,
    suspicious_only: bool = False,
) -> list[SecurityEventRecord]:
    stmt = select(SecurityEventRecord)
    if audience.is_member:
        conditions = [SecurityEventRecord.user_id == audience.user_id]
        if audience.member_ids:
            conditions.append(
                SecurityEventRecord.family_member_id.in_(audience.member_ids)
            )
        stmt = stmt.where(or_(*conditions))
    if severity is not None:
        stmt = stmt.where(SecurityEventRecord.severity == severity)
    if suspicious_only:
        stmt = stmt.where(SecurityEventRecord.suspicious == 1)
    page = _page(stmt, SecurityEventRecord.id, limit=limit, before_id=before_id)
    return list(db.execute(page).scalars())


def parse_details(raw: str | None) -> dict[str, Any] | None:
    """Stored details are JSON (CHECK json_valid). Anything else fails closed."""
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


# --- incidents -----------------------------------------------------------------


def list_incidents(
    db: Session,
    *,
    limit: int = 50,
    before_id: int | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> list[IncidentRecord]:
    stmt = select(IncidentRecord)
    if status is not None:
        stmt = stmt.where(IncidentRecord.status == status)
    if severity is not None:
        stmt = stmt.where(IncidentRecord.severity == severity)
    page = _page(stmt, IncidentRecord.id, limit=limit, before_id=before_id)
    return list(db.execute(page).scalars())


# --- dashboard -----------------------------------------------------------------


def _decision_counts(
    db: Session, audience: Audience, *, since: datetime | None
) -> dict[str, int]:
    counts = {"allow": 0, "deny": 0, "hold": 0}
    stmt = _scope_access(
        select(AccessEvent.decision, func.count()).group_by(AccessEvent.decision),
        audience,
    )
    if stmt is not None:
        if since is not None:
            stmt = stmt.where(AccessEvent.occurred_at >= since)
        for decision, count in db.execute(stmt):
            counts[str(decision)] = int(count)
    counts["total"] = sum(counts.values())
    return counts


def dashboard_summary(
    db: Session, audience: Audience, *, now: datetime | None = None
) -> dict[str, Any]:
    """Live figures from the database at ``now`` (server time)."""
    now = now or utc_now()
    summary: dict[str, Any] = {
        "generated_at": now,
        "scope": "own" if audience.is_member else "household",
        "access_last_24h": _decision_counts(
            db, audience, since=now - timedelta(hours=24)
        ),
        "access_last_7d": _decision_counts(db, audience, since=now - timedelta(days=7)),
        "access_all_time": _decision_counts(db, audience, since=None),
        "last_access_event_at": None,
        "active_incidents_by_severity": None,
        "suspicious_events_last_24h": None,
    }

    last = _scope_access(select(func.max(AccessEvent.occurred_at)), audience)
    if last is not None:
        summary["last_access_event_at"] = db.execute(last).scalar_one_or_none()

    if audience.sees_household:
        by_severity = dict.fromkeys(("info", "low", "medium", "high", "critical"), 0)
        rows = db.execute(
            select(IncidentRecord.severity, func.count())
            .where(IncidentRecord.status.in_(ACTIVE_INCIDENT_STATUSES))
            .group_by(IncidentRecord.severity)
        )
        for severity, count in rows:
            by_severity[str(severity)] = int(count)
        summary["active_incidents_by_severity"] = by_severity
        summary["suspicious_events_last_24h"] = int(
            db.execute(
                select(func.count())
                .select_from(SecurityEventRecord)
                .where(SecurityEventRecord.suspicious == 1)
                .where(SecurityEventRecord.occurred_at >= now - timedelta(hours=24))
            ).scalar_one()
        )
    return summary
