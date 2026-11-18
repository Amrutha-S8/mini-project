"""M02 — Identity Registry service.

Owns the roster of people the system recognises. Deactivation and revocation
are soft state changes, never deletes, so historical access events keep
resolving to a real person (DATABASE_DESIGN.md design rule 2).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models.audit_log import (
    ACTION_MEMBER_CREATE,
    ACTION_MEMBER_DEACTIVATE,
    ACTION_MEMBER_REVOKE,
    ACTION_MEMBER_UPDATE,
)
from app.models.family_member import (
    STATUS_ACTIVE,
    STATUS_INACTIVE,
    STATUS_REVOKED,
    TYPE_FAMILY,
    FamilyMember,
)
from app.services import audit_service


def get_member(db: Session, member_id: int) -> FamilyMember:
    member = db.get(FamilyMember, member_id)
    if member is None:
        raise NotFoundError("Family member not found")
    return member


def list_members(db: Session, *, include_revoked: bool = False) -> list[FamilyMember]:
    stmt = select(FamilyMember).order_by(FamilyMember.full_name)
    if not include_revoked:
        stmt = stmt.where(FamilyMember.status != STATUS_REVOKED)
    return list(db.execute(stmt).scalars())


def create_member(
    db: Session,
    *,
    full_name: str,
    member_type: str = TYPE_FAMILY,
    relationship_label: str | None = None,
    notes: str | None = None,
    user_id: int | None = None,
    actor_user_id: int | None = None,
    actor_ip: str | None = None,
) -> FamilyMember:
    member = FamilyMember(
        full_name=full_name.strip(),
        member_type=member_type,
        relationship_label=relationship_label,
        notes=notes,
        user_id=user_id,
        status=STATUS_ACTIVE,
    )
    db.add(member)
    db.flush()

    audit_service.record(
        db,
        action=ACTION_MEMBER_CREATE,
        entity_type="family_member",
        entity_id=member.id,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
        after={
            "full_name": member.full_name,
            "member_type": member.member_type,
            "status": member.status,
        },
    )
    return member


def update_member(
    db: Session,
    member_id: int,
    *,
    changes: dict[str, object],
    actor_user_id: int | None = None,
    actor_ip: str | None = None,
) -> FamilyMember:
    """Apply a partial update, auditing before/after values.

    ``status`` is rejected here so that deactivation and revocation always go
    through their dedicated, separately-audited operations.
    """
    if "status" in changes:
        raise ValueError("status must be changed via deactivate_member/revoke_member")

    member = get_member(db, member_id)
    before = {
        "full_name": member.full_name,
        "member_type": member.member_type,
        "relationship_label": member.relationship_label,
        "notes": member.notes,
    }

    applied: dict[str, object] = {}
    for field, value in changes.items():
        if value is None:
            continue
        if not hasattr(member, field):
            raise ValueError(f"unknown field: {field}")
        setattr(member, field, value)
        applied[field] = value

    db.flush()
    audit_service.record(
        db,
        action=ACTION_MEMBER_UPDATE,
        entity_type="family_member",
        entity_id=member.id,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
        before=before,
        after=applied,
    )
    return member


def _change_status(
    db: Session,
    member_id: int,
    *,
    new_status: str,
    action: str,
    actor_user_id: int | None,
    actor_ip: str | None,
) -> FamilyMember:
    member = get_member(db, member_id)
    before = {"status": member.status}
    member.status = new_status
    db.flush()
    audit_service.record(
        db,
        action=action,
        entity_type="family_member",
        entity_id=member.id,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
        before=before,
        after={"status": new_status},
    )
    return member


def deactivate_member(
    db: Session,
    member_id: int,
    *,
    actor_user_id: int | None = None,
    actor_ip: str | None = None,
) -> FamilyMember:
    """Soft deactivation. The row is never deleted."""
    return _change_status(
        db,
        member_id,
        new_status=STATUS_INACTIVE,
        action=ACTION_MEMBER_DEACTIVATE,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
    )


def revoke_member(
    db: Session,
    member_id: int,
    *,
    actor_user_id: int | None = None,
    actor_ip: str | None = None,
) -> FamilyMember:
    """Permanent revocation of access rights, preserving history.

    From Day 4 this status causes AccessEngine rule 4 to deny immediately.
    """
    return _change_status(
        db,
        member_id,
        new_status=STATUS_REVOKED,
        action=ACTION_MEMBER_REVOKE,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
    )
