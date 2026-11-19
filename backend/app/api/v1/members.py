"""Family-member registry endpoints (M02).

All mutations are admin-only (SR-AUTHZ-03) and audited. There is no delete
endpoint: members are deactivated or revoked so history stays resolvable.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from app.api.deps import AdminUser, CurrentUser, DbDep, client_ip, ensure_role
from app.core.errors import NotFoundError, ValidationError
from app.models.family_member import FamilyMember
from app.models.user import ROLE_ADMIN, ROLE_MEMBER, User
from app.schemas.family_member import (
    FamilyMemberCreate,
    FamilyMemberPublic,
    FamilyMemberUpdate,
)
from app.services import identity_service

router = APIRouter(prefix="/members", tags=["members"])


def _present(member: FamilyMember, user: User) -> FamilyMemberPublic:
    """Admins see the full record; a member sees their own without admin notes."""
    public = FamilyMemberPublic.model_validate(member)
    if user.role != ROLE_ADMIN:
        public.notes = None
    return public


@router.get("", response_model=list[FamilyMemberPublic])
def list_members(
    db: DbDep,
    user: CurrentUser,
    include_revoked: bool = False,
) -> list[FamilyMemberPublic]:
    """List family members (finding S5, owner decisions R-1 and D-3).

    * admin: every record.
    * member: only records linked to their own account.
    * viewer: 403. Viewers never see individual member records.
    """
    ensure_role(user, ROLE_ADMIN, ROLE_MEMBER)
    members = identity_service.list_members(
        db,
        include_revoked=include_revoked,
        linked_user_id=None if user.role == ROLE_ADMIN else user.id,
    )
    return [_present(m, user) for m in members]


@router.get("/{member_id}", response_model=FamilyMemberPublic)
def get_member(
    member_id: int,
    db: DbDep,
    user: CurrentUser,
) -> FamilyMemberPublic:
    """One record. A member asking for someone else's gets 404, not 403, so
    the response does not confirm that the id exists."""
    ensure_role(user, ROLE_ADMIN, ROLE_MEMBER)
    member = identity_service.get_member(db, member_id)
    if user.role != ROLE_ADMIN and member.user_id != user.id:
        raise NotFoundError("Family member not found")
    return _present(member, user)


@router.post("", response_model=FamilyMemberPublic, status_code=status.HTTP_201_CREATED)
def create_member(
    payload: FamilyMemberCreate,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> FamilyMemberPublic:
    member = identity_service.create_member(
        db,
        full_name=payload.full_name,
        member_type=payload.member_type,
        relationship_label=payload.relationship_label,
        notes=payload.notes,
        user_id=payload.user_id,
        actor_user_id=admin.id,
        actor_ip=client_ip(request),
    )
    return FamilyMemberPublic.model_validate(member)


@router.patch("/{member_id}", response_model=FamilyMemberPublic)
def update_member(
    member_id: int,
    payload: FamilyMemberUpdate,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> FamilyMemberPublic:
    try:
        member = identity_service.update_member(
            db,
            member_id,
            changes=payload.model_dump(exclude_unset=True),
            actor_user_id=admin.id,
            actor_ip=client_ip(request),
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    return FamilyMemberPublic.model_validate(member)


@router.post("/{member_id}/deactivate", response_model=FamilyMemberPublic)
def deactivate_member(
    member_id: int,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> FamilyMemberPublic:
    """Soft deactivation. Never deletes the row."""
    return FamilyMemberPublic.model_validate(
        identity_service.deactivate_member(
            db, member_id, actor_user_id=admin.id, actor_ip=client_ip(request)
        )
    )


@router.post("/{member_id}/revoke", response_model=FamilyMemberPublic)
def revoke_member(
    member_id: int,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> FamilyMemberPublic:
    """Revoke access rights, preserving history."""
    return FamilyMemberPublic.model_validate(
        identity_service.revoke_member(
            db, member_id, actor_user_id=admin.id, actor_ip=client_ip(request)
        )
    )
