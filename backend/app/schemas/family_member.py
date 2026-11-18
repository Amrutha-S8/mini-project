"""Pydantic models for the family-member registry (M02)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MemberType = Literal["family", "resident", "staff", "recurring_visitor"]
MemberStatus = Literal["active", "inactive", "revoked"]
EnrollmentStatus = Literal["not_enrolled", "enrolled", "needs_reenrollment"]


class FamilyMemberCreate(BaseModel):
    full_name: str = Field(min_length=1, max_length=200)
    member_type: MemberType = "family"
    relationship_label: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=2000)
    user_id: int | None = None


class FamilyMemberUpdate(BaseModel):
    """Partial update. ``status`` changes go through the dedicated endpoints so
    that deactivation and revocation are always audited as distinct actions."""

    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    member_type: MemberType | None = None
    relationship_label: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=2000)


class FamilyMemberPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    member_type: MemberType
    status: MemberStatus
    enrollment_status: EnrollmentStatus
    relationship_label: str | None = None
    notes: str | None = None
    user_id: int | None = None
    created_at: datetime
    updated_at: datetime
