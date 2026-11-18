"""``family_members`` — people the system recognises (DATABASE_DESIGN.md 3.2).

Never hard-deleted: ``revoked`` members must stay resolvable from historical
access events. ``status`` is read by AccessEngine rule 4 from Day 4 onward.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UtcDateTime

if TYPE_CHECKING:
    from app.models.user import User

STATUS_ACTIVE = "active"
STATUS_INACTIVE = "inactive"
STATUS_REVOKED = "revoked"
VALID_STATUSES = (STATUS_ACTIVE, STATUS_INACTIVE, STATUS_REVOKED)

TYPE_FAMILY = "family"
TYPE_RESIDENT = "resident"
TYPE_STAFF = "staff"
TYPE_RECURRING_VISITOR = "recurring_visitor"
VALID_MEMBER_TYPES = (
    TYPE_FAMILY,
    TYPE_RESIDENT,
    TYPE_STAFF,
    TYPE_RECURRING_VISITOR,
)

ENROLL_NOT_ENROLLED = "not_enrolled"
ENROLL_ENROLLED = "enrolled"
ENROLL_NEEDS_REENROLLMENT = "needs_reenrollment"
VALID_ENROLLMENT_STATUSES = (
    ENROLL_NOT_ENROLLED,
    ENROLL_ENROLLED,
    ENROLL_NEEDS_REENROLLMENT,
)


class FamilyMember(Base):
    __tablename__ = "family_members"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'inactive', 'revoked')", name="status_valid"
        ),
        CheckConstraint(
            "member_type IN ('family', 'resident', 'staff', 'recurring_visitor')",
            name="member_type_valid",
        ),
        CheckConstraint(
            "enrollment_status IN ('not_enrolled', 'enrolled', 'needs_reenrollment')",
            name="enrollment_status_valid",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Set only when this person also operates the system.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    relationship_label: Mapped[str | None] = mapped_column(
        "relationship", String(100), nullable=True
    )
    member_type: Mapped[str] = mapped_column(
        String(30), nullable=False, default=TYPE_FAMILY, server_default=TYPE_FAMILY
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=STATUS_ACTIVE,
        server_default=STATUS_ACTIVE,
        index=True,
    )
    enrollment_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=ENROLL_NOT_ENROLLED,
        server_default=ENROLL_NOT_ENROLLED,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    user: Mapped["User | None"] = relationship(back_populates="family_members")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<FamilyMember id={self.id} status={self.status!r}>"
