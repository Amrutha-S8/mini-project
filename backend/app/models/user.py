"""``users`` — operator accounts (DATABASE_DESIGN.md section 3.1).

Who may *operate the system*. Distinct from ``family_members``, who may *enter
the door*. Conflating the two would be a security error (SR-AUTH-01).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UtcDateTime

if TYPE_CHECKING:
    from app.models.family_member import FamilyMember
    from app.models.session import SessionRecord

ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLE_VIEWER = "viewer"
VALID_ROLES = (ROLE_ADMIN, ROLE_MEMBER, ROLE_VIEWER)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'member', 'viewer')", name="role_valid"),
        CheckConstraint("is_active IN (0, 1)", name="is_active_bool"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True
    )
    #: Argon2id encoded hash. Never a plaintext or reversible value.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    # server_default mirrors each Python default at the database level, so the
    # migrated schema and the model-created schema are identical and raw SQL
    # inserts get the same least-privilege defaults.
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ROLE_VIEWER, server_default=ROLE_VIEWER
    )

    #: Soft deactivation — users are never hard-deleted so historical audit
    #: entries keep resolving to a real actor.
    is_active: Mapped[bool] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )

    # --- Brute-force tracking (SR-AUTH-11) ---
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    sessions: Mapped[list["SessionRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    family_members: Mapped[list["FamilyMember"]] = relationship(back_populates="user")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<User id={self.id} role={self.role!r}>"
