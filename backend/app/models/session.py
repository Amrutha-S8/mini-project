"""``sessions`` — server-side refresh sessions (DATABASE_DESIGN.md section 3.5).

Only the HMAC of a refresh token is stored, so a stolen database yields no
usable tokens. ``parent_session_id`` records rotation lineage, which is what
makes replay detection possible (SR-AUTH-08).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UtcDateTime

if TYPE_CHECKING:
    from app.models.user import User

REVOKED_LOGOUT = "logout"
REVOKED_ROTATION = "rotation"
REVOKED_REUSE = "reuse_detected"
REVOKED_ADMIN = "admin_revoke"
REVOKED_PASSWORD_CHANGE = "password_change"  # noqa: S105 - revocation reason


class SessionRecord(Base):
    """A refresh session.

    Named ``SessionRecord`` rather than ``Session`` to avoid colliding with
    ``sqlalchemy.orm.Session`` at call sites.
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: HMAC-SHA256 of the refresh token. Never the token itself.
    refresh_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    #: Rotation lineage. Enables reuse detection across a session family.
    parent_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    issued_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    expires_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, index=True
    )
    #: Non-null means unusable.
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(50), nullable=True)

    user: Mapped["User"] = relationship(back_populates="sessions")

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_expired(self, *, now: datetime) -> bool:
        return self.expires_at <= now

    def is_usable(self, *, now: datetime) -> bool:
        """Fail-closed: usable only when explicitly neither revoked nor expired."""
        return not self.is_revoked and not self.is_expired(now=now)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SessionRecord id={self.id} user_id={self.user_id}>"
