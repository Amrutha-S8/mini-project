"""``audit_log`` — security-relevant configuration changes (DATABASE_DESIGN 7).

Append-only. The application exposes no update or delete path for this table,
which is the primary control against a malicious insider silently widening a
permission (SR-AUDIT-03, SR-AUDIT-06, SR-AUDIT-07).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"

# Action constants used by Day 2 modules. Extended as later days add modules.
ACTION_LOGIN_SUCCESS = "login.success"
ACTION_LOGIN_FAILURE = "login.failure"
ACTION_LOGOUT = "logout"
ACTION_TOKEN_REFRESH = "token.refresh"  # noqa: S105 - audit action name
ACTION_TOKEN_REUSE_DETECTED = "token.reuse_detected"  # noqa: S105 - action name
ACTION_USER_CREATE = "user.create"
ACTION_MEMBER_CREATE = "member.create"
ACTION_MEMBER_UPDATE = "member.update"
ACTION_MEMBER_DEACTIVATE = "member.deactivate"
ACTION_MEMBER_REVOKE = "member.revoke"
ACTION_INCIDENT_UPDATE = "incident.update"


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("outcome IN ('success', 'failure')", name="outcome_valid"),
        # DATABASE_DESIGN.md section 7: idx_audit_log_entity(entity_type, entity_id)
        Index("ix_audit_log_entity", "entity_type", "entity_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        index=True,
    )
    #: NULL for system-initiated actions, which are attributed to 'system'
    #: via ``actor_label`` rather than left ambiguous (SR-AUDIT-04).
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_label: Mapped[str] = mapped_column(
        String(50), nullable=False, default="system", server_default="system"
    )
    actor_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(50), nullable=True)

    #: JSON strings. Before/after values make a silent permission change
    #: distinguishable from an attack.
    before_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    outcome: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=OUTCOME_SUCCESS,
        server_default=OUTCOME_SUCCESS,
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AuditLog id={self.id} action={self.action!r}>"


# Database-level append-only guard (migration 0004, finding S4).
attach_append_only_guards(AuditLog.__table__)
