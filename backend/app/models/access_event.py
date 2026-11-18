"""``access_events`` — every AccessEngine decision (DATABASE_DESIGN 4.1, DD-09).

One row per decision, ALLOW, DENY or HOLD, with no sampling (SR-AUDIT-01).
The values mirror ``app.domain.access_engine.AccessDecision`` so a stored row
can explain itself without re-running the engine. Append-only: a database
trigger rejects every UPDATE and DELETE (``app/database/append_only.py``).

``permission_id`` and ``matched_embedding_id`` get foreign keys when the
``permissions`` and ``face_embeddings`` tables are built.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

DECISIONS = ("allow", "deny", "hold")
SOURCES = ("camera", "admin_review", "manual_override")


class AccessEvent(Base):
    __tablename__ = "access_events"
    __table_args__ = (
        CheckConstraint("decision IN ('allow', 'deny', 'hold')", name="decision_valid"),
        CheckConstraint(
            "source IN ('camera', 'admin_review', 'manual_override')",
            name="source_valid",
        ),
        CheckConstraint("rule_number >= 0", name="rule_number_valid"),
        CheckConstraint(
            "source = 'admin_review' OR review_of_decision_id IS NULL",
            name="review_link_only_for_reviews",
        ),
        CheckConstraint(
            "source <> 'admin_review' OR decision IN ('allow', 'deny')",
            name="review_never_holds",
        ),
        CheckConstraint(
            "match_confidence IS NULL OR "
            "(match_confidence >= -1 AND match_confidence <= 1)",
            name="match_confidence_range",
        ),
        CheckConstraint(
            "threshold_used IS NULL OR (threshold_used > 0 AND threshold_used <= 1)",
            name="threshold_range",
        ),
        CheckConstraint(
            "decision_latency_ms IS NULL OR decision_latency_ms >= 0",
            name="latency_nonnegative",
        ),
        Index("ix_access_events_member_time", "family_member_id", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, index=True
    )
    recorded_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    door_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    decision: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    rule_number: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_name: Mapped[str] = mapped_column(String(50), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(50), nullable=False)
    #: NULL means the identity was unknown.
    family_member_id: Mapped[int | None] = mapped_column(
        ForeignKey("family_members.id"), nullable=True
    )
    permission_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_embedding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    match_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    threshold_used: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: The HOLD decision an admin review resolved (DD-01).
    review_of_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approver_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    camera_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    decision_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AccessEvent id={self.id} decision={self.decision!r}>"


attach_append_only_guards(AccessEvent.__table__)
