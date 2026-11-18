"""``retention_extensions`` — approved retention extensions (DD-11).

Append-only. The original deadline in ``incident_evidence`` is never
changed; each approved extension is a new row recording the requester, the
approving admin, the reason, the original, previous and extended deadlines,
and when it was requested and approved. Rows are produced by
``app.domain.retention.approve_extension`` and validated again by a database
trigger on insert. There is no automatic extension.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards


class RetentionExtensionRecord(Base):
    __tablename__ = "retention_extensions"
    __table_args__ = (
        CheckConstraint(
            "length(trim(reason)) BETWEEN 10 AND 1000", name="reason_length"
        ),
        CheckConstraint(
            "extended_deadline > previous_deadline", name="extends_deadline"
        ),
        CheckConstraint(
            "previous_deadline >= original_deadline",
            name="previous_not_before_original",
        ),
        CheckConstraint("approved_at >= requested_at", name="approved_after_request"),
        CheckConstraint(
            "approved_at < previous_deadline", name="approved_before_expiry"
        ),
        CheckConstraint(
            "julianday(extended_deadline) - julianday(previous_deadline) <= 365",
            name="max_extension",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("incident_evidence.id"), nullable=False, index=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), nullable=False, index=True
    )
    requested_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    approved_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    original_deadline: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    previous_deadline: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    extended_deadline: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<RetentionExtensionRecord id={self.id} evidence={self.evidence_id}>"


attach_append_only_guards(RetentionExtensionRecord.__table__)
