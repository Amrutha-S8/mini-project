"""``incident_detections`` — each suspicious-activity finding (migration 0005).

One row per rule firing: which rule, the severity, the plain-language reason,
the stored security event that triggered it and every event uid it is based
on. Several findings with the same ``dedupe_key`` within the merge window
belong to one incident. Append-only: no UPDATE, no DELETE (database
triggers), so the reason an incident was raised can never be rewritten.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards


class IncidentDetection(Base):
    __tablename__ = "incident_detections"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity_valid",
        ),
        CheckConstraint("length(reason) BETWEEN 1 AND 1000", name="reason_length"),
        CheckConstraint("json_valid(event_uids)", name="event_uids_json"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), nullable=False, index=True
    )
    #: The stored event that triggered this finding.
    security_event_id: Mapped[int] = mapped_column(
        ForeignKey("security_events.id"), nullable=False, index=True
    )
    detector_rule: Mapped[str] = mapped_column(String(100), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    #: JSON list of the event uids the finding is based on, oldest first.
    event_uids: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<IncidentDetection id={self.id} rule={self.detector_rule!r}>"


attach_append_only_guards(IncidentDetection.__table__)
