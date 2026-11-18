"""``security_events`` — normalised pipeline events (DATABASE_DESIGN 4.3, DD-09).

Stores every ``app.domain.events.SecurityEvent`` the pipeline accepts,
including each failed login as its own row (finding P2), plus later M13
detections, which set ``detector_rule``. ``event_uid`` is the pipeline's
``event_id`` and is unique, so persistence is idempotent in the same way as
the pipeline's de-duplication.

``details`` holds the already-redacted mapping as JSON. ``evidence_ref`` is
the validated relative reference from P1. Append-only triggers allow only two
changes: linking the row to an incident once, and clearing ``visitor_key``
during a privacy purge.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards


class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("length(event_uid) BETWEEN 1 AND 128", name="event_uid_length"),
        CheckConstraint(
            "modality IN ('biometric', 'access', 'door', 'auth', 'api', 'admin', "
            "'ai_agent', 'system', 'notification')",
            name="modality_valid",
        ),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity_valid",
        ),
        CheckConstraint(
            "outcome IN ('succeeded', 'blocked', 'failed', 'observed')",
            name="outcome_valid",
        ),
        CheckConstraint("suspicious IN (0, 1)", name="suspicious_bool"),
        CheckConstraint(
            "timestamp_assumed_utc IN (0, 1)", name="timestamp_assumed_utc_bool"
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
            name="confidence_range",
        ),
        CheckConstraint(
            "evidence_ref IS NULL OR (length(evidence_ref) BETWEEN 1 AND 255 AND "
            "length(CAST(evidence_ref AS BLOB)) = length(evidence_ref) AND "
            "evidence_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND "
            "substr(evidence_ref, 1, 1) <> '/' AND "
            "substr(evidence_ref, -1, 1) <> '/' AND "
            "instr(evidence_ref, '//') = 0 AND evidence_ref <> '..' AND "
            "substr(evidence_ref, 1, 3) <> '../' AND "
            "substr(evidence_ref, -3, 3) <> '/..' AND "
            "instr(evidence_ref, '/../') = 0)",
            name="evidence_ref_safe",
        ),
        CheckConstraint("json_valid(details)", name="details_json"),
        CheckConstraint(
            "contributing_event_ids IS NULL OR json_valid(contributing_event_ids)",
            name="contributing_json",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uid: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    modality: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(10), nullable=False)
    suspicious: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    occurred_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    timestamp_assumed_utc: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    recorded_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    source_module: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Set by M13 rule-based detections; NULL for raw pipeline events.
    detector_rule: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    family_member_id: Mapped[int | None] = mapped_column(
        ForeignKey("family_members.id"), nullable=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    visitor_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(128), nullable=True)
    door_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    camera_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True, index=True
    )
    contributing_event_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[str] = mapped_column(
        Text, nullable=False, default="{}", server_default="{}"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SecurityEventRecord id={self.id} type={self.event_type!r}>"


attach_append_only_guards(SecurityEventRecord.__table__)
