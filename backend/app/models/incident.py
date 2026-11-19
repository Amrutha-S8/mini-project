"""``incidents`` and ``incident_evidence`` (DATABASE_DESIGN 5.1/5.2, DD-09).

``attack_chain`` is the deterministic M15 reconstruction. The ``ai_*``
columns are advisory Gemini output and may only be filled when
``is_ai_enriched = 1``, with a model version and timestamp (SR-AI-14); CHECK
constraints make unlabelled AI content impossible. They are written by the
non-AI recorder service, never by the AI tier itself (DD-08).

Incidents cannot be deleted (trigger), so their evidence cannot disappear
through a cascade. Evidence is referenced by a relative ``evidence_ref``
(P1, SR-STORE-12) and every file reference carries a SHA-256 (SR-STORE-11).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("open", "investigating", "resolved", "false_positive")
EVIDENCE_TYPES = ("snapshot", "clip", "log_extract", "event_export", "note")


class IncidentRecord(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity_valid",
        ),
        CheckConstraint(
            "status IN ('open', 'investigating', 'resolved', 'false_positive')",
            name="status_valid",
        ),
        CheckConstraint("event_count >= 0", name="event_count_nonnegative"),
        CheckConstraint("notify_recommended IN (0, 1)", name="notify_recommended_bool"),
        CheckConstraint("is_ai_enriched IN (0, 1)", name="is_ai_enriched_bool"),
        CheckConstraint(
            "(status IN ('resolved', 'false_positive')) = (closed_at IS NOT NULL)",
            name="closed_consistent",
        ),
        CheckConstraint(
            "first_event_at IS NULL OR last_event_at IS NULL OR "
            "first_event_at <= last_event_at",
            name="window_ordered",
        ),
        CheckConstraint(
            "attack_chain IS NULL OR json_valid(attack_chain)",
            name="attack_chain_json",
        ),
        CheckConstraint(
            "(attack_chain IS NULL) = (attack_chain_generated_at IS NULL)",
            name="attack_chain_dated",
        ),
        CheckConstraint(
            "ai_recommendations IS NULL OR json_valid(ai_recommendations)",
            name="ai_recommendations_json",
        ),
        CheckConstraint(
            "is_ai_enriched = 1 OR (ai_summary IS NULL AND "
            "ai_recommendations IS NULL AND ai_model_version IS NULL AND "
            "ai_generated_at IS NULL)",
            name="ai_content_labelled",
        ),
        CheckConstraint(
            "is_ai_enriched = 0 OR (ai_summary IS NOT NULL AND "
            "ai_model_version IS NOT NULL AND ai_generated_at IS NOT NULL)",
            name="ai_provenance",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: ``Incident.incident_id`` from the deterministic M15 reconstruction.
    incident_uid: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    opened_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", server_default="open", index=True
    )
    event_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    first_event_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    notify_recommended: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    assigned_to_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolved_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Migration 0005. An admin has seen the incident. No foreign key because
    #: SQLite cannot add one to an existing table without rebuilding it (which
    #: would drop the no-delete trigger); the audit log records the actor too.
    acknowledged_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    acknowledged_by_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attack_chain: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_chain_generated_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True
    )
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ai_generated_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    is_ai_enriched: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<IncidentRecord id={self.id} status={self.status!r}>"


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('snapshot', 'clip', 'log_extract', 'event_export', "
            "'note')",
            name="evidence_type_valid",
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
        CheckConstraint(
            "sha256 IS NULL OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')",
            name="sha256_hex",
        ),
        CheckConstraint(
            "byte_size IS NULL OR byte_size >= 0", name="byte_size_nonnegative"
        ),
        CheckConstraint(
            "evidence_ref IS NULL OR sha256 IS NOT NULL", name="file_hashed"
        ),
        CheckConstraint(
            "purged_at IS NOT NULL OR evidence_ref IS NOT NULL OR content IS NOT NULL",
            name="has_payload",
        ),
        CheckConstraint(
            "purged_at IS NULL OR (evidence_ref IS NULL AND content IS NULL)",
            name="purge_complete",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    byte_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    captured_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    source_module: Mapped[str] = mapped_column(String(64), nullable=False)
    retention_expires_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True, index=True
    )
    purged_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<IncidentEvidence id={self.id} type={self.evidence_type!r}>"


attach_append_only_guards(IncidentRecord.__table__)
attach_append_only_guards(IncidentEvidence.__table__)
