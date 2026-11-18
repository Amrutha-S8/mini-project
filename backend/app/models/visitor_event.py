"""``visitor_events`` — unrecognised-person encounters (DATABASE_DESIGN 4.2).

Visitors are anonymous: there is no member or user column, and no face
vector is ever stored for them (SR-PRIV-01). ``visitor_cluster_key`` is a
transient grouping handle. A purge clears the key and the snapshot reference
and stamps ``purged_at``; a CHECK constraint makes a half-done purge
impossible (SR-PRIV-04).

``snapshot_ref`` is a relative evidence reference validated like
``SecurityEvent.evidence_ref`` (P1), never an absolute path. Append-only
triggers allow only the purge columns and ``disposition`` to change.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

DISPOSITIONS = ("unreviewed", "benign", "suspicious", "promoted_to_member")


class VisitorEvent(Base):
    __tablename__ = "visitor_events"
    __table_args__ = (
        CheckConstraint(
            "disposition IN ('unreviewed', 'benign', 'suspicious', "
            "'promoted_to_member')",
            name="disposition_valid",
        ),
        CheckConstraint("sighting_count >= 1", name="sighting_count_positive"),
        CheckConstraint("face_count >= 1", name="face_count_positive"),
        CheckConstraint(
            "dwell_seconds IS NULL OR dwell_seconds >= 0", name="dwell_nonnegative"
        ),
        CheckConstraint(
            "snapshot_ref IS NULL OR (length(snapshot_ref) BETWEEN 1 AND 255 AND "
            "length(CAST(snapshot_ref AS BLOB)) = length(snapshot_ref) AND "
            "snapshot_ref NOT GLOB '*[^A-Za-z0-9._/-]*' AND "
            "substr(snapshot_ref, 1, 1) <> '/' AND "
            "substr(snapshot_ref, -1, 1) <> '/' AND "
            "instr(snapshot_ref, '//') = 0 AND snapshot_ref <> '..' AND "
            "substr(snapshot_ref, 1, 3) <> '../' AND "
            "substr(snapshot_ref, -3, 3) <> '/..' AND "
            "instr(snapshot_ref, '/../') = 0)",
            name="snapshot_ref_safe",
        ),
        CheckConstraint(
            "snapshot_sha256 IS NULL OR (length(snapshot_sha256) = 64 AND "
            "snapshot_sha256 NOT GLOB '*[^0-9a-f]*')",
            name="snapshot_sha256_hex",
        ),
        CheckConstraint(
            "(snapshot_ref IS NULL) = (snapshot_sha256 IS NULL)",
            name="snapshot_hashed",
        ),
        CheckConstraint(
            "purged_at IS NULL OR (snapshot_ref IS NULL AND "
            "snapshot_sha256 IS NULL AND visitor_cluster_key IS NULL)",
            name="purge_complete",
        ),
        CheckConstraint(
            "retention_expires_at > occurred_at", name="retention_after_occurrence"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, index=True
    )
    recorded_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    camera_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    access_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("access_events.id"), nullable=True
    )
    visitor_cluster_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    sighting_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    dwell_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    face_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    snapshot_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    snapshot_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    disposition: Mapped[str] = mapped_column(
        String(30), nullable=False, default="unreviewed", server_default="unreviewed"
    )
    retention_expires_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, index=True
    )
    purged_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<VisitorEvent id={self.id} disposition={self.disposition!r}>"


attach_append_only_guards(VisitorEvent.__table__)
