"""``workflow_executions`` — scheduled jobs and LangGraph runs (DESIGN 6.4).

Written only by the non-AI workflow recorder service (DD-08 decision 10);
the AI tier never holds a writer session. ``run_uid`` is the opaque id the
status API exposes, so run ids cannot be enumerated. ``requested_by_user_id``
lets the API show a run only to its requester or an admin.

A trigger freezes a row once it leaves ``running`` and rejects DELETE.
``automation_task_id`` gets its foreign key when ``automation_tasks`` is
built (Day 12).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

KINDS = ("scheduled_job", "langgraph_workflow")
TRIGGER_SOURCES = ("schedule", "manual", "event")
STATUSES = ("running", "succeeded", "failed", "cancelled", "timeout")


class WorkflowExecution(Base):
    __tablename__ = "workflow_executions"
    __table_args__ = (
        CheckConstraint(
            "execution_kind IN ('scheduled_job', 'langgraph_workflow')",
            name="execution_kind_valid",
        ),
        CheckConstraint(
            "trigger_source IN ('schedule', 'manual', 'event')",
            name="trigger_source_valid",
        ),
        CheckConstraint(
            "status IN ('running', 'succeeded', 'failed', 'cancelled', 'timeout')",
            name="status_valid",
        ),
        CheckConstraint(
            "(execution_kind = 'langgraph_workflow') = (workflow_name IS NOT NULL)",
            name="name_matches_kind",
        ),
        CheckConstraint(
            "execution_kind = 'scheduled_job' OR automation_task_id IS NULL",
            name="task_only_for_jobs",
        ),
        CheckConstraint(
            "(status = 'running') = (finished_at IS NULL)",
            name="finished_consistent",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0", name="duration_nonnegative"
        ),
        CheckConstraint(
            "tokens_used IS NULL OR tokens_used >= 0", name="tokens_nonnegative"
        ),
        CheckConstraint("steps IS NULL OR json_valid(steps)", name="steps_json"),
        Index("ix_workflow_executions_kind_started", "execution_kind", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_uid: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    execution_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    workflow_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    workflow_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    automation_task_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id"), nullable=True, index=True
    )
    requested_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    trigger_source: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="running",
        server_default="running",
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_node: Mapped[str | None] = mapped_column(String(100), nullable=True)
    steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<WorkflowExecution run={self.run_uid!r} status={self.status!r}>"


attach_append_only_guards(WorkflowExecution.__table__)
