"""Retention extensions (DD-11).

Adds ``retention_extensions``: append-only records of admin-approved
retention extensions for incident evidence. Original deadlines in
``incident_evidence`` are never modified. Triggers (copied as literals from
``app/database/append_only.py``):

* reject UPDATE and DELETE on ``retention_extensions``;
* validate each insert against the evidence row, its open incident, an
  active admin approver and the current effective deadline;
* stop ``incident_evidence`` from being purged while an extension runs.

``downgrade()`` refuses to drop the table if it holds rows.

Status: written and checked statically against the reference DDL. Never
applied: Alembic and SQLAlchemy cannot be installed in this environment.

Revision ID: 0003_retention_extensions
Revises: 0002_events_incidents_workflows
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_retention_extensions"
down_revision: str | None = "0002_events_incidents_workflows"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRIGGERS = (
    (
        "CREATE TRIGGER trg_retention_extensions_guard_update BEFORE UPDATE ON "
        "retention_extensions FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'retention_extensions: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_retention_extensions_no_delete BEFORE DELETE ON "
        "retention_extensions FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'retention_extensions: delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_retention_extensions_validate_insert BEFORE INSERT ON "
        "retention_extensions FOR EACH ROW WHEN NOT EXISTS (SELECT 1 FROM "
        "incident_evidence e JOIN incidents i ON i.id = e.incident_id WHERE e.id = "
        "NEW.evidence_id AND e.incident_id = NEW.incident_id AND e.purged_at IS "
        "NULL AND e.retention_expires_at = NEW.original_deadline AND i.status IN "
        "('open', 'investigating')) OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id"
        " = NEW.approved_by_user_id AND u.role = 'admin' AND u.is_active = 1) OR "
        "NEW.previous_deadline IS NOT COALESCE((SELECT MAX(x.extended_deadline) "
        "FROM retention_extensions x WHERE x.evidence_id = NEW.evidence_id), "
        "NEW.original_deadline) BEGIN SELECT RAISE(ABORT, 'retention_extensions: "
        "extension not valid for this evidence'); END"
    ),
    (
        "CREATE TRIGGER trg_incident_evidence_respect_extensions BEFORE UPDATE OF "
        "purged_at ON incident_evidence FOR EACH ROW WHEN NEW.purged_at IS NOT NULL"
        " AND EXISTS (SELECT 1 FROM retention_extensions r WHERE r.evidence_id = "
        "NEW.id AND r.extended_deadline > NEW.purged_at) BEGIN SELECT RAISE(ABORT, "
        "'incident_evidence: retention extended; purge not permitted'); END"
    ),
)


def upgrade() -> None:
    op.create_table(
        "retention_extensions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=False),
        sa.Column("approved_by_user_id", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("original_deadline", sa.DateTime(), nullable=False),
        sa.Column("previous_deadline", sa.DateTime(), nullable=False),
        sa.Column("extended_deadline", sa.DateTime(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "length(trim(reason)) BETWEEN 10 AND 1000",
            name=op.f("ck_retention_extensions_reason_length"),
        ),
        sa.CheckConstraint(
            "extended_deadline > previous_deadline",
            name=op.f("ck_retention_extensions_extends_deadline"),
        ),
        sa.CheckConstraint(
            "previous_deadline >= original_deadline",
            name=op.f("ck_retention_extensions_previous_not_before_original"),
        ),
        sa.CheckConstraint(
            "approved_at >= requested_at",
            name=op.f("ck_retention_extensions_approved_after_request"),
        ),
        sa.CheckConstraint(
            "approved_at < previous_deadline",
            name=op.f("ck_retention_extensions_approved_before_expiry"),
        ),
        sa.CheckConstraint(
            "julianday(extended_deadline) - julianday(previous_deadline) <= 365",
            name=op.f("ck_retention_extensions_max_extension"),
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["incident_evidence.id"],
            name=op.f("fk_retention_extensions_evidence_id_incident_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_retention_extensions_incident_id_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_retention_extensions_requested_by_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_user_id"],
            ["users.id"],
            name=op.f("fk_retention_extensions_approved_by_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retention_extensions")),
    )
    op.create_index(
        op.f("ix_retention_extensions_evidence_id"),
        "retention_extensions",
        ["evidence_id"],
    )
    op.create_index(
        op.f("ix_retention_extensions_incident_id"),
        "retention_extensions",
        ["incident_id"],
    )
    for statement in _TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    """Drop the extension table and its triggers, but only if it is empty."""
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT COUNT(*) FROM retention_extensions"))
    if count.scalar_one():
        raise RuntimeError(
            "refusing to downgrade: retention_extensions holds approved extensions"
        )
    op.execute("DROP TRIGGER IF EXISTS trg_incident_evidence_respect_extensions")
    op.drop_table("retention_extensions")
