"""Suspicious-activity detections and homeowner notifications (M13, M20).

* ``incidents`` gains ``acknowledged_at`` and ``acknowledged_by_user_id``
  through ``ALTER TABLE ... ADD COLUMN``. No foreign key: SQLite cannot add
  one to an existing table without a rebuild, and a rebuild would drop the
  ``trg_incidents_no_delete`` trigger.
* ``incident_detections``: one append-only row per rule firing.
* ``notifications``: every notification attempt and its provider status.

Triggers are copied as literals from ``app/database/append_only.py``.
``downgrade()`` refuses to run while either new table holds rows.

Status: written and checked statically against the reference DDL and the
models. Not applied in the Kiro sandbox (SQLAlchemy and Alembic cannot be
installed there).

Revision ID: 0005_detections_notifications
Revises: 0004_audit_log_append_only
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_detections_notifications"
down_revision: str | None = "0004_audit_log_append_only"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRIGGERS = (
    (
        "CREATE TRIGGER trg_incident_detections_guard_update BEFORE UPDATE ON "
        "incident_detections FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'incident_detections: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_incident_detections_no_delete BEFORE DELETE ON "
        "incident_detections FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'incident_detections: delete not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_notifications_guard_update BEFORE UPDATE ON "
        "notifications FOR EACH ROW WHEN NEW.id IS NOT OLD.id OR NEW.incident_id "
        "IS NOT OLD.incident_id OR NEW.channel IS NOT OLD.channel OR NEW.provider "
        "IS NOT OLD.provider OR NEW.recipient_masked IS NOT OLD.recipient_masked "
        "OR NEW.trigger_reason IS NOT OLD.trigger_reason OR NEW.created_at IS NOT "
        "OLD.created_at OR (OLD.provider_message_id IS NOT NULL AND "
        "NEW.provider_message_id IS NOT OLD.provider_message_id) OR (OLD.sent_at "
        "IS NOT NULL AND NEW.sent_at IS NOT OLD.sent_at) OR (OLD.delivered_at IS "
        "NOT NULL AND NEW.delivered_at IS NOT OLD.delivered_at) OR (OLD.failed_at "
        "IS NOT NULL AND NEW.failed_at IS NOT OLD.failed_at) BEGIN SELECT "
        "RAISE(ABORT, 'notifications: update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_notifications_no_delete BEFORE DELETE ON "
        "notifications FOR EACH ROW BEGIN SELECT RAISE(ABORT, "
        "'notifications: delete not permitted'); END"
    ),
)


def upgrade() -> None:
    op.add_column(
        "incidents", sa.Column("acknowledged_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "incidents", sa.Column("acknowledged_by_user_id", sa.Integer(), nullable=True)
    )

    op.create_table(
        "incident_detections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("security_event_id", sa.Integer(), nullable=False),
        sa.Column("detector_rule", sa.String(length=100), nullable=False),
        sa.Column("dedupe_key", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("event_uids", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_incident_detections_severity_valid"),
        ),
        sa.CheckConstraint(
            "length(reason) BETWEEN 1 AND 1000",
            name=op.f("ck_incident_detections_reason_length"),
        ),
        sa.CheckConstraint(
            "json_valid(event_uids)",
            name=op.f("ck_incident_detections_event_uids_json"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_detections_incident_id_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["security_event_id"],
            ["security_events.id"],
            name=op.f("fk_incident_detections_security_event_id_security_events"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_detections")),
    )
    op.create_index(
        op.f("ix_incident_detections_incident_id"),
        "incident_detections",
        ["incident_id"],
    )
    op.create_index(
        op.f("ix_incident_detections_security_event_id"),
        "incident_detections",
        ["security_event_id"],
    )
    op.create_index(
        op.f("ix_incident_detections_dedupe_key"),
        "incident_detections",
        ["dedupe_key"],
    )

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("recipient_masked", sa.String(length=32), nullable=True),
        sa.Column("trigger_reason", sa.String(length=20), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("provider_message_id", sa.String(length=128), nullable=True),
        sa.Column("provider_status", sa.String(length=32), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=300), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("failed_at", sa.DateTime(), nullable=True),
        sa.Column("status_checked_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "channel IN ('whatsapp', 'sms')",
            name=op.f("ck_notifications_channel_valid"),
        ),
        sa.CheckConstraint(
            "provider IN ('meta_whatsapp_cloud', 'twilio')",
            name=op.f("ck_notifications_provider_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'not_configured', 'send_failed', 'accepted', "
            "'sent', 'delivered', 'read', 'failed')",
            name=op.f("ck_notifications_status_valid"),
        ),
        sa.CheckConstraint(
            "trigger_reason IN ('created', 'escalated', 'fallback', 'manual')",
            name=op.f("ck_notifications_trigger_reason_valid"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('delivered', 'read') OR "
            "(provider_message_id IS NOT NULL AND delivered_at IS NOT NULL)",
            name=op.f("ck_notifications_delivery_confirmed_by_provider"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('accepted', 'sent') OR provider_message_id IS NOT NULL",
            name=op.f("ck_notifications_accepted_has_provider_id"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_notifications_incident_id_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notifications")),
    )
    op.create_index(
        op.f("ix_notifications_incident_id"), "notifications", ["incident_id"]
    )
    op.create_index(op.f("ix_notifications_status"), "notifications", ["status"])
    op.create_index(
        op.f("ix_notifications_provider_message_id"),
        "notifications",
        ["provider_message_id"],
    )
    for statement in _TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    """Remove 0005, but only while it holds no detections or notifications."""
    bind = op.get_bind()
    for table in ("incident_detections", "notifications"):
        count = bind.execute(sa.text(f"SELECT COUNT(*) FROM {table}"))  # noqa: S608
        if count.scalar_one():
            raise RuntimeError(f"refusing to downgrade: {table} holds rows")
    op.drop_table("notifications")
    op.drop_table("incident_detections")
    # Native DROP COLUMN (SQLite 3.35+) keeps trg_incidents_no_delete intact.
    op.execute("ALTER TABLE incidents DROP COLUMN acknowledged_by_user_id")
    op.execute("ALTER TABLE incidents DROP COLUMN acknowledged_at")
