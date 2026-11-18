"""audit_log append-only triggers (finding S4, SR-AUDIT-06/07).

Migration 0001 created ``audit_log`` without database protection, so an
``UPDATE`` or ``DELETE`` would succeed (confirmed on the reference schema).
These triggers, copied as literals from ``app/database/append_only.py``,
refuse every change except ``actor_user_id`` becoming NULL, which is what
``ON DELETE SET NULL`` from ``users`` does. No table or column changes.

``downgrade()`` drops the two triggers only; it deletes no data.

Status: written and checked statically against the reference DDL. Never
applied: Alembic and SQLAlchemy cannot be installed in this environment.

Revision ID: 0004_audit_log_append_only
Revises: 0003_retention_extensions
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_audit_log_append_only"
down_revision: str | None = "0003_retention_extensions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRIGGERS = (
    (
        "CREATE TRIGGER trg_audit_log_guard_update BEFORE UPDATE ON audit_log FOR "
        "EACH ROW WHEN NEW.id IS NOT OLD.id OR NEW.occurred_at IS NOT "
        "OLD.occurred_at OR NEW.actor_label IS NOT OLD.actor_label OR NEW.actor_ip "
        "IS NOT OLD.actor_ip OR NEW.action IS NOT OLD.action OR NEW.entity_type IS "
        "NOT OLD.entity_type OR NEW.entity_id IS NOT OLD.entity_id OR "
        "NEW.before_value IS NOT OLD.before_value OR NEW.after_value IS NOT "
        "OLD.after_value OR NEW.outcome IS NOT OLD.outcome OR NEW.correlation_id IS"
        " NOT OLD.correlation_id OR (NEW.actor_user_id IS NOT OLD.actor_user_id AND"
        " NEW.actor_user_id IS NOT NULL) BEGIN SELECT RAISE(ABORT, 'audit_log: "
        "update not permitted'); END"
    ),
    (
        "CREATE TRIGGER trg_audit_log_no_delete BEFORE DELETE ON audit_log FOR EACH"
        " ROW BEGIN SELECT RAISE(ABORT, 'audit_log: delete not permitted'); END"
    ),
)


def upgrade() -> None:
    for statement in _TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_guard_update")
