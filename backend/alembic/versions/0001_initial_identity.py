"""Day 2 initial identity schema: users, sessions, family_members, audit_log.

Only the four tables modules M01/M02/M12 need are created. The remaining
eleven tables from DATABASE_DESIGN.md arrive with their owning module, so no
unused or placeholder table is introduced.

Constraint and index names are wrapped in ``op.f()``, which marks them as final.
Alembic applies the target metadata's naming convention to operations, and the
CHECK convention ``ck_%(table_name)s_%(constraint_name)s`` would otherwise turn
"ck_users_role_valid" into "ck_users_ck_users_role_valid".

Unique columns get a unique INDEX only, matching the models
(``unique=True, index=True`` emits one unique index, not a separate constraint).

This revision was edited in place on Day 2B because it had never been applied
to any database. Once applied anywhere, it is immutable; changes go in 0002+.

Revision ID: 0001_initial_identity
Revises: None
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_identity"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column(
            "role", sa.String(length=20), nullable=False, server_default="viewer"
        ),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "failed_login_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
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
        sa.CheckConstraint(
            "role IN ('admin', 'member', 'viewer')", name=op.f("ck_users_role_valid")
        ),
        sa.CheckConstraint("is_active IN (0, 1)", name=op.f("ck_users_is_active_bool")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "family_members",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("relationship", sa.String(length=100), nullable=True),
        sa.Column(
            "member_type",
            sa.String(length=30),
            nullable=False,
            server_default="family",
        ),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="active"
        ),
        sa.Column(
            "enrollment_status",
            sa.String(length=30),
            nullable=False,
            server_default="not_enrolled",
        ),
        sa.Column("notes", sa.Text(), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'revoked')",
            name=op.f("ck_family_members_status_valid"),
        ),
        sa.CheckConstraint(
            "member_type IN ('family', 'resident', 'staff', 'recurring_visitor')",
            name=op.f("ck_family_members_member_type_valid"),
        ),
        sa.CheckConstraint(
            "enrollment_status IN ('not_enrolled', 'enrolled', 'needs_reenrollment')",
            name=op.f("ck_family_members_enrollment_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_family_members_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_family_members")),
    )
    op.create_index(op.f("ix_family_members_status"), "family_members", ["status"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("parent_session_id", sa.Integer(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column(
            "issued_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_session_id"],
            ["sessions.id"],
            name=op.f("fk_sessions_parent_session_id_sessions"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
    )
    op.create_index(
        op.f("ix_sessions_refresh_token_hash"),
        "sessions",
        ["refresh_token_hash"],
        unique=True,
    )
    op.create_index(op.f("ix_sessions_user_id"), "sessions", ["user_id"])
    op.create_index(op.f("ix_sessions_expires_at"), "sessions", ["expires_at"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "actor_label",
            sa.String(length=50),
            nullable=False,
            server_default="system",
        ),
        sa.Column("actor_ip", sa.String(length=45), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_id", sa.String(length=50), nullable=True),
        sa.Column("before_value", sa.Text(), nullable=True),
        sa.Column("after_value", sa.Text(), nullable=True),
        sa.Column(
            "outcome", sa.String(length=20), nullable=False, server_default="success"
        ),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure')",
            name=op.f("ck_audit_log_outcome_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name=op.f("fk_audit_log_actor_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index(op.f("ix_audit_log_occurred_at"), "audit_log", ["occurred_at"])
    op.create_index(op.f("ix_audit_log_actor_user_id"), "audit_log", ["actor_user_id"])
    op.create_index(op.f("ix_audit_log_action"), "audit_log", ["action"])
    op.create_index(
        op.f("ix_audit_log_entity"), "audit_log", ["entity_type", "entity_id"]
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("sessions")
    op.drop_table("family_members")
    op.drop_table("users")
