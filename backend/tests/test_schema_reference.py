"""Tests that the Day 2 schema actually works on SQLite.

These execute the reference DDL with stdlib ``sqlite3`` and verify the
constraints the design depends on: foreign-key enforcement, CHECK constraints,
unique email, and cascade/SET NULL behaviour.

Scope note: the SQLAlchemy models are canonical. This suite proves the *schema
design* is sound; reconciling it against ``alembic upgrade head`` is a Day 2b
task recorded in schema_reference.sql.
"""

from __future__ import annotations

import sqlite3

import pytest

IDENTITY_TABLES = {"users", "family_members", "sessions", "audit_log"}
#: Added by migration 0002 (DD-09); behaviour tested in test_schema_events.py.
EVENT_TABLES = {
    "access_events",
    "visitor_events",
    "security_events",
    "incidents",
    "incident_evidence",
    "workflow_executions",
}
#: Added by migration 0003 (DD-11); tested in test_retention_extensions.py.
RETENTION_TABLES = {"retention_extensions"}
EXPECTED_TABLES = IDENTITY_TABLES | EVENT_TABLES | RETENTION_TABLES

#: The five tables that must NOT exist yet — each arrives with its module.
DEFERRED_TABLES = {
    "face_embeddings",
    "permissions",
    "pipeline_logs",
    "automation_tasks",
    "notifications",
}


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows if not r[0].startswith("sqlite_")}


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


# --- structure ---------------------------------------------------------------


def test_exactly_the_expected_tables_exist(sqlite_db: sqlite3.Connection) -> None:
    assert _table_names(sqlite_db) == EXPECTED_TABLES


def test_no_deferred_table_was_created_prematurely(
    sqlite_db: sqlite3.Connection,
) -> None:
    """No table is created before the module that owns it exists."""
    created = _table_names(sqlite_db)
    assert not (created & DEFERRED_TABLES)


def test_users_columns_match_design(sqlite_db: sqlite3.Connection) -> None:
    assert _columns(sqlite_db, "users") == {
        "id",
        "email",
        "password_hash",
        "full_name",
        "role",
        "is_active",
        "failed_login_count",
        "locked_until",
        "last_login_at",
        "created_at",
        "updated_at",
    }


def test_sessions_columns_match_design(sqlite_db: sqlite3.Connection) -> None:
    assert _columns(sqlite_db, "sessions") == {
        "id",
        "user_id",
        "refresh_token_hash",
        "parent_session_id",
        "ip_address",
        "user_agent",
        "issued_at",
        "expires_at",
        "revoked_at",
        "revoked_reason",
    }


def test_family_members_columns_match_design(
    sqlite_db: sqlite3.Connection,
) -> None:
    assert _columns(sqlite_db, "family_members") == {
        "id",
        "user_id",
        "full_name",
        "relationship",
        "member_type",
        "status",
        "enrollment_status",
        "notes",
        "created_at",
        "updated_at",
    }


def test_audit_log_columns_match_design(sqlite_db: sqlite3.Connection) -> None:
    assert _columns(sqlite_db, "audit_log") == {
        "id",
        "occurred_at",
        "actor_user_id",
        "actor_label",
        "actor_ip",
        "action",
        "entity_type",
        "entity_id",
        "before_value",
        "after_value",
        "outcome",
        "correlation_id",
    }


def test_sessions_has_no_plaintext_token_column(
    sqlite_db: sqlite3.Connection,
) -> None:
    """Only the hash may be stored (DATABASE_DESIGN.md 3.5)."""
    columns = _columns(sqlite_db, "sessions")
    assert "refresh_token" not in columns
    assert "refresh_token_hash" in columns


def test_users_has_no_plaintext_password_column(
    sqlite_db: sqlite3.Connection,
) -> None:
    columns = _columns(sqlite_db, "users")
    assert "password" not in columns
    assert "password_hash" in columns


# --- pragmas -----------------------------------------------------------------


def test_wal_mode_is_active(sqlite_db: sqlite3.Connection) -> None:
    mode = sqlite_db.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_foreign_keys_enforced(sqlite_db: sqlite3.Connection) -> None:
    assert sqlite_db.execute("PRAGMA foreign_keys").fetchone()[0] == 1


# --- constraints -------------------------------------------------------------


def _insert_user(conn: sqlite3.Connection, email: str = "a@example.com") -> int:
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
        (email, "$argon2id$dummy", "Test User", "admin"),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def test_email_is_unique(sqlite_db: sqlite3.Connection) -> None:
    _insert_user(sqlite_db, "dup@example.com")
    with pytest.raises(sqlite3.IntegrityError):
        _insert_user(sqlite_db, "dup@example.com")


def test_invalid_role_rejected(sqlite_db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        sqlite_db.execute(
            "INSERT INTO users (email, password_hash, full_name, role) "
            "VALUES (?, ?, ?, ?)",
            ("r@example.com", "h", "R", "superuser"),
        )


def test_invalid_member_status_rejected(sqlite_db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        sqlite_db.execute(
            "INSERT INTO family_members (full_name, status) VALUES (?, ?)",
            ("Someone", "deleted"),
        )


def test_invalid_audit_outcome_rejected(sqlite_db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        sqlite_db.execute(
            "INSERT INTO audit_log (action, entity_type, outcome) VALUES (?, ?, ?)",
            ("x", "y", "maybe"),
        )


def test_session_requires_existing_user(sqlite_db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        sqlite_db.execute(
            "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) "
            "VALUES (?, ?, ?)",
            (9999, "deadbeef", "2030-01-01T00:00:00+00:00"),
        )


def test_refresh_token_hash_is_unique(sqlite_db: sqlite3.Connection) -> None:
    user_id = _insert_user(sqlite_db, "u1@example.com")
    sqlite_db.execute(
        "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) "
        "VALUES (?, ?, ?)",
        (user_id, "samehash", "2030-01-01T00:00:00+00:00"),
    )
    sqlite_db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        sqlite_db.execute(
            "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) "
            "VALUES (?, ?, ?)",
            (user_id, "samehash", "2030-01-01T00:00:00+00:00"),
        )


def test_deleting_user_cascades_sessions(sqlite_db: sqlite3.Connection) -> None:
    user_id = _insert_user(sqlite_db, "cascade@example.com")
    sqlite_db.execute(
        "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) "
        "VALUES (?, ?, ?)",
        (user_id, "hash-cascade", "2030-01-01T00:00:00+00:00"),
    )
    sqlite_db.commit()
    sqlite_db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    sqlite_db.commit()
    remaining = sqlite_db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    assert remaining == 0


def test_deleting_user_preserves_audit_history(
    sqlite_db: sqlite3.Connection,
) -> None:
    """Audit entries must survive actor deletion (SR-AUDIT-06)."""
    user_id = _insert_user(sqlite_db, "audit@example.com")
    sqlite_db.execute(
        "INSERT INTO audit_log (actor_user_id, action, entity_type) VALUES (?, ?, ?)",
        (user_id, "login.success", "user"),
    )
    sqlite_db.commit()
    sqlite_db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    sqlite_db.commit()
    row = sqlite_db.execute("SELECT actor_user_id, action FROM audit_log").fetchone()
    assert row is not None, "audit entry was deleted with the user"
    assert row[0] is None, "actor should be SET NULL, not cascade-deleted"
    assert row[1] == "login.success"


def test_family_member_user_link_set_null_on_user_delete(
    sqlite_db: sqlite3.Connection,
) -> None:
    user_id = _insert_user(sqlite_db, "link@example.com")
    sqlite_db.execute(
        "INSERT INTO family_members (user_id, full_name) VALUES (?, ?)",
        (user_id, "Linked Person"),
    )
    sqlite_db.commit()
    sqlite_db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    sqlite_db.commit()
    row = sqlite_db.execute("SELECT user_id, full_name FROM family_members").fetchone()
    assert row is not None, "family member must not be deleted with the user"
    assert row[0] is None


def test_defaults_match_design(sqlite_db: sqlite3.Connection) -> None:
    _insert_user(sqlite_db, "defaults@example.com")
    sqlite_db.execute(
        "INSERT INTO family_members (full_name) VALUES (?)", ("Default Person",)
    )
    sqlite_db.commit()
    row = sqlite_db.execute(
        "SELECT member_type, status, enrollment_status FROM family_members"
    ).fetchone()
    assert row == ("family", "active", "not_enrolled")


# --- alignment with the canonical SQLAlchemy models (Day 2B, defect D9) ------
#
# The models are canonical. These tests pin the properties of the model-emitted
# DDL that the reference must mirror, so drift is caught without SQLAlchemy.

#: Columns the models declare with the UtcDateTime type (DDL type DATETIME).
TIMESTAMP_COLUMNS = {
    "users": {"locked_until", "last_login_at", "created_at", "updated_at"},
    "family_members": {"created_at", "updated_at"},
    "sessions": {"issued_at", "expires_at", "revoked_at"},
    "audit_log": {"occurred_at"},
}

#: Non-automatic indexes per table (DATABASE_DESIGN.md sections 3 and 7).
EXPECTED_INDEXES = {
    "users": {"ix_users_email"},
    "family_members": {"ix_family_members_status"},
    "sessions": {
        "ix_sessions_refresh_token_hash",
        "ix_sessions_user_id",
        "ix_sessions_expires_at",
    },
    "audit_log": {
        "ix_audit_log_occurred_at",
        "ix_audit_log_actor_user_id",
        "ix_audit_log_action",
        "ix_audit_log_entity",
    },
}


def _unique_indexes_covering(
    conn: sqlite3.Connection, table: str, column: str
) -> list[str]:
    names = []
    for _seq, name, unique, _origin, _partial in conn.execute(
        f"PRAGMA index_list({table})"
    ):
        cols = [r[2] for r in conn.execute(f"PRAGMA index_info({name})")]
        if unique and cols == [column]:
            names.append(name)
    return names


@pytest.mark.parametrize(
    "table,column",
    [("users", "email"), ("sessions", "refresh_token_hash")],
)
def test_unique_column_has_exactly_one_unique_index(
    sqlite_db: sqlite3.Connection, table: str, column: str
) -> None:
    """The models emit one unique index; an extra UNIQUE constraint is drift."""
    assert _unique_indexes_covering(sqlite_db, table, column) == [
        f"ix_{table}_{column}"
    ]


def test_no_autoincrement(sqlite_db: sqlite3.Connection) -> None:
    """The models do not request AUTOINCREMENT, so the reference must not."""
    ddl = " ".join(
        r[0] for r in sqlite_db.execute("SELECT sql FROM sqlite_master") if r[0]
    )
    assert "AUTOINCREMENT" not in ddl.upper()


def test_timestamp_columns_are_declared_datetime(
    sqlite_db: sqlite3.Connection,
) -> None:
    """UtcDateTime renders as DATETIME; TEXT would change SQLite affinity."""
    for table, columns in TIMESTAMP_COLUMNS.items():
        declared = {
            row[1]: row[2].upper()
            for row in sqlite_db.execute(f"PRAGMA table_info({table})")
        }
        for column in columns:
            assert declared[column] == "DATETIME", f"{table}.{column}"


def test_indexes_match_design(sqlite_db: sqlite3.Connection) -> None:
    for table, expected in EXPECTED_INDEXES.items():
        actual = {
            row[1]
            for row in sqlite_db.execute(f"PRAGMA index_list({table})")
            if not row[1].startswith("sqlite_autoindex")
        }
        assert actual == expected, table
