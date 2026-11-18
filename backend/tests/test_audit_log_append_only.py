"""Finding S4: audit_log is append-only inside the database (SR-AUDIT-06/07).

Runs the reference DDL on real SQLite. Migration 0004 carries the same
trigger text (checked in test_schema_parity.py); it has not been applied
with Alembic, which cannot be installed here.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest


@pytest.fixture
def db(sqlite_db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    sqlite_db.execute(
        "INSERT INTO users (id, email, password_hash, full_name, role) "
        "VALUES (1, 'admin@example.com', 'h', 'Admin', 'admin')"
    )
    sqlite_db.execute(
        "INSERT INTO audit_log (id, actor_user_id, actor_label, actor_ip, action,"
        " entity_type, entity_id, before_value, after_value, outcome,"
        " correlation_id) VALUES (1, 1, 'admin', '10.0.0.2', 'permission.update',"
        " 'permission', '7', '{\"door\": \"main\"}', '{\"door\": \"all\"}',"
        " 'success', 'c-1')"
    )
    sqlite_db.commit()
    yield sqlite_db


def rejected(conn: sqlite3.Connection, sql: str) -> str:
    with pytest.raises(sqlite3.IntegrityError) as info:
        conn.execute(sql)
        conn.commit()
    conn.rollback()
    return str(info.value)


@pytest.mark.parametrize(
    "column,value",
    [
        ("action", "'nothing'"),
        ("before_value", "NULL"),
        ("after_value", '\'{"door": "main"}\''),
        ("outcome", "'failure'"),
        ("actor_label", "'system'"),
        ("actor_ip", "NULL"),
        ("entity_id", "'8'"),
        ("occurred_at", "'2020-01-01 00:00:00'"),
        ("correlation_id", "NULL"),
        ("id", "2"),
        ("actor_user_id", "2"),
    ],
)
def test_audit_entries_cannot_be_edited(
    db: sqlite3.Connection, column: str, value: str
) -> None:
    message = rejected(db, f"UPDATE audit_log SET {column} = {value}")  # noqa: S608
    assert "audit_log: update not permitted" in message


def test_audit_entries_cannot_be_deleted(db: sqlite3.Connection) -> None:
    assert "delete not permitted" in rejected(db, "DELETE FROM audit_log")
    assert db.execute("SELECT COUNT(*) FROM audit_log").fetchone() == (1,)


def test_entry_is_unchanged_after_refused_writes(db: sqlite3.Connection) -> None:
    before = db.execute("SELECT * FROM audit_log").fetchall()
    for sql in [
        "UPDATE audit_log SET after_value = '{}'",
        "DELETE FROM audit_log WHERE id = 1",
    ]:
        rejected(db, sql)
    assert db.execute("SELECT * FROM audit_log").fetchall() == before


def test_new_entries_can_still_be_written(db: sqlite3.Connection) -> None:
    db.execute(
        "INSERT INTO audit_log (action, entity_type) VALUES ('login.failure', 'user')"
    )
    db.commit()
    assert db.execute("SELECT COUNT(*) FROM audit_log").fetchone() == (2,)


def test_user_deletion_still_sets_actor_null_and_keeps_entry(
    db: sqlite3.Connection,
) -> None:
    """ON DELETE SET NULL is an UPDATE; the trigger allows exactly that."""
    db.execute("DELETE FROM users WHERE id = 1")
    db.commit()
    row = db.execute(
        "SELECT actor_user_id, actor_label, action, after_value FROM audit_log"
    ).fetchone()
    assert row == (None, "admin", "permission.update", '{"door": "all"}')


def test_no_op_update_is_allowed(db: sqlite3.Connection) -> None:
    db.execute("UPDATE audit_log SET action = action")
    db.commit()
