"""The read-only database boundary that contains the AI tier.

SR-AI-05/06 require that the AI tier (M15-M18, Days 8-11) hold no write
capability. The design achieves this with a SQLite ``mode=ro`` URI connection,
which refuses writes *inside the database engine* rather than relying on
application-layer discipline.

These tests prove the mechanism works, today, with stdlib ``sqlite3``. The
production wiring in ``app/database/session.py`` uses the same URI through
SQLAlchemy, so verifying the underlying guarantee here is meaningful even
while SQLAlchemy is uninstallable.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

#: Statements the AI tier must never be able to execute.
FORBIDDEN_WRITES = [
    ("INSERT", "INSERT INTO audit_log (action, entity_type) VALUES ('x','y')"),
    ("UPDATE", "UPDATE users SET role = 'admin'"),
    ("DELETE", "DELETE FROM audit_log"),
    ("CREATE", "CREATE TABLE ai_backdoor (id INTEGER)"),
    ("DROP", "DROP TABLE audit_log"),
    ("ALTER", "ALTER TABLE users ADD COLUMN injected TEXT"),
]


@pytest.fixture
def seeded_db(tmp_path: Path, schema_sql: str) -> Path:
    """A database with the Day 2 schema and one row, closed and on disk."""
    path = tmp_path / "ro_boundary.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(schema_sql)
    conn.execute(
        "INSERT INTO users (email, password_hash, full_name, role) "
        "VALUES ('owner@example.com', '$argon2id$dummy', 'Owner', 'admin')"
    )
    conn.commit()
    conn.close()
    return path


def _readonly_connection(path: Path) -> sqlite3.Connection:
    """Open the same way ``create_readonly_engine`` does."""
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def test_readonly_connection_can_read(seeded_db: Path) -> None:
    conn = _readonly_connection(seeded_db)
    try:
        row = conn.execute("SELECT email, role FROM users").fetchone()
        assert row == ("owner@example.com", "admin")
    finally:
        conn.close()


@pytest.mark.parametrize(
    "label,statement", FORBIDDEN_WRITES, ids=[w[0] for w in FORBIDDEN_WRITES]
)
def test_readonly_connection_rejects_writes(
    seeded_db: Path, label: str, statement: str
) -> None:
    """Every write class must fail at the engine level."""
    conn = _readonly_connection(seeded_db)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            conn.execute(statement)
            conn.commit()
    finally:
        conn.close()


def test_data_survives_attempted_writes(seeded_db: Path) -> None:
    """A rejected write must leave no trace."""
    conn = _readonly_connection(seeded_db)
    try:
        for _label, statement in FORBIDDEN_WRITES:
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(statement)
    finally:
        conn.close()

    verify = sqlite3.connect(seeded_db)
    try:
        count = verify.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        role = verify.execute("SELECT role FROM users").fetchone()[0]
        tables = {
            r[0]
            for r in verify.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert count == 1
        assert role == "admin", "privilege escalation via read-only session"
        assert "ai_backdoor" not in tables
        assert "audit_log" in tables, "audit table was dropped"
    finally:
        verify.close()


def test_writer_connection_still_works(seeded_db: Path) -> None:
    """The boundary must not break legitimate writes by the deterministic core."""
    conn = sqlite3.connect(seeded_db)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "INSERT INTO audit_log (action, entity_type) VALUES (?, ?)",
            ("member.create", "family_member"),
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    finally:
        conn.close()
