"""Shared pytest fixtures and dependency gating.

Two classes of test live in this suite:

1. Tests that run on the Python standard library alone. These execute and pass
   in the current sandbox and verify real behaviour.
2. Tests that need the approved stack (FastAPI, SQLAlchemy, Pydantic,
   argon2-cffi, PyJWT). Those packages cannot be installed here because PyPI
   is unreachable (PROJECT_AUDIT.md blocker E1), so these tests SKIP with an
   explicit reason. They are never faked, stubbed, or reported as passing.
"""

from __future__ import annotations

import importlib.util
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
APP_ROOT = BACKEND_ROOT / "app"
SCHEMA_REFERENCE = APP_ROOT / "database" / "schema_reference.sql"

#: Packages required by the approved stack.
REQUIRED_STACK = (
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "pydantic_settings",
    "argon2",
    "jwt",
)


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


MISSING_STACK = tuple(m for m in REQUIRED_STACK if not _installed(m))
STACK_AVAILABLE = not MISSING_STACK

#: Marker applied to tests that cannot run without the approved stack.
requires_stack = pytest.mark.skipif(
    not STACK_AVAILABLE,
    reason=(
        "approved stack not installed: missing "
        + ", ".join(MISSING_STACK)
        + " (PyPI unreachable - PROJECT_AUDIT.md blocker E1)"
    ),
)


@pytest.fixture(scope="session")
def schema_sql() -> str:
    """The Day 2 reference DDL."""
    assert SCHEMA_REFERENCE.is_file(), f"missing {SCHEMA_REFERENCE}"
    return SCHEMA_REFERENCE.read_text(encoding="utf-8")


@pytest.fixture
def sqlite_db(tmp_path: Path, schema_sql: str) -> Iterator[sqlite3.Connection]:
    """A real on-disk SQLite database with the Day 2 schema applied.

    On-disk rather than in-memory so WAL mode and the read-only URI behave as
    they do in production.
    """
    db_path = tmp_path / "test_smarthome.db"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(schema_sql)
    # executescript commits and resets pragmas on some versions; re-assert.
    conn.execute("PRAGMA foreign_keys=ON")
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def sqlite_db_path(sqlite_db: sqlite3.Connection, tmp_path: Path) -> Path:
    """Path of the database created by :func:`sqlite_db`."""
    return tmp_path / "test_smarthome.db"


# --- API fixtures (need the approved stack) ------------------------------------

#: The first admin, created in ``app_client`` through ``create_first_admin``,
#: the same function the ``create-admin`` CLI uses.
ADMIN_PAYLOAD = {
    "email": "admin@example.com",
    "password": "Adm1n-Household-Pass",
    "full_name": "Household Admin",
}


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """TestClient bound to a fresh temporary database with one admin.

    Imports happen inside the fixture so collection does not fail when the
    stack is absent. Tests using it must carry the ``requires_stack`` marker.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session

    import app.models  # noqa: F401  (registers tables on Base.metadata)
    from app.core.config import Settings
    from app.database.base import Base
    from app.database.session import create_writer_engine
    from app.main import create_app
    from app.services.auth_service import create_first_admin

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-at-least-32-characters-long")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))

    settings = Settings()
    engine = create_writer_engine(settings)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        create_first_admin(
            db,
            email=ADMIN_PAYLOAD["email"],
            password=ADMIN_PAYLOAD["password"],
            full_name=ADMIN_PAYLOAD["full_name"],
        )
        db.commit()
    engine.dispose()

    from app.core.tasks import InlineTaskRunner

    application = create_app(settings)
    # Run notification jobs synchronously so tests can assert on their rows.
    application.state.task_runner = InlineTaskRunner()
    with TestClient(application) as client:
        yield client
