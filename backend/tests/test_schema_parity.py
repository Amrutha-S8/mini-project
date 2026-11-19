"""Schema parity: SQLAlchemy models vs Alembic migration vs reference SQL.

The models are canonical. Day 2B step 3 asks that the migrated database be
compared with ``schema_reference.sql`` and that differences be resolved.

* Runs now (stdlib): migrations 0001-0002 parsed statically, compared with the
  reference SQL executed in a real SQLite database; plus checks that the
  comparator actually detects drift.
* Runs once the stack installs: ``alembic upgrade head`` and
  ``Base.metadata.create_all`` on real databases, compared with each other
  and with the reference. Until then it SKIPS with an explicit reason.
"""

from __future__ import annotations

import importlib.metadata
import sqlite3
from pathlib import Path

import pytest

from tests.conftest import BACKEND_ROOT, SCHEMA_REFERENCE
from tests.schema_tools import (
    describe_migration,
    describe_migrations,
    describe_sqlite,
    diff_schemas,
    normalise_default,
)

VERSIONS = BACKEND_ROOT / "alembic" / "versions"
MIGRATION_0001 = VERSIONS / "0001_initial_identity.py"
MIGRATION_0002 = VERSIONS / "0002_events_incidents_workflows.py"
MIGRATION_0003 = VERSIONS / "0003_retention_extensions.py"
MIGRATION_0004 = VERSIONS / "0004_audit_log_append_only.py"
MIGRATION_0005 = VERSIONS / "0005_detections_notifications.py"
MIGRATIONS = [
    MIGRATION_0001,
    MIGRATION_0002,
    MIGRATION_0003,
    MIGRATION_0004,
    MIGRATION_0005,
]
HEAD_REVISION = "0005_detections_notifications"
RETENTION_TABLES = {"retention_extensions"}
MONITORING_TABLES = {"incident_detections", "notifications"}
IDENTITY_TABLES = {"users", "family_members", "sessions", "audit_log"}
EVENT_TABLES = {
    "access_events",
    "visitor_events",
    "security_events",
    "incidents",
    "incident_evidence",
    "workflow_executions",
}
EXPECTED_TABLES = IDENTITY_TABLES | EVENT_TABLES | RETENTION_TABLES | MONITORING_TABLES


def _reference_db(path: Path, sql: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    if sql is None:
        sql = SCHEMA_REFERENCE.read_text(encoding="utf-8")
    conn.executescript(sql)
    return conn


# --- runs now ----------------------------------------------------------------


def test_reference_schema_has_exactly_the_expected_tables(tmp_path: Path) -> None:
    schema = describe_sqlite(_reference_db(tmp_path / "ref.db"))
    assert set(schema) == EXPECTED_TABLES


def test_versions_directory_holds_exactly_the_known_migrations() -> None:
    found = sorted(p.name for p in VERSIONS.glob("*.py"))
    assert found == [p.name for p in MIGRATIONS]


def test_migration_0001_creates_only_identity_tables() -> None:
    assert set(describe_migration(MIGRATION_0001)) == IDENTITY_TABLES


def test_migration_0002_creates_only_event_tables() -> None:
    assert set(describe_migration(MIGRATION_0002)) == EVENT_TABLES


def test_migration_0003_creates_only_retention_table() -> None:
    described = describe_migration(MIGRATION_0003)
    later = described.pop("<triggers on existing tables>", {})
    assert set(described) == RETENTION_TABLES
    assert set(later) == {"incident_evidence"}


def test_migration_0004_only_adds_audit_log_triggers() -> None:
    described = describe_migration(MIGRATION_0004)
    later = described.pop("<triggers on existing tables>", {})
    assert described == {}
    assert set(later) == {"audit_log"}
    assert set(later["audit_log"]) == {
        "trg_audit_log_guard_update",
        "trg_audit_log_no_delete",
    }


def test_migration_0005_adds_monitoring_tables_and_incident_columns() -> None:
    from tests.schema_tools import LATER_COLUMNS

    described = describe_migration(MIGRATION_0005)
    added = described.pop(LATER_COLUMNS, {})
    assert described.pop("<triggers on existing tables>", {}) == {}
    assert set(described) == MONITORING_TABLES
    assert set(added) == {"incidents"}
    assert set(added["incidents"]) == {"acknowledged_at", "acknowledged_by_user_id"}
    # ADD COLUMN must stay nullable without a default (no table rebuild).
    assert all(not notnull for _aff, notnull, _d in added["incidents"].values())


@pytest.mark.parametrize(
    "path,revision,down",
    [
        (MIGRATION_0002, "0002_events_incidents_workflows", "0001_initial_identity"),
        (
            MIGRATION_0003,
            "0003_retention_extensions",
            "0002_events_incidents_workflows",
        ),
        (
            MIGRATION_0004,
            "0004_audit_log_append_only",
            "0003_retention_extensions",
        ),
        (
            MIGRATION_0005,
            "0005_detections_notifications",
            "0004_audit_log_append_only",
        ),
    ],
)
def test_migration_chain(path: Path, revision: str, down: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert f'down_revision: str | None = "{down}"' in text
    assert f'revision: str = "{revision}"' in text


def test_migrations_match_reference_schema(tmp_path: Path) -> None:
    """Static parity between migrations 0001+0002 and the reference DDL.

    Covers columns, defaults, indexes, foreign keys, CHECK constraints and
    append-only triggers.
    """
    migration = describe_migrations(MIGRATIONS)
    reference = describe_sqlite(_reference_db(tmp_path / "ref.db"))
    assert diff_schemas(migration, reference, ("migration", "reference")) == []


def test_comparator_is_clean_on_identical_schemas(tmp_path: Path) -> None:
    a = describe_sqlite(_reference_db(tmp_path / "a.db"))
    b = describe_sqlite(_reference_db(tmp_path / "b.db"))
    assert diff_schemas(a, b, ("a", "b")) == []


@pytest.mark.parametrize(
    "description,old,new",
    [
        (
            "redundant UNIQUE constraint",
            "email               TEXT    NOT NULL,",
            "email               TEXT    NOT NULL UNIQUE,",
        ),
        (
            "missing index",
            "CREATE INDEX IF NOT EXISTS ix_audit_log_action"
            "        ON audit_log (action);",
            "",
        ),
        (
            "changed ON DELETE action",
            "REFERENCES users (id) ON DELETE CASCADE",
            "REFERENCES users (id) ON DELETE SET NULL",
        ),
        (
            "changed CHECK expression",
            "CHECK (outcome IN ('success', 'failure'))",
            "CHECK (outcome IN ('success', 'failure', 'unknown'))",
        ),
        (
            "changed default",
            "role                TEXT    NOT NULL DEFAULT 'viewer',",
            "role                TEXT    NOT NULL DEFAULT 'admin',",
        ),
        (
            "changed affinity",
            "expires_at          DATETIME NOT NULL,",
            "expires_at          TEXT NOT NULL,",
        ),
        (
            "dropped NOT NULL",
            "full_name           TEXT    NOT NULL,\n    relationship",
            "full_name           TEXT,\n    relationship",
        ),
        (
            "weakened append-only trigger",
            "        OR (OLD.incident_id IS NOT NULL AND "
            "NEW.incident_id IS NOT OLD.incident_id)\n",
            "",
        ),
        (
            "dropped delete guard",
            "CREATE TRIGGER IF NOT EXISTS trg_incidents_no_delete",
            "CREATE TRIGGER IF NOT EXISTS trg_incidents_no_delete_renamed",
        ),
        (
            "changed REAL affinity",
            "match_confidence        REAL,",
            "match_confidence        TEXT,",
        ),
    ],
)
def test_comparator_detects_drift(
    tmp_path: Path, description: str, old: str, new: str
) -> None:
    sql = SCHEMA_REFERENCE.read_text(encoding="utf-8")
    assert old in sql, f"mutation anchor not found for: {description}"
    baseline = describe_sqlite(_reference_db(tmp_path / "base.db"))
    mutated = describe_sqlite(
        _reference_db(tmp_path / "mut.db", sql.replace(old, new, 1))
    )
    assert diff_schemas(baseline, mutated, ("base", "mutated")), (
        f"comparator missed: {description}"
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("'viewer'", "viewer"),
        ("viewer", "viewer"),
        ("(CURRENT_TIMESTAMP)", "CURRENT_TIMESTAMP"),
        ("CURRENT_TIMESTAMP", "CURRENT_TIMESTAMP"),
        ("'1'", "1"),
        ("1", "1"),
        (None, None),
    ],
)
def test_default_normalisation(raw: str | None, expected: str | None) -> None:
    assert normalise_default(raw) == expected


# --- runs once the approved stack installs -----------------------------------

#: Checked by installed DISTRIBUTION, not importlib.util.find_spec: the local
#: backend/alembic/ migrations directory is importable as a namespace package,
#: so find_spec("alembic") succeeds even when the library is absent.
_RUNTIME_STACK = ("SQLAlchemy", "alembic")


def _distribution_installed(name: str) -> bool:
    try:
        importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


_MISSING = [d for d in _RUNTIME_STACK if not _distribution_installed(d)]


@pytest.mark.skipif(
    bool(_MISSING),
    reason=(
        "needs " + ", ".join(_MISSING) + " to run migrations "
        "(PyPI unreachable - PROJECT_AUDIT.md blocker E1)"
    ),
)
def test_alembic_models_and_reference_produce_identical_schemas(
    tmp_path: Path,
) -> None:
    """The authoritative runtime check for Day 2B step 3."""
    # mypy resolves "alembic" to the local migrations directory (a namespace
    # package) while the library is absent; at runtime the installed regular
    # package always takes precedence over a namespace portion.
    from alembic import command  # type: ignore[attr-defined]
    from alembic.config import Config
    from sqlalchemy import create_engine

    import app.models  # noqa: F401
    from app.database.base import Base

    migrated_path = tmp_path / "alembic.db"
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{migrated_path}")
    command.upgrade(cfg, "head")

    models_path = tmp_path / "models.db"
    engine = create_engine(f"sqlite:///{models_path}")
    Base.metadata.create_all(engine)
    engine.dispose()

    migrated = describe_sqlite(sqlite3.connect(migrated_path))
    models = describe_sqlite(sqlite3.connect(models_path))
    reference = describe_sqlite(_reference_db(tmp_path / "ref.db"))

    assert set(migrated) == EXPECTED_TABLES
    assert diff_schemas(models, migrated, ("models", "alembic")) == []
    assert diff_schemas(models, reference, ("models", "reference")) == []

    version = (
        sqlite3.connect(migrated_path)
        .execute("SELECT version_num FROM alembic_version")
        .fetchall()
    )
    assert version == [(HEAD_REVISION,)], "version stamp not committed"
