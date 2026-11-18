"""Migration 0002 tables: behaviour on real SQLite, and agreement with the code.

Stdlib only. The reference DDL is executed with ``sqlite3`` and exercised
directly: CHECK constraints, foreign keys, append-only triggers, purge rules,
the AI-labelling rule, and the evidence-reference check that mirrors P1.
The canonical SQLAlchemy models are compared with the reference statically,
and the CHECK value lists are compared with the domain enums they mirror.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.database import append_only
from app.domain.access_engine import Outcome, Source
from app.domain.events import OUTCOMES, Modality, Severity
from tests.conftest import APP_ROOT
from tests.schema_tools import (
    describe_models,
    describe_sqlite,
    diff_schemas,
    normalise_trigger,
)
from tests.test_evidence_paths import MALICIOUS, VALID

MODELS = sorted(
    p for p in (APP_ROOT / "models").glob("*.py") if not p.name.startswith("_")
)
GUARDED = sorted(set(append_only.UPDATE_RULES) | set(append_only.NO_DELETE))
T0 = "2026-11-16 10:00:00.000000"
T1 = "2026-11-16 10:05:00.000000"
LATER = "2026-12-16 10:00:00.000000"
SHA = "a" * 64


@pytest.fixture
def db(sqlite_db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    sqlite_db.execute(
        "INSERT INTO users (id, email, password_hash, full_name, role) "
        "VALUES (1, 'admin@example.com', 'h', 'Admin', 'admin')"
    )
    sqlite_db.execute(
        "INSERT INTO family_members (id, user_id, full_name) VALUES (1, 1, 'Alex')"
    )
    sqlite_db.commit()
    yield sqlite_db


def insert(conn: sqlite3.Connection, table: str, **values: Any) -> int:
    """Insert with bound values. Table and column names come from test code."""
    cols = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    sql = f"INSERT INTO {table} ({cols}) VALUES ({marks})"  # noqa: S608
    cur = conn.execute(sql, tuple(values.values()))
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def access_event(conn: sqlite3.Connection, **overrides: Any) -> int:
    values: dict[str, Any] = {
        "decision_id": f"d-{overrides.get('n', 1)}",
        "request_id": "r-1",
        "occurred_at": T0,
        "door_id": "main",
        "source": "camera",
        "decision": "deny",
        "rule_number": 3,
        "rule_name": "identity",
        "reason_code": "unknown_identity",
        "engine_version": "1",
        "correlation_id": "c-1",
    }
    overrides.pop("n", None)
    values.update(overrides)
    return insert(conn, "access_events", **values)


def security_event(conn: sqlite3.Connection, **overrides: Any) -> int:
    values: dict[str, Any] = {
        "event_uid": "e-1",
        "event_type": "auth.login_failed",
        "modality": "auth",
        "severity": "low",
        "outcome": "failed",
        "suspicious": 1,
        "occurred_at": T0,
        "received_at": T0,
        "source_module": "auth_service",
    }
    values.update(overrides)
    return insert(conn, "security_events", **values)


def incident(conn: sqlite3.Connection, **overrides: Any) -> int:
    values: dict[str, Any] = {
        "incident_uid": "inc-1",
        "opened_at": T0,
        "title": "Repeated failed logins",
        "category": "credential_attack",
        "severity": "medium",
    }
    values.update(overrides)
    return insert(conn, "incidents", **values)


def visitor_event(conn: sqlite3.Connection, **overrides: Any) -> int:
    values: dict[str, Any] = {
        "occurred_at": T0,
        "camera_id": "cam1",
        "visitor_cluster_key": "v-4",
        "snapshot_ref": "snap/1.jpg",
        "snapshot_sha256": SHA,
        "retention_expires_at": LATER,
    }
    values.update(overrides)
    return insert(conn, "visitor_events", **values)


def workflow(conn: sqlite3.Connection, **overrides: Any) -> int:
    values: dict[str, Any] = {
        "run_uid": "run-1",
        "execution_kind": "langgraph_workflow",
        "workflow_name": "supervisor",
        "trigger_source": "manual",
        "started_at": T0,
        "requested_by_user_id": 1,
    }
    values.update(overrides)
    return insert(conn, "workflow_executions", **values)


def rejected(conn: sqlite3.Connection, sql: str, *params: Any) -> str:
    with pytest.raises(sqlite3.IntegrityError) as info:
        conn.execute(sql, params)
        conn.commit()
    conn.rollback()
    return str(info.value)


# --- agreement with code -------------------------------------------------------


def test_models_match_reference_schema(sqlite_db: sqlite3.Connection) -> None:
    """Static parity: the canonical models against the executed reference DDL."""
    models = describe_models(MODELS)
    reference = describe_sqlite(sqlite_db)
    assert diff_schemas(models, reference, ("models", "reference")) == []


def test_model_parser_detects_drift(
    tmp_path: Path, sqlite_db: sqlite3.Connection
) -> None:
    source = (APP_ROOT / "models" / "access_event.py").read_text(encoding="utf-8")
    mutated = tmp_path / "access_event.py"
    mutated.write_text(
        source.replace('name="review_never_holds"', 'name="review_may_hold"'),
        encoding="utf-8",
    )
    others = [p for p in MODELS if p.name != "access_event.py"]
    problems = diff_schemas(
        describe_models([*others, mutated]),
        describe_sqlite(sqlite_db),
        ("models", "reference"),
    )
    assert any("review" in p for p in problems)


def _check_values(conn: sqlite3.Connection, table: str, check: str) -> set[str]:
    ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()[0]
    match = re.search(rf"CONSTRAINT {check}\s+CHECK \(\w+ IN \(([^)]*)\)\)", ddl)
    assert match, f"{check} not found"
    return set(re.findall(r"'([^']*)'", match.group(1)))


@pytest.mark.parametrize(
    "table,check,expected",
    [
        (
            "access_events",
            "ck_access_events_decision_valid",
            {o.value for o in Outcome},
        ),
        (
            "access_events",
            "ck_access_events_source_valid",
            {s.value for s in Source},
        ),
        (
            "security_events",
            "ck_security_events_modality_valid",
            {m.value for m in Modality},
        ),
        (
            "security_events",
            "ck_security_events_severity_valid",
            {s.name.lower() for s in Severity},
        ),
        ("security_events", "ck_security_events_outcome_valid", set(OUTCOMES)),
        (
            "incidents",
            "ck_incidents_severity_valid",
            {s.name.lower() for s in Severity},
        ),
    ],
)
def test_check_lists_match_domain_enums(
    sqlite_db: sqlite3.Connection, table: str, check: str, expected: set[str]
) -> None:
    assert _check_values(sqlite_db, table, check) == expected


def test_every_column_of_a_guarded_table_is_classified(
    sqlite_db: sqlite3.Connection,
) -> None:
    for table, rule in append_only.UPDATE_RULES.items():
        columns = {r[1] for r in sqlite_db.execute(f"PRAGMA table_info({table})")}
        assert rule.columns == columns, table


def test_reference_triggers_match_canonical_text(sqlite_db: sqlite3.Connection) -> None:
    stored = {
        name: normalise_trigger(sql)[2]
        for name, sql in sqlite_db.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
        )
    }
    canonical = {
        normalise_trigger(s)[0]: normalise_trigger(s)[2]
        for statements in append_only.all_trigger_statements().values()
        for s in statements
    }
    assert stored == canonical


def test_no_biometric_or_secret_columns(sqlite_db: sqlite3.Connection) -> None:
    """The new tables store references and redacted text, never raw secrets."""
    forbidden = re.compile(
        r"(^|_)(embedding|vector|password|token|secret|api_key|image|photo|blob)(_|$)"
    )
    for table in GUARDED:
        for _cid, name, decl, *_ in sqlite_db.execute(f"PRAGMA table_info({table})"):
            assert "BLOB" not in decl.upper(), f"{table}.{name}"
            if name.endswith("_id"):
                # e.g. matched_embedding_id: a row id, never the vector itself
                assert decl.upper() in {"INTEGER", "TEXT"}, f"{table}.{name}"
                continue
            assert not forbidden.search(name), f"{table}.{name}"


def test_visitor_events_have_no_identity_columns(sqlite_db: sqlite3.Connection) -> None:
    columns = {r[1] for r in sqlite_db.execute("PRAGMA table_info(visitor_events)")}
    assert not {"family_member_id", "user_id", "full_name", "name"} & columns


# --- access_events -----------------------------------------------------------


def test_all_three_outcomes_recordable(db: sqlite3.Connection) -> None:
    for n, decision in enumerate(("allow", "deny", "hold"), start=1):
        access_event(db, n=n, decision=decision)
    assert db.execute("SELECT COUNT(*) FROM access_events").fetchone()[0] == 3


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"decision": "granted"}, "decision_valid"),
        ({"source": "ai_agent"}, "source_valid"),
        ({"rule_number": -1}, "rule_number_valid"),
        ({"match_confidence": 1.5}, "match_confidence_range"),
        ({"threshold_used": 0}, "threshold_range"),
        ({"decision_latency_ms": -1}, "latency_nonnegative"),
        ({"review_of_decision_id": "d-0"}, "review_link_only_for_reviews"),
        (
            {"source": "admin_review", "decision": "hold"},
            "review_never_holds",
        ),
    ],
)
def test_access_event_constraints(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match=constraint):
        access_event(db, **overrides)


def test_ai_cannot_be_recorded_as_a_decision_source(db: sqlite3.Connection) -> None:
    for source in ("ai_agent", "gemini", "langgraph", "rag"):
        with pytest.raises(sqlite3.IntegrityError, match="source_valid"):
            access_event(db, source=source)


def test_admin_review_with_and_without_hold_link(db: sqlite3.Connection) -> None:
    """A review that found no valid HOLD still has to be recordable."""
    access_event(db, n=1, decision="hold")
    access_event(
        db, n=2, source="admin_review", decision="allow", review_of_decision_id="d-1"
    )
    access_event(db, n=3, source="admin_review", decision="deny")
    assert db.execute("SELECT COUNT(*) FROM access_events").fetchone()[0] == 3


def test_decision_id_unique(db: sqlite3.Connection) -> None:
    access_event(db, n=1)
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        access_event(db, n=1)


def test_unknown_member_rejected_by_foreign_key(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        access_event(db, family_member_id=999)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE access_events SET decision = 'allow'",
        "UPDATE access_events SET reason_code = reason_code",  # even a no-op
        "DELETE FROM access_events",
    ],
)
def test_access_events_are_immutable(db: sqlite3.Connection, sql: str) -> None:
    access_event(db)
    message = rejected(db, sql)
    assert "access_events" in message and "not permitted" in message
    assert db.execute("SELECT decision FROM access_events").fetchone() == ("deny",)


def test_member_with_history_cannot_be_hard_deleted(db: sqlite3.Connection) -> None:
    access_event(db, family_member_id=1)
    assert "FOREIGN KEY" in rejected(db, "DELETE FROM family_members WHERE id = 1")


# --- security_events (P2 audit trail) ----------------------------------------


def test_every_failed_login_is_its_own_row(db: sqlite3.Connection) -> None:
    for i in range(5):
        security_event(db, event_uid=f"e-{i}", ip_address="203.0.113.7")
    count = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE event_type = 'auth.login_failed'"
    ).fetchone()[0]
    assert count == 5


def test_event_uid_unique_makes_persistence_idempotent(db: sqlite3.Connection) -> None:
    security_event(db)
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        security_event(db)


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"modality": "camera"}, "modality_valid"),
        ({"severity": "apocalyptic"}, "severity_valid"),
        ({"outcome": "maybe"}, "outcome_valid"),
        ({"suspicious": 2}, "suspicious_bool"),
        ({"confidence": 1.01}, "confidence_range"),
        ({"details": "not json"}, "details_json"),
        ({"contributing_event_ids": "{"}, "contributing_json"),
        ({"event_uid": ""}, "event_uid_length"),
    ],
)
def test_security_event_constraints(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match=constraint):
        security_event(db, **overrides)


def test_security_event_allows_only_incident_link_and_key_purge(
    db: sqlite3.Connection,
) -> None:
    inc = incident(db)
    other = incident(db, incident_uid="inc-2")
    row = security_event(db, visitor_key="v-4")
    db.execute("UPDATE security_events SET incident_id = ? WHERE id = ?", (inc, row))
    db.execute("UPDATE security_events SET visitor_key = NULL WHERE id = ?", (row,))
    db.commit()
    assert "not permitted" in rejected(
        db, "UPDATE security_events SET incident_id = ? WHERE id = ?", other, row
    )
    assert "not permitted" in rejected(
        db, "UPDATE security_events SET visitor_key = 'v-9' WHERE id = ?", row
    )
    for column, value in [
        ("severity", "info"),
        ("outcome", "succeeded"),
        ("details", '{"rewritten": true}'),
        ("ip_address", "10.0.0.1"),
        ("occurred_at", T1),
    ]:
        sql = f"UPDATE security_events SET {column} = ? WHERE id = ?"  # noqa: S608
        assert "not permitted" in rejected(db, sql, value, row)
    assert "not permitted" in rejected(db, "DELETE FROM security_events")


# --- evidence references (P1 mirrored in the database) ------------------------


@pytest.mark.parametrize("ref", VALID)
def test_every_valid_ref_is_accepted_by_the_database(
    db: sqlite3.Connection, ref: str
) -> None:
    security_event(db, evidence_ref=ref)


#: Refs the database CHECK must reject on its own. The CHECK is a coarser
#: backstop than validate_evidence_ref, so it cannot catch Windows device
#: names, leading dots or '.' components; those are rejected in Python first.
DB_REJECTS = [
    r
    for r in MALICIOUS
    if r
    and (
        not re.fullmatch(r"[A-Za-z0-9._/-]+", r)
        or r.startswith("/")
        or r.endswith("/")
        or "//" in r
        or ".." in r.split("/")
        or len(r) > 255
    )
]


def test_database_check_covers_traversal_and_absolute_paths() -> None:
    for probe in ("../../etc/passwd", "/etc/shadow", "snap/../../x.jpg"):
        assert probe in DB_REJECTS


@pytest.mark.parametrize("ref", DB_REJECTS)
@pytest.mark.parametrize(
    "table,column",
    [
        ("security_events", "evidence_ref"),
        ("visitor_events", "snapshot_ref"),
        ("incident_evidence", "evidence_ref"),
    ],
)
def test_database_rejects_unsafe_refs(
    db: sqlite3.Connection, ref: str, table: str, column: str
) -> None:
    inc = incident(db)
    if table == "security_events":
        sql = (
            "INSERT INTO security_events (event_uid, event_type, modality, severity,"
            " outcome, occurred_at, received_at, source_module, evidence_ref)"
            " VALUES ('x', 'face.unknown_visitor', 'biometric', 'low', 'observed',"
            " ?, ?, 'face', ?)"
        )
        params: tuple[Any, ...] = (T0, T0, ref)
    elif table == "visitor_events":
        sql = (
            "INSERT INTO visitor_events (occurred_at, snapshot_ref, snapshot_sha256,"
            " retention_expires_at) VALUES (?, ?, ?, ?)"
        )
        params = (T0, ref, SHA, LATER)
    else:
        sql = (
            "INSERT INTO incident_evidence (incident_id, evidence_type, evidence_ref,"
            " sha256, captured_at, source_module)"
            " VALUES (?, 'snapshot', ?, ?, ?, 'm14')"
        )
        params = (inc, ref, SHA, T0)
    assert f"{column}_safe" in rejected(db, sql, *params)


# --- visitor_events privacy ------------------------------------------------------


def test_visitor_purge_clears_identifying_data(db: sqlite3.Connection) -> None:
    row = visitor_event(db)
    db.execute(
        "UPDATE visitor_events SET visitor_cluster_key = NULL, snapshot_ref = NULL,"
        " snapshot_sha256 = NULL, purged_at = ? WHERE id = ?",
        (T1, row),
    )
    db.commit()
    assert db.execute(
        "SELECT visitor_cluster_key, snapshot_ref, purged_at FROM visitor_events"
    ).fetchone() == (None, None, T1)


def test_half_done_purge_rejected(db: sqlite3.Connection) -> None:
    row = visitor_event(db)
    message = rejected(
        db, "UPDATE visitor_events SET purged_at = ? WHERE id = ?", T1, row
    )
    assert "purge_complete" in message


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE visitor_events SET visitor_cluster_key = 'v-other'",
        "UPDATE visitor_events SET snapshot_ref = 'snap/2.jpg'",
        "UPDATE visitor_events SET occurred_at = '2020-01-01 00:00:00'",
        "UPDATE visitor_events SET retention_expires_at = '2099-01-01 00:00:00'",
        "DELETE FROM visitor_events",
    ],
)
def test_visitor_history_cannot_be_rewritten(db: sqlite3.Connection, sql: str) -> None:
    visitor_event(db)
    assert "not permitted" in rejected(db, sql)


def test_visitor_disposition_can_be_reviewed(db: sqlite3.Connection) -> None:
    row = visitor_event(db)
    db.execute("UPDATE visitor_events SET disposition = 'benign' WHERE id = ?", (row,))
    db.commit()


def test_purge_stamp_cannot_be_removed(db: sqlite3.Connection) -> None:
    row = visitor_event(
        db,
        visitor_cluster_key=None,
        snapshot_ref=None,
        snapshot_sha256=None,
        purged_at=T1,
    )
    assert "not permitted" in rejected(
        db, "UPDATE visitor_events SET purged_at = NULL WHERE id = ?", row
    )


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"snapshot_sha256": None}, "snapshot_hashed"),
        ({"snapshot_sha256": "A" * 64}, "snapshot_sha256_hex"),
        ({"snapshot_sha256": "a" * 63}, "snapshot_sha256_hex"),
        ({"retention_expires_at": T0}, "retention_after_occurrence"),
        ({"face_count": 0}, "face_count_positive"),
        ({"disposition": "enrolled"}, "disposition_valid"),
    ],
)
def test_visitor_event_constraints(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match=constraint):
        visitor_event(db, **overrides)


# --- incidents: AI content must be labelled ----------------------------------


def test_unlabelled_ai_summary_rejected(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="ai_content_labelled"):
        incident(db, ai_summary="Gemini says...")


def test_ai_summary_needs_model_version_and_time(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="ai_provenance"):
        incident(db, ai_summary="x", is_ai_enriched=1)
    incident(
        db,
        ai_summary="Advisory narrative",
        ai_recommendations=json.dumps(["consider lockdown"]),
        ai_model_version="gemini-x",
        ai_generated_at=T1,
        is_ai_enriched=1,
    )


def test_removing_ai_label_while_content_remains_rejected(
    db: sqlite3.Connection,
) -> None:
    row = incident(
        db, ai_summary="x", ai_model_version="m", ai_generated_at=T1, is_ai_enriched=1
    )
    assert "ai_content_labelled" in rejected(
        db, "UPDATE incidents SET is_ai_enriched = 0 WHERE id = ?", row
    )


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"status": "closed"}, "status_valid"),
        ({"status": "resolved"}, "closed_consistent"),
        ({"closed_at": T1}, "closed_consistent"),
        ({"first_event_at": T1, "last_event_at": T0}, "window_ordered"),
        ({"attack_chain": "{bad"}, "attack_chain_json"),
        ({"attack_chain": "{}"}, "attack_chain_dated"),
        ({"severity": "urgent"}, "severity_valid"),
    ],
)
def test_incident_constraints(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match=constraint):
        incident(db, **overrides)


def test_incident_lifecycle_and_no_delete(db: sqlite3.Connection) -> None:
    row = incident(db)
    db.execute(
        "UPDATE incidents SET status = 'resolved', closed_at = ?,"
        " resolved_by_user_id = 1 WHERE id = ?",
        (T1, row),
    )
    db.commit()
    assert "not permitted" in rejected(db, "DELETE FROM incidents")


# --- incident_evidence -----------------------------------------------------------


def test_file_evidence_needs_a_hash(db: sqlite3.Connection) -> None:
    inc = incident(db)
    with pytest.raises(sqlite3.IntegrityError, match="file_hashed"):
        insert(
            db,
            "incident_evidence",
            incident_id=inc,
            evidence_type="snapshot",
            evidence_ref="snap/1.jpg",
            captured_at=T0,
            source_module="m14",
        )


def test_evidence_integrity_columns_are_immutable(db: sqlite3.Connection) -> None:
    inc = incident(db)
    row = insert(
        db,
        "incident_evidence",
        incident_id=inc,
        evidence_type="snapshot",
        evidence_ref="snap/1.jpg",
        sha256=SHA,
        captured_at=T0,
        source_module="m14",
    )
    for column, value in [
        ("sha256", "b" * 64),
        ("evidence_ref", "snap/2.jpg"),
        ("captured_at", T1),
        ("incident_id", incident(db, incident_uid="inc-2")),
    ]:
        sql = f"UPDATE incident_evidence SET {column} = ? WHERE id = ?"  # noqa: S608
        assert "not permitted" in rejected(db, sql, value, row)
    db.execute(
        "UPDATE incident_evidence SET evidence_ref = NULL, purged_at = ? WHERE id = ?",
        (T1, row),
    )
    db.commit()
    assert db.execute("SELECT sha256 FROM incident_evidence").fetchone() == (SHA,)
    assert "not permitted" in rejected(db, "DELETE FROM incident_evidence")


def test_incident_with_evidence_cannot_lose_it(db: sqlite3.Connection) -> None:
    inc = incident(db)
    insert(
        db,
        "incident_evidence",
        incident_id=inc,
        evidence_type="note",
        content="operator note",
        captured_at=T0,
        source_module="api",
    )
    assert "not permitted" in rejected(db, "DELETE FROM incidents")
    assert db.execute("SELECT COUNT(*) FROM incident_evidence").fetchone()[0] == 1


# --- workflow_executions ----------------------------------------------------------


def test_workflow_progresses_then_freezes(db: sqlite3.Connection) -> None:
    row = workflow(db)
    db.execute(
        "UPDATE workflow_executions SET current_node = 'retrieve', steps = ?"
        " WHERE id = ?",
        (json.dumps(["supervisor", "retrieve"]), row),
    )
    db.execute(
        "UPDATE workflow_executions SET status = 'succeeded', finished_at = ?,"
        " duration_ms = 1200 WHERE id = ?",
        (T1, row),
    )
    db.commit()
    assert "not permitted" in rejected(
        db, "UPDATE workflow_executions SET result_summary = 'edited' WHERE id = ?", row
    )
    assert "not permitted" in rejected(db, "DELETE FROM workflow_executions")


def test_workflow_requester_cannot_be_changed(db: sqlite3.Connection) -> None:
    row = workflow(db)
    assert "not permitted" in rejected(
        db,
        "UPDATE workflow_executions SET requested_by_user_id = NULL WHERE id = ?",
        row,
    )


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"execution_kind": "agent"}, "execution_kind_valid"),
        ({"workflow_name": None}, "name_matches_kind"),
        ({"automation_task_id": 7}, "task_only_for_jobs"),
        ({"status": "succeeded"}, "finished_consistent"),
        ({"finished_at": T1}, "finished_consistent"),
        ({"steps": "["}, "steps_json"),
        ({"tokens_used": -5}, "tokens_nonnegative"),
        ({"trigger_source": "gemini"}, "trigger_source_valid"),
    ],
)
def test_workflow_constraints(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError, match=constraint):
        workflow(db, **overrides)


def test_scheduled_job_row(db: sqlite3.Connection) -> None:
    workflow(
        db,
        run_uid="run-2",
        execution_kind="scheduled_job",
        workflow_name=None,
        automation_task_id=3,
        trigger_source="schedule",
        requested_by_user_id=None,
    )


# --- read-only boundary covers the new tables ---------------------------------


def test_readonly_connection_cannot_write_new_tables(
    tmp_path: Path, schema_sql: str
) -> None:
    path = tmp_path / "ro.db"
    conn = sqlite3.connect(path)
    conn.executescript(schema_sql)
    conn.close()
    ro = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        now = datetime.now(UTC).isoformat()
        statements: list[tuple[str, tuple[Any, ...]]] = [
            (
                "INSERT INTO incidents (incident_uid, opened_at, title, category,"
                " severity) VALUES ('i', ?, 't', 'c', 'low')",
                (now,),
            ),
            (
                "INSERT INTO workflow_executions (run_uid, execution_kind,"
                " workflow_name, trigger_source, started_at)"
                " VALUES ('r', 'langgraph_workflow', 'w', 'manual', ?)",
                (now,),
            ),
            ("UPDATE incidents SET ai_summary = 'x'", ()),
            ("DROP TRIGGER trg_access_events_guard_update", ()),
        ]
        for sql, params in statements:
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                ro.execute(sql, params)
    finally:
        ro.close()
