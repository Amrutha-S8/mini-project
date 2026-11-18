"""Retention extensions: Python policy and database enforcement (DD-11). Stdlib.

Original deadlines are never modified. Extensions are separate append-only
records that need an authorised approval. Covers unauthorised, expired and
invalid extensions at both layers.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.domain.retention import (
    MAX_EXTENSION,
    REQUEST_TTL,
    Approver,
    EvidenceRetention,
    ExtensionRequest,
    RetentionExtension,
    RetentionExtensionError,
    approve_extension,
    effective_deadline,
)

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
ORIGINAL = NOW + timedelta(days=30)
ADMIN = Approver(user_id=1, role="admin", is_active=True)
EVIDENCE = EvidenceRetention(
    evidence_id=7,
    incident_id=3,
    incident_status="investigating",
    original_deadline=ORIGINAL,
    purged=False,
)


def request(**overrides: Any) -> ExtensionRequest:
    values: dict[str, Any] = {
        "evidence_id": 7,
        "incident_id": 3,
        "requested_by_user_id": 2,
        "requested_at": NOW - timedelta(hours=1),
        "reason": "Police asked us to keep the footage for the case.",
        "extended_deadline": ORIGINAL + timedelta(days=90),
    }
    values.update(overrides)
    return ExtensionRequest(**values)


def approve(**kw: Any) -> RetentionExtension:
    args: dict[str, Any] = {
        "request": request(),
        "evidence": EVIDENCE,
        "approver": ADMIN,
        "existing": (),
        "now": NOW,
    }
    args.update(kw)
    return approve_extension(**args)


def error_code(**kw: Any) -> str:
    with pytest.raises(RetentionExtensionError) as info:
        approve(**kw)
    return info.value.code


# --- policy: valid ---------------------------------------------------------------


def test_valid_extension_records_everything() -> None:
    ext = approve()
    assert ext.original_deadline == ORIGINAL
    assert ext.previous_deadline == ORIGINAL
    assert ext.extended_deadline == ORIGINAL + timedelta(days=90)
    assert (ext.requested_by_user_id, ext.approved_by_user_id) == (2, 1)
    assert ext.approved_at == NOW and ext.requested_at < NOW
    assert ext.reason.startswith("Police")


def test_chained_extension_builds_on_the_effective_deadline() -> None:
    first = approve()
    second = approve(
        request=request(extended_deadline=first.extended_deadline + timedelta(days=30)),
        existing=(first,),
    )
    assert second.original_deadline == ORIGINAL
    assert second.previous_deadline == first.extended_deadline
    assert effective_deadline(ORIGINAL, [first, second]) == second.extended_deadline


def test_effective_deadline_without_extensions_is_original() -> None:
    assert effective_deadline(ORIGINAL, []) == ORIGINAL
    assert effective_deadline(None, []) is None


def test_policy_never_mutates_the_original() -> None:
    before = replace(EVIDENCE)
    approve()
    assert before == EVIDENCE and EVIDENCE.original_deadline == ORIGINAL


# --- policy: unauthorised ----------------------------------------------------


@pytest.mark.parametrize(
    "approver",
    [
        Approver(1, "viewer", True),
        Approver(1, "member", True),
        Approver(1, "admin", False),
        Approver(1, "ADMIN", True),
        Approver(1, "", True),
    ],
)
def test_only_active_admins_may_approve(approver: Approver) -> None:
    assert error_code(approver=approver) == "approver_not_authorised"


def test_self_approval_rejected_by_default() -> None:
    assert (
        error_code(approver=Approver(2, "admin", True)) == "self_approval_not_allowed"
    )


def test_self_approval_only_when_explicitly_allowed() -> None:
    ext = approve(approver=Approver(2, "admin", True), allow_self_approval=True)
    assert ext.approved_by_user_id == ext.requested_by_user_id == 2


# --- policy: expired ---------------------------------------------------------


def test_expired_retention_cannot_be_revived() -> None:
    fresh = request(requested_at=ORIGINAL - timedelta(hours=1))
    assert error_code(request=fresh, now=ORIGINAL) == "retention_already_expired"
    late = request(requested_at=ORIGINAL + timedelta(hours=1))
    assert (
        error_code(request=late, now=ORIGINAL + timedelta(hours=2))
        == "retention_already_expired"
    )


def test_expired_after_an_earlier_extension() -> None:
    first = approve()
    later = first.extended_deadline + timedelta(seconds=1)
    code = error_code(
        request=request(
            requested_at=later - timedelta(hours=1),
            extended_deadline=later + timedelta(days=1),
        ),
        existing=(first,),
        now=later,
    )
    assert code == "retention_already_expired"


def test_stale_request_rejected() -> None:
    old = NOW - REQUEST_TTL - timedelta(seconds=1)
    assert error_code(request=request(requested_at=old)) == "request_expired"


def test_request_from_the_future_rejected() -> None:
    future = NOW + timedelta(minutes=1)
    assert error_code(request=request(requested_at=future)) == "request_from_the_future"


# --- policy: invalid ---------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,code",
    [
        ({"extended_deadline": ORIGINAL}, "not_an_extension"),
        ({"extended_deadline": ORIGINAL - timedelta(days=1)}, "not_an_extension"),
        (
            {"extended_deadline": ORIGINAL + MAX_EXTENSION + timedelta(seconds=1)},
            "extension_too_long",
        ),
        ({"reason": "because"}, "reason_invalid"),
        ({"reason": "   "}, "reason_invalid"),
        ({"reason": "x" * 1001}, "reason_invalid"),
        ({"reason": "keep this\x00 for court"}, "reason_invalid"),
        ({"evidence_id": 8}, "evidence_mismatch"),
        ({"incident_id": 4}, "incident_mismatch"),
        (
            {"extended_deadline": (ORIGINAL + timedelta(days=1)).replace(tzinfo=None)},
            "naive_datetime",
        ),
    ],
)
def test_invalid_requests(overrides: dict[str, Any], code: str) -> None:
    assert error_code(request=request(**overrides)) == code


@pytest.mark.parametrize(
    "evidence,code",
    [
        (replace(EVIDENCE, purged=True), "evidence_purged"),
        (replace(EVIDENCE, original_deadline=None), "no_retention_deadline"),
        (replace(EVIDENCE, incident_status="resolved"), "incident_not_open"),
        (replace(EVIDENCE, incident_status="false_positive"), "incident_not_open"),
    ],
)
def test_invalid_evidence_state(evidence: EvidenceRetention, code: str) -> None:
    assert error_code(evidence=evidence) == code


def test_extension_for_other_evidence_cannot_be_mixed_in() -> None:
    foreign = replace(approve(), evidence_id=99)
    assert error_code(existing=(foreign,)) == "foreign_extension_supplied"


def test_there_is_no_automatic_extension() -> None:
    """approve_extension has no default approver and nothing schedules it."""
    import inspect

    import app.domain.retention as module

    sig = inspect.signature(approve_extension)
    assert sig.parameters["approver"].default is inspect.Parameter.empty
    names = {n for n in dir(module) if not n.startswith("_")}
    assert not {n for n in names if "auto" in n.lower() or "schedule" in n.lower()}


# --- database enforcement ------------------------------------------------------

T = "%Y-%m-%d %H:%M:%S.%f"


def ts(dt: datetime) -> str:
    """The format SQLAlchemy's UtcDateTime writes to SQLite."""
    return dt.astimezone(UTC).strftime(T)


@pytest.fixture
def db(sqlite_db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    c = sqlite_db
    c.execute(
        "INSERT INTO users (id, email, password_hash, full_name, role) VALUES "
        "(1, 'a@example.com', 'h', 'Admin', 'admin'),"
        "(2, 'b@example.com', 'h', 'Viewer', 'viewer'),"
        "(3, 'c@example.com', 'h', 'Old admin', 'admin')"
    )
    c.execute("UPDATE users SET is_active = 0 WHERE id = 3")
    c.execute(
        "INSERT INTO incidents (id, incident_uid, opened_at, title, category,"
        " severity, status) VALUES (3, 'inc-1', ?, 't', 'intrusion_attempt',"
        " 'high', 'investigating')",
        (ts(NOW),),
    )
    c.execute(
        "INSERT INTO incident_evidence (id, incident_id, evidence_type, evidence_ref,"
        " sha256, captured_at, source_module, retention_expires_at)"
        " VALUES (7, 3, 'snapshot', 'snap/1.jpg', ?, ?, 'm14', ?)",
        ("a" * 64, ts(NOW), ts(ORIGINAL)),
    )
    c.commit()
    yield c


def insert_ext(conn: sqlite3.Connection, **overrides: Any) -> None:
    values: dict[str, Any] = {
        "evidence_id": 7,
        "incident_id": 3,
        "requested_by_user_id": 2,
        "approved_by_user_id": 1,
        "reason": "Police asked us to keep the footage.",
        "original_deadline": ts(ORIGINAL),
        "previous_deadline": ts(ORIGINAL),
        "extended_deadline": ts(ORIGINAL + timedelta(days=90)),
        "requested_at": ts(NOW - timedelta(hours=1)),
        "approved_at": ts(NOW),
    }
    values.update(overrides)
    cols = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    sql = f"INSERT INTO retention_extensions ({cols}) VALUES ({marks})"  # noqa: S608
    conn.execute(sql, tuple(values.values()))
    conn.commit()


def db_rejects(conn: sqlite3.Connection, **overrides: Any) -> str:
    with pytest.raises(sqlite3.IntegrityError) as info:
        insert_ext(conn, **overrides)
    conn.rollback()
    return str(info.value)


def test_db_accepts_a_valid_extension_and_keeps_the_original(
    db: sqlite3.Connection,
) -> None:
    insert_ext(db)
    original = db.execute(
        "SELECT retention_expires_at FROM incident_evidence WHERE id = 7"
    ).fetchone()
    assert original == (ts(ORIGINAL),)


def test_db_record_from_policy_output_is_accepted(db: sqlite3.Connection) -> None:
    ext = approve()
    insert_ext(
        db,
        original_deadline=ts(ext.original_deadline),
        previous_deadline=ts(ext.previous_deadline),
        extended_deadline=ts(ext.extended_deadline),
        requested_at=ts(ext.requested_at),
        approved_at=ts(ext.approved_at),
        requested_by_user_id=ext.requested_by_user_id,
        approved_by_user_id=ext.approved_by_user_id,
        reason=ext.reason,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"approved_by_user_id": 2},  # viewer
        {"approved_by_user_id": 3},  # inactive admin
        {"original_deadline": ts(ORIGINAL + timedelta(days=1))},  # falsified
        {"evidence_id": 7, "incident_id": 3, "previous_deadline": ts(NOW)},
    ],
    ids=["viewer_approver", "inactive_admin", "falsified_original", "wrong_previous"],
)
def test_db_trigger_rejects_unauthorised_or_inconsistent(
    db: sqlite3.Connection, overrides: dict[str, Any]
) -> None:
    message = db_rejects(db, **overrides)
    assert "not valid" in message or "previous_not_before_original" in message


@pytest.mark.parametrize(
    "overrides,constraint",
    [
        ({"extended_deadline": ts(ORIGINAL)}, "extends_deadline"),
        ({"reason": "short"}, "reason_length"),
        ({"approved_at": ts(ORIGINAL)}, "approved_before_expiry"),
        ({"approved_at": ts(NOW - timedelta(days=1))}, "approved_after_request"),
        (
            {"extended_deadline": ts(ORIGINAL + timedelta(days=366))},
            "max_extension",
        ),
    ],
)
def test_db_checks(
    db: sqlite3.Connection, overrides: dict[str, Any], constraint: str
) -> None:
    assert constraint in db_rejects(db, **overrides)


def test_db_rejects_extension_for_closed_incident(db: sqlite3.Connection) -> None:
    db.execute(
        "UPDATE incidents SET status = 'resolved', closed_at = ? WHERE id = 3",
        (ts(NOW),),
    )
    db.commit()
    assert "not valid" in db_rejects(db)


def test_db_rejects_extension_for_purged_evidence(db: sqlite3.Connection) -> None:
    db.execute(
        "UPDATE incident_evidence SET evidence_ref = NULL, purged_at = ? WHERE id = 7",
        (ts(NOW),),
    )
    db.commit()
    assert "not valid" in db_rejects(db)


def test_db_chain_must_start_from_the_latest_extension(db: sqlite3.Connection) -> None:
    first_end = ORIGINAL + timedelta(days=90)
    insert_ext(db)
    # A second extension that ignores the first one is rejected.
    assert "not valid" in db_rejects(
        db, extended_deadline=ts(first_end + timedelta(days=10))
    )
    insert_ext(
        db,
        previous_deadline=ts(first_end),
        extended_deadline=ts(first_end + timedelta(days=10)),
    )
    assert db.execute("SELECT COUNT(*) FROM retention_extensions").fetchone() == (2,)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE retention_extensions SET extended_deadline = '2099-01-01 00:00:00'",
        "UPDATE retention_extensions SET reason = reason",
        "DELETE FROM retention_extensions",
    ],
)
def test_db_extensions_are_append_only(db: sqlite3.Connection, sql: str) -> None:
    insert_ext(db)
    with pytest.raises(sqlite3.IntegrityError, match="not permitted"):
        db.execute(sql)
    db.rollback()


def test_original_deadline_still_immutable(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError, match="not permitted"):
        db.execute(
            "UPDATE incident_evidence SET retention_expires_at = ? WHERE id = 7",
            (ts(ORIGINAL + timedelta(days=90)),),
        )
    db.rollback()


def test_evidence_cannot_be_purged_during_an_extension(db: sqlite3.Connection) -> None:
    insert_ext(db)
    during = ORIGINAL + timedelta(days=10)  # past the original, inside the extension
    with pytest.raises(sqlite3.IntegrityError, match="retention extended"):
        db.execute(
            "UPDATE incident_evidence SET evidence_ref = NULL, purged_at = ?"
            " WHERE id = 7",
            (ts(during),),
        )
    db.rollback()
    after = ORIGINAL + timedelta(days=91)
    db.execute(
        "UPDATE incident_evidence SET evidence_ref = NULL, purged_at = ? WHERE id = 7",
        (ts(after),),
    )
    db.commit()
