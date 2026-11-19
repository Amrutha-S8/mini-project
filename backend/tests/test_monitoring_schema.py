"""Database rules for migration 0005 (stdlib sqlite3 on the reference DDL).

* a detection finding can never be edited or deleted;
* a notification can never be deleted, never claim delivery without a
  provider message id and a delivery time, and never rewrite who it was for
  or a provider fact once recorded;
* incidents can be acknowledged.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

T0 = "2026-11-19 14:00:00.000000"
T1 = "2026-11-19 14:05:00.000000"


@pytest.fixture
def db(sqlite_db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    sqlite_db.execute(
        "INSERT INTO incidents (id, incident_uid, opened_at, title, category, "
        "severity) VALUES (1, 'inc-1', ?, 'Repeated denied access', "
        "'repeated_denied_access', 'medium')",
        (T0,),
    )
    sqlite_db.execute(
        "INSERT INTO security_events (id, event_uid, event_type, modality, severity, "
        "outcome, occurred_at, received_at, source_module) VALUES "
        "(1, 'e-1', 'access.denied', 'access', 'low', 'blocked', ?, ?, 'camera')",
        (T0, T0),
    )
    sqlite_db.commit()
    yield sqlite_db


def _detection(db: sqlite3.Connection, **overrides: object) -> None:
    values: dict[str, object] = {
        "incident_id": 1,
        "security_event_id": 1,
        "detector_rule": "repeated_denied_access",
        "dedupe_key": "repeated_denied_access:front",
        "severity": "medium",
        "reason": "3 denied access decisions at front within 10 minutes.",
        "event_uids": '["e-1"]',
        "detected_at": T0,
    }
    values.update(overrides)
    cols = ", ".join(values)
    db.execute(
        f"INSERT INTO incident_detections ({cols}) "  # noqa: S608
        f"VALUES ({', '.join('?' * len(values))})",
        tuple(values.values()),
    )
    db.commit()


def _notification(db: sqlite3.Connection, **overrides: object) -> int:
    values: dict[str, object] = {
        "incident_id": 1,
        "channel": "whatsapp",
        "provider": "meta_whatsapp_cloud",
        "recipient_masked": "+91******3210",
        "trigger_reason": "created",
    }
    values.update(overrides)
    cols = ", ".join(values)
    cur = db.execute(
        f"INSERT INTO notifications ({cols}) "  # noqa: S608
        f"VALUES ({', '.join('?' * len(values))})",
        tuple(values.values()),
    )
    db.commit()
    return int(cur.lastrowid or 0)


def _fails(db: sqlite3.Connection, sql: str, *params: object) -> str:
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as info:
        db.execute(sql, params)
        db.commit()
    db.rollback()
    return str(info.value)


def test_detection_is_stored_with_reason_and_event(db: sqlite3.Connection) -> None:
    _detection(db)
    row = db.execute(
        "SELECT detector_rule, reason, security_event_id FROM incident_detections"
    ).fetchone()
    assert row == (
        "repeated_denied_access",
        "3 denied access decisions at front within 10 minutes.",
        1,
    )


def test_detection_cannot_be_edited_or_deleted(db: sqlite3.Connection) -> None:
    _detection(db)
    assert "update not permitted" in _fails(
        db, "UPDATE incident_detections SET reason = 'nothing happened'"
    )
    assert "delete not permitted" in _fails(db, "DELETE FROM incident_detections")


@pytest.mark.parametrize(
    "overrides",
    [
        {"severity": "urgent"},
        {"reason": ""},
        {"event_uids": "not json"},
        {"security_event_id": 999},
        {"incident_id": 999},
    ],
)
def test_detection_constraints(
    db: sqlite3.Connection, overrides: dict[str, object]
) -> None:
    db.execute("PRAGMA foreign_keys=ON")
    with pytest.raises(sqlite3.IntegrityError):
        _detection(db, **overrides)
    db.rollback()


def test_notification_defaults_to_pending(db: sqlite3.Connection) -> None:
    nid = _notification(db)
    assert db.execute(
        "SELECT status FROM notifications WHERE id = ?", (nid,)
    ).fetchone() == ("pending",)


def test_delivered_requires_provider_id_and_time(db: sqlite3.Connection) -> None:
    nid = _notification(db)
    assert "delivery_confirmed_by_provider" in _fails(
        db, "UPDATE notifications SET status = 'delivered' WHERE id = ?", nid
    )
    assert "accepted_has_provider_id" in _fails(
        db, "UPDATE notifications SET status = 'accepted' WHERE id = ?", nid
    )
    db.execute(
        "UPDATE notifications SET status = 'accepted', "
        "provider_message_id = 'wamid.1', sent_at = ? WHERE id = ?",
        (T0, nid),
    )
    db.commit()
    assert "delivery_confirmed_by_provider" in _fails(
        db, "UPDATE notifications SET status = 'read' WHERE id = ?", nid
    )
    db.execute(
        "UPDATE notifications SET status = 'delivered', delivered_at = ? WHERE id = ?",
        (T1, nid),
    )
    db.commit()


def test_provider_facts_are_set_once(db: sqlite3.Connection) -> None:
    nid = _notification(
        db, status="accepted", provider_message_id="wamid.1", sent_at=T0
    )
    assert "update not permitted" in _fails(
        db, "UPDATE notifications SET provider_message_id = 'wamid.2' WHERE id = ?", nid
    )
    assert "update not permitted" in _fails(
        db, "UPDATE notifications SET sent_at = ? WHERE id = ?", T1, nid
    )
    assert "update not permitted" in _fails(
        db, "UPDATE notifications SET recipient_masked = '+1***' WHERE id = ?", nid
    )
    assert "update not permitted" in _fails(
        db, "UPDATE notifications SET channel = 'sms' WHERE id = ?", nid
    )


def test_notification_cannot_be_deleted(db: sqlite3.Connection) -> None:
    _notification(db)
    assert "delete not permitted" in _fails(db, "DELETE FROM notifications")


@pytest.mark.parametrize(
    "overrides",
    [
        {"channel": "email"},
        {"provider": "someone_else"},
        {"status": "probably_delivered"},
        {"trigger_reason": "ai_decided"},
    ],
)
def test_notification_constraints(
    db: sqlite3.Connection, overrides: dict[str, object]
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _notification(db, **overrides)
    db.rollback()


def test_incident_can_be_acknowledged_and_still_not_deleted(
    db: sqlite3.Connection,
) -> None:
    db.execute(
        "UPDATE incidents SET acknowledged_at = ?, acknowledged_by_user_id = 1 "
        "WHERE id = 1",
        (T1,),
    )
    db.commit()
    assert db.execute("SELECT acknowledged_at FROM incidents").fetchone() == (T1,)
    assert "delete not permitted" in _fails(db, "DELETE FROM incidents")


def test_notifications_hold_no_full_phone_number_column(db: sqlite3.Connection) -> None:
    columns = {r[1] for r in db.execute("PRAGMA table_info(notifications)")}
    assert "recipient_masked" in columns
    assert not columns & {"recipient", "phone", "phone_number", "to_number"}
