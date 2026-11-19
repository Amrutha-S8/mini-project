"""API tests for Phase 2: session-bound access tokens (finding S2), role
visibility (finding S5, owner decisions R-1 and D-3), event history,
incident management and the dashboard summary.

These need the approved stack and SKIP without it. Event, incident and
security-event rows are inserted directly with the ORM because the pipeline
that writes them is wired in a later phase; the tests check what each role
can read back, not how the rows were produced.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.conftest import ADMIN_PAYLOAD, requires_stack

pytestmark = requires_stack

V1 = "/api/v1"
PASSWORD = "Str0ng-Household-Pass"
_seq = itertools.count(1)


# --- helpers -------------------------------------------------------------------


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login(client: Any, email: str, password: str = PASSWORD) -> dict[str, Any]:
    response = client.post(
        f"{V1}/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def _admin(client: Any) -> dict[str, Any]:
    return _login(client, ADMIN_PAYLOAD["email"], ADMIN_PAYLOAD["password"])


def _create_user(client: Any, admin_token: str, email: str, role: str) -> int:
    response = client.post(
        f"{V1}/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": email, "role": role},
        headers=_auth(admin_token),
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _create_member(
    client: Any, admin_token: str, name: str, *, user_id: int | None = None
) -> int:
    response = client.post(
        f"{V1}/members",
        json={
            "full_name": name,
            "notes": f"admin note about {name}",
            "user_id": user_id,
        },
        headers=_auth(admin_token),
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _db() -> Any:
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine

    return Session(get_writer_engine())


def _insert_access_event(
    *, decision: str, member_id: int | None = None, occurred_at: datetime | None = None
) -> int:
    from app.models.access_event import AccessEvent

    n = next(_seq)
    with _db() as db:
        row = AccessEvent(
            decision_id=f"dec-{n}",
            request_id=f"req-{n}",
            occurred_at=occurred_at or datetime.now(UTC),
            door_id="front-door",
            source="camera",
            decision=decision,
            rule_number=1,
            rule_name="rule_under_test",
            reason_code="reason_under_test",
            engine_version="test",
            family_member_id=member_id,
            correlation_id=f"corr-{n}",
        )
        db.add(row)
        db.commit()
        return int(row.id)


def _insert_security_event(
    *,
    member_id: int | None = None,
    user_id: int | None = None,
    suspicious: bool = False,
    severity: str = "medium",
    occurred_at: datetime | None = None,
) -> int:
    from app.models.security_event import SecurityEventRecord

    n = next(_seq)
    when = occurred_at or datetime.now(UTC)
    with _db() as db:
        row = SecurityEventRecord(
            event_uid=f"evt-{n}",
            event_type="access.denied",
            modality="access",
            severity=severity,
            outcome="blocked",
            suspicious=int(suspicious),
            occurred_at=when,
            received_at=when,
            source_module="test",
            family_member_id=member_id,
            user_id=user_id,
            ip_address="10.0.0.5",
            details=json.dumps({"attempts": 3}),
        )
        db.add(row)
        db.commit()
        return int(row.id)


def _insert_incident(*, severity: str = "high", status: str = "open") -> int:
    from app.models.incident import IncidentRecord

    n = next(_seq)
    now = datetime.now(UTC)
    with _db() as db:
        row = IncidentRecord(
            incident_uid=f"inc-{n}",
            opened_at=now,
            title="Repeated denied attempts",
            category="access",
            severity=severity,
            status=status,
            # CHECK closed_consistent: closed cases carry closed_at.
            closed_at=now if status in ("resolved", "false_positive") else None,
            attack_chain=json.dumps({"steps": ["deny", "deny", "deny"]}),
            attack_chain_generated_at=now,
        )
        db.add(row)
        db.commit()
        return int(row.id)


def _audit_count(action: str) -> int:
    from sqlalchemy import func, select

    from app.models.audit_log import AuditLog

    with _db() as db:
        return int(
            db.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == action)
            ).scalar_one()
        )


@pytest.fixture
def household(app_client: Any) -> dict[str, Any]:
    """Admin, a viewer, a member user linked to "Asha", and an unlinked "Ravi"."""
    admin = _admin(app_client)["tokens"]
    admin_token = admin["access_token"]
    viewer_id = _create_user(app_client, admin_token, "viewer@example.com", "viewer")
    member_user_id = _create_user(
        app_client, admin_token, "member@example.com", "member"
    )
    asha = _create_member(app_client, admin_token, "Asha", user_id=member_user_id)
    ravi = _create_member(app_client, admin_token, "Ravi")
    return {
        "admin": admin_token,
        "admin_refresh": admin["refresh_token"],
        "viewer": _login(app_client, "viewer@example.com")["tokens"]["access_token"],
        "member": _login(app_client, "member@example.com")["tokens"]["access_token"],
        "viewer_id": viewer_id,
        "member_user_id": member_user_id,
        "asha": asha,
        "ravi": ravi,
    }


# --- S2: access tokens are bound to server-side sessions -----------------------


def _me(client: Any, token: str) -> Any:
    return client.get(f"{V1}/auth/me", headers=_auth(token))


def _refresh(client: Any, refresh_token: str) -> Any:
    return client.post(f"{V1}/auth/refresh", json={"refresh_token": refresh_token})


def _logout(client: Any, access: str, refresh_token: str) -> Any:
    return client.post(
        f"{V1}/auth/logout",
        json={"refresh_token": refresh_token},
        headers=_auth(access),
    )


def test_access_token_rejected_after_logout(app_client: Any) -> None:
    tokens = _admin(app_client)["tokens"]
    assert _me(app_client, tokens["access_token"]).status_code == 200
    assert (
        _logout(app_client, tokens["access_token"], tokens["refresh_token"]).status_code
        == 204
    )

    after = _me(app_client, tokens["access_token"])
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "session_revoked"


def test_access_token_survives_refresh_rotation(app_client: Any) -> None:
    tokens = _admin(app_client)["tokens"]
    rotated = _refresh(app_client, tokens["refresh_token"])
    assert rotated.status_code == 200
    assert _me(app_client, tokens["access_token"]).status_code == 200
    assert _me(app_client, rotated.json()["access_token"]).status_code == 200


def test_logout_after_rotation_ends_every_access_token_of_the_lineage(
    app_client: Any,
) -> None:
    first = _admin(app_client)["tokens"]
    second = _refresh(app_client, first["refresh_token"]).json()
    assert (
        _logout(app_client, second["access_token"], second["refresh_token"]).status_code
        == 204
    )
    assert _me(app_client, first["access_token"]).status_code == 401
    assert _me(app_client, second["access_token"]).status_code == 401


def test_logout_with_stale_refresh_token_still_ends_current_access_token(
    app_client: Any,
) -> None:
    first = _admin(app_client)["tokens"]
    second = _refresh(app_client, first["refresh_token"]).json()
    # The client sends the already-rotated refresh token by mistake.
    assert (
        _logout(app_client, second["access_token"], first["refresh_token"]).status_code
        == 204
    )
    assert _me(app_client, second["access_token"]).status_code == 401
    assert _refresh(app_client, second["refresh_token"]).status_code == 401


def test_reuse_detection_ends_access_tokens(app_client: Any) -> None:
    first = _admin(app_client)["tokens"]
    second = _refresh(app_client, first["refresh_token"]).json()
    replay = _refresh(app_client, first["refresh_token"])
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "token_reuse_detected"
    assert _me(app_client, second["access_token"]).status_code == 401


def test_token_without_session_claim_rejected(app_client: Any) -> None:
    import jwt

    settings = app_client.app.state.settings
    user_id = _admin(app_client)["user"]["id"]
    now = int(datetime.now(UTC).timestamp())
    token = jwt.encode(
        {
            "sub": str(user_id),
            "role": "admin",
            "typ": "access",
            "iat": now,
            "exp": now + 600,
        },
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    assert _me(app_client, token).status_code == 401


def test_token_cannot_borrow_another_users_session(
    app_client: Any, household: dict[str, Any]
) -> None:
    """A correctly signed token whose ``sid`` belongs to someone else fails."""
    from sqlalchemy import select

    from app.core.security import create_access_token
    from app.models.session import SessionRecord

    with _db() as db:
        viewer_session = db.execute(
            select(SessionRecord.id).where(
                SessionRecord.user_id == household["viewer_id"]
            )
        ).scalar_one()
    admin_id = _me(app_client, household["admin"]).json()["id"]
    forged = create_access_token(
        subject=str(admin_id),
        role="admin",
        session_id=viewer_session,
        settings=app_client.app.state.settings,
    )
    assert _me(app_client, forged).status_code == 401


def test_logout_cannot_revoke_another_users_session(
    app_client: Any, household: dict[str, Any]
) -> None:
    viewer_refresh = _login(app_client, "viewer@example.com")["tokens"]
    response = _logout(app_client, household["member"], viewer_refresh["refresh_token"])
    assert response.status_code == 204
    assert _refresh(app_client, viewer_refresh["refresh_token"]).status_code == 200


def test_logout_is_audited_once(app_client: Any) -> None:
    tokens = _admin(app_client)["tokens"]
    _logout(app_client, tokens["access_token"], tokens["refresh_token"])
    assert _audit_count("logout") == 1


# --- S5: member records by role ------------------------------------------------


def test_viewer_cannot_read_member_records(
    app_client: Any, household: dict[str, Any]
) -> None:
    viewer = _auth(household["viewer"])
    assert app_client.get(f"{V1}/members", headers=viewer).status_code == 403
    one = app_client.get(f"{V1}/members/{household['asha']}", headers=viewer)
    assert one.status_code == 403


def test_member_sees_only_own_record_without_admin_notes(
    app_client: Any, household: dict[str, Any]
) -> None:
    member = _auth(household["member"])
    listed = app_client.get(f"{V1}/members", headers=member)
    assert listed.status_code == 200
    assert [m["id"] for m in listed.json()] == [household["asha"]]
    assert listed.json()[0]["notes"] is None

    own = app_client.get(f"{V1}/members/{household['asha']}", headers=member)
    assert own.status_code == 200
    other = app_client.get(f"{V1}/members/{household['ravi']}", headers=member)
    assert other.status_code == 404


def test_admin_sees_every_member_with_notes(
    app_client: Any, household: dict[str, Any]
) -> None:
    listed = app_client.get(f"{V1}/members", headers=_auth(household["admin"])).json()
    assert {m["id"] for m in listed} == {household["asha"], household["ravi"]}
    assert all(m["notes"] for m in listed)


# --- access-event history ------------------------------------------------------


def test_access_events_visibility_per_role(
    app_client: Any, household: dict[str, Any]
) -> None:
    asha_event = _insert_access_event(decision="allow", member_id=household["asha"])
    _insert_access_event(decision="allow", member_id=household["ravi"])
    _insert_access_event(decision="deny", member_id=None)

    admin = app_client.get(f"{V1}/events/access", headers=_auth(household["admin"]))
    assert admin.status_code == 200
    assert {e["member_name"] for e in admin.json()} == {"Asha", "Ravi", None}

    viewer = app_client.get(f"{V1}/events/access", headers=_auth(household["viewer"]))
    assert viewer.status_code == 200
    assert len(viewer.json()) == 3
    for event in viewer.json():
        assert event["member_name"] is None
        assert event["family_member_id"] is None
    assert sorted(e["identity"] for e in viewer.json()) == [
        "registered",
        "registered",
        "unknown",
    ]
    assert "Asha" not in viewer.text and "Ravi" not in viewer.text

    member = app_client.get(f"{V1}/events/access", headers=_auth(household["member"]))
    assert [e["id"] for e in member.json()] == [asha_event]
    assert member.json()[0]["member_name"] == "Asha"


def test_access_events_paging_and_filter(
    app_client: Any, household: dict[str, Any]
) -> None:
    ids = [_insert_access_event(decision=d) for d in ("deny", "hold", "deny", "allow")]
    headers = _auth(household["admin"])

    page = app_client.get(f"{V1}/events/access", params={"limit": 2}, headers=headers)
    assert [e["id"] for e in page.json()] == [ids[3], ids[2]]
    nxt = app_client.get(
        f"{V1}/events/access",
        params={"limit": 2, "before_id": ids[2]},
        headers=headers,
    )
    assert [e["id"] for e in nxt.json()] == [ids[1], ids[0]]

    denies = app_client.get(
        f"{V1}/events/access", params={"decision": "deny"}, headers=headers
    )
    assert [e["id"] for e in denies.json()] == [ids[2], ids[0]]


@pytest.mark.parametrize("limit", [0, 201])
def test_access_events_reject_out_of_range_limit(
    app_client: Any, household: dict[str, Any], limit: int
) -> None:
    response = app_client.get(
        f"{V1}/events/access",
        params={"limit": limit},
        headers=_auth(household["admin"]),
    )
    assert response.status_code == 422


def test_member_without_linked_record_sees_no_access_events(
    app_client: Any, household: dict[str, Any]
) -> None:
    _create_user(app_client, household["admin"], "unlinked@example.com", "member")
    token = _login(app_client, "unlinked@example.com")["tokens"]["access_token"]
    _insert_access_event(decision="allow", member_id=household["asha"])
    response = app_client.get(f"{V1}/events/access", headers=_auth(token))
    assert response.status_code == 200
    assert response.json() == []


def test_events_require_authentication(app_client: Any) -> None:
    for path in (
        "/events/access",
        "/events/security",
        "/incidents",
        "/dashboard/summary",
    ):
        assert app_client.get(f"{V1}{path}").status_code == 401, path


# --- security-event history ----------------------------------------------------


def test_security_events_visibility_per_role(
    app_client: Any, household: dict[str, Any]
) -> None:
    own = _insert_security_event(member_id=household["asha"], suspicious=True)
    _insert_security_event(member_id=household["ravi"])
    account = _insert_security_event(user_id=household["member_user_id"])

    admin = app_client.get(f"{V1}/events/security", headers=_auth(household["admin"]))
    assert len(admin.json()) == 3
    assert all(e["ip_address"] == "10.0.0.5" for e in admin.json())
    assert all(e["details"] == {"attempts": 3} for e in admin.json())

    viewer = app_client.get(f"{V1}/events/security", headers=_auth(household["viewer"]))
    assert len(viewer.json()) == 3
    for event in viewer.json():
        assert event["family_member_id"] is None
        assert event["user_id"] is None
        assert event["ip_address"] is None
        assert event["details"] is None

    member = app_client.get(f"{V1}/events/security", headers=_auth(household["member"]))
    assert {e["id"] for e in member.json()} == {own, account}
    assert all(e["ip_address"] is None for e in member.json())

    suspicious = app_client.get(
        f"{V1}/events/security",
        params={"suspicious_only": "true"},
        headers=_auth(household["admin"]),
    )
    assert [e["id"] for e in suspicious.json()] == [own]


# --- incidents -----------------------------------------------------------------


def test_member_cannot_read_incidents(
    app_client: Any, household: dict[str, Any]
) -> None:
    incident = _insert_incident()
    member = _auth(household["member"])
    assert app_client.get(f"{V1}/incidents", headers=member).status_code == 403
    assert (
        app_client.get(f"{V1}/incidents/{incident}", headers=member).status_code == 403
    )


def test_viewer_reads_incident_summary_without_attack_chain(
    app_client: Any, household: dict[str, Any]
) -> None:
    incident = _insert_incident()
    viewer = _auth(household["viewer"])
    listed = app_client.get(f"{V1}/incidents", headers=viewer)
    assert [i["id"] for i in listed.json()] == [incident]

    detail = app_client.get(f"{V1}/incidents/{incident}", headers=viewer).json()
    assert detail["attack_chain"] is None
    assert detail["ai_advisory"] is None

    admin = app_client.get(
        f"{V1}/incidents/{incident}", headers=_auth(household["admin"])
    ).json()
    assert admin["attack_chain"] == {"steps": ["deny", "deny", "deny"]}


def test_incident_status_workflow_is_validated_and_audited(
    app_client: Any, household: dict[str, Any]
) -> None:
    incident = _insert_incident()
    url = f"{V1}/incidents/{incident}"
    admin = _auth(household["admin"])

    step = app_client.patch(url, json={"status": "investigating"}, headers=admin)
    assert step.status_code == 200
    assert step.json()["status"] == "investigating"

    no_notes = app_client.patch(url, json={"status": "resolved"}, headers=admin)
    assert no_notes.status_code == 422

    closed = app_client.patch(
        url,
        json={"status": "resolved", "resolution_notes": "Neighbour's child, known."},
        headers=admin,
    )
    assert closed.status_code == 200
    assert closed.json()["closed_at"] is not None
    assert closed.json()["resolved_by_user_id"] is not None

    skip = app_client.patch(url, json={"status": "investigating"}, headers=admin)
    assert skip.status_code == 422, "a closed incident can only be reopened"

    reopened = app_client.patch(url, json={"status": "open"}, headers=admin)
    assert reopened.status_code == 200
    assert reopened.json()["closed_at"] is None

    assert _audit_count("incident.update") == 3


def test_incident_update_rules(app_client: Any, household: dict[str, Any]) -> None:
    incident = _insert_incident()
    url = f"{V1}/incidents/{incident}"
    admin = _auth(household["admin"])

    assert app_client.patch(url, json={}, headers=admin).status_code == 422
    assert (
        app_client.patch(
            url, json={"status": "open"}, headers=_auth(household["viewer"])
        ).status_code
        == 403
    )
    not_admin = app_client.patch(
        url, json={"assigned_to_user_id": household["viewer_id"]}, headers=admin
    )
    assert not_admin.status_code == 422

    admin_id = _me(app_client, household["admin"]).json()["id"]
    assigned = app_client.patch(
        url, json={"assigned_to_user_id": admin_id}, headers=admin
    )
    assert assigned.json()["assigned_to_user_id"] == admin_id
    unassigned = app_client.patch(
        url, json={"assigned_to_user_id": None}, headers=admin
    )
    assert unassigned.json()["assigned_to_user_id"] is None

    missing = app_client.patch(
        f"{V1}/incidents/99999", json={"status": "open"}, headers=admin
    )
    assert missing.status_code == 404


# --- dashboard -----------------------------------------------------------------


def test_dashboard_on_empty_database_reports_zeros(
    app_client: Any, household: dict[str, Any]
) -> None:
    body = app_client.get(
        f"{V1}/dashboard/summary", headers=_auth(household["admin"])
    ).json()
    assert body["scope"] == "household"
    assert body["access_all_time"] == {"allow": 0, "deny": 0, "hold": 0, "total": 0}
    assert body["last_access_event_at"] is None
    assert sum(body["active_incidents_by_severity"].values()) == 0
    assert body["suspicious_events_last_24h"] == 0


def test_dashboard_counts_come_from_stored_rows(
    app_client: Any, household: dict[str, Any]
) -> None:
    now = datetime.now(UTC)
    _insert_access_event(
        decision="allow",
        member_id=household["asha"],
        occurred_at=now - timedelta(hours=1),
    )
    _insert_access_event(decision="deny", occurred_at=now - timedelta(days=2))
    _insert_access_event(decision="hold", occurred_at=now - timedelta(days=30))
    _insert_incident(severity="high")
    _insert_incident(severity="low", status="investigating")
    _insert_incident(severity="critical", status="false_positive")
    _insert_security_event(suspicious=True, occurred_at=now - timedelta(hours=2))
    _insert_security_event(suspicious=True, occurred_at=now - timedelta(days=3))

    admin = app_client.get(
        f"{V1}/dashboard/summary", headers=_auth(household["admin"])
    ).json()
    assert admin["access_last_24h"] == {"allow": 1, "deny": 0, "hold": 0, "total": 1}
    assert admin["access_last_7d"]["total"] == 2
    assert admin["access_all_time"] == {"allow": 1, "deny": 1, "hold": 1, "total": 3}
    assert admin["active_incidents_by_severity"]["high"] == 1
    assert admin["active_incidents_by_severity"]["low"] == 1
    assert admin["active_incidents_by_severity"]["critical"] == 0
    assert admin["suspicious_events_last_24h"] == 1

    member = app_client.get(
        f"{V1}/dashboard/summary", headers=_auth(household["member"])
    ).json()
    assert member["scope"] == "own"
    assert member["access_all_time"]["total"] == 1
    assert member["active_incidents_by_severity"] is None
    assert member["suspicious_events_last_24h"] is None
