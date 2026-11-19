"""API tests: suspicious activity monitoring, incidents and notifications.

Need the approved stack (FastAPI, SQLAlchemy, ...) and SKIP without it.
Providers are replaced by the scripted ``FakeTransport`` from
``test_notifications_core`` through ``app.state.notification_transport``; no
real WhatsApp or SMS request is made and no credential is real.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.conftest import ADMIN_PAYLOAD, requires_stack
from tests.test_notifications_core import (
    ACCOUNT,
    SMS_OK,
    SMS_SID,
    WA_ERR,
    WA_ID,
    WA_OK,
    FakeTransport,
    _twilio_sig,
)

pytestmark = requires_stack

V1 = "/api/v1"
PASSWORD = "Str0ng-Household-Pass"
APP_SECRET = "test-app-secret"
CALLBACK = "https://home.example/api/v1/notifications/webhooks/twilio"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login(client: Any, email: str, password: str = PASSWORD) -> str:
    response = client.post(
        f"{V1}/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["tokens"]["access_token"])


def _user(client: Any, admin: str, email: str, role: str) -> str:
    response = client.post(
        f"{V1}/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": email, "role": role},
        headers=_auth(admin),
    )
    assert response.status_code == 201, response.text
    return _login(client, email)


@pytest.fixture
def admin(app_client: Any) -> str:
    return _login(app_client, ADMIN_PAYLOAD["email"], ADMIN_PAYLOAD["password"])


def _configure(client: Any, *, transport: FakeTransport | None, **values: Any) -> None:
    base = {
        "whatsapp_app_secret": APP_SECRET,
        "twilio_status_callback_url": CALLBACK,
    }
    whatsapp = {
        "whatsapp_enabled": True,
        "whatsapp_access_token": "wa-token",
        "whatsapp_phone_number_id": "1234567890",
        "homeowner_whatsapp_number": "+919876543210",
    }
    sms = {
        "sms_enabled": True,
        "twilio_account_sid": ACCOUNT,
        "twilio_auth_token": "tw-token",
        "twilio_from_number": "+15005550006",
        "homeowner_sms_number": "+919876543210",
    }
    update: dict[str, Any] = {**base}
    if values.pop("with_whatsapp", False):
        update.update(whatsapp)
    if values.pop("with_sms", False):
        update.update(sms)
    update.update(values)
    state = client.app.state
    state.settings = state.settings.model_copy(update=update)
    state.notification_transport = transport


def _record(event_type: str, **fields: Any) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "source_module": "camera_client",
        "occurred_at": datetime.now(UTC).isoformat(),
        **fields,
    }


def _ingest(client: Any, token: str, record: dict[str, Any]) -> dict[str, Any]:
    response = client.post(f"{V1}/monitoring/events", json=record, headers=_auth(token))
    assert response.status_code == 201, response.text
    return dict(response.json())


def _notifications(client: Any, admin: str, incident_id: int) -> list[dict[str, Any]]:
    response = client.get(
        f"{V1}/incidents/{incident_id}/notifications", headers=_auth(admin)
    )
    assert response.status_code == 200, response.text
    return list(response.json())


def _wa_webhook(client: Any, status: str, *, secret: str = APP_SECRET) -> Any:
    body = json.dumps(
        {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "1",
                    "changes": [
                        {
                            "field": "messages",
                            "value": {
                                "statuses": [
                                    {"id": WA_ID, "status": status, "timestamp": "1"}
                                ]
                            },
                        }
                    ],
                }
            ],
        }
    ).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        f"{V1}/notifications/webhooks/whatsapp",
        content=body,
        headers={"X-Hub-Signature-256": signature, "Content-Type": "application/json"},
    )


def _tampered_grant(client: Any, admin: str) -> dict[str, Any]:
    """An external record claiming an unlock with no AccessEngine decision."""
    result = _ingest(client, admin, _record("access.allowed", door_id="front"))
    (finding,) = [
        f for f in result["findings"] if f["rule"] == "unverified_access_grant"
    ]
    return finding


# --- ingestion and permissions --------------------------------------------------------


def test_ingestion_requires_admin(app_client: Any, admin: str) -> None:
    viewer = _user(app_client, admin, "viewer@example.com", "viewer")
    member = _user(app_client, admin, "member@example.com", "member")
    record = _record("access.denied", door_id="front")
    assert app_client.post(f"{V1}/monitoring/events", json=record).status_code == 401
    for token in (viewer, member):
        response = app_client.post(
            f"{V1}/monitoring/events", json=record, headers=_auth(token)
        )
        assert response.status_code == 403


def test_single_denial_is_stored_without_an_incident(
    app_client: Any, admin: str
) -> None:
    result = _ingest(app_client, admin, _record("access.denied", door_id="front"))
    assert result["status"] == "stored"
    assert result["findings"] == []
    assert app_client.get(f"{V1}/incidents", headers=_auth(admin)).json() == []


def test_repeated_denials_create_one_incident_with_reason_and_events(
    app_client: Any, admin: str
) -> None:
    results = [
        _ingest(app_client, admin, _record("access.denied", door_id="front"))
        for _ in range(4)
    ]
    assert results[0]["findings"] == [] and results[1]["findings"] == []
    third = results[2]["findings"][0]
    fourth = results[3]["findings"][0]
    assert third["rule"] == "repeated_denied_access" and third["created"] is True
    assert fourth["incident_id"] == third["incident_id"] and fourth["created"] is False

    incidents = app_client.get(f"{V1}/incidents", headers=_auth(admin)).json()
    assert len(incidents) == 1
    assert incidents[0]["incident_uid"].startswith("inc-")
    assert incidents[0]["severity"] == "medium"
    assert "denied access decisions at front" in incidents[0]["latest_reason"]
    assert incidents[0]["event_count"] == 4

    detail = app_client.get(
        f"{V1}/incidents/{third['incident_id']}", headers=_auth(admin)
    ).json()
    assert [d["detector_rule"] for d in detail["detections"]] == [
        "repeated_denied_access",
        "repeated_denied_access",
    ]
    assert results[2]["event_uid"] in detail["detections"][0]["event_uids"]

    events = app_client.get(f"{V1}/events/security", headers=_auth(admin)).json()
    assert {e["incident_id"] for e in events} == {third["incident_id"]}


def test_external_record_cannot_pose_as_an_internal_module(
    app_client: Any, admin: str
) -> None:
    _ingest(app_client, admin, _record("auth.login_failed", source_module="auth"))
    (event,) = app_client.get(f"{V1}/events/security", headers=_auth(admin)).json()
    assert event["source_module"] == "ingest.auth"


def test_rejected_records_are_recorded_and_bursts_detected(
    app_client: Any, admin: str
) -> None:
    bad = _record("door.teleported")
    results = [_ingest(app_client, admin, bad) for _ in range(5)]
    assert all(r["status"] == "rejected" for r in results)
    assert "unknown event_type" in (results[0]["error"] or "")
    events = app_client.get(f"{V1}/events/security", headers=_auth(admin)).json()
    assert {e["event_type"] for e in events} == {"api.invalid_input"}
    assert results[-1]["findings"][0]["rule"] == "malformed_activity_records"


def test_far_future_record_is_rejected_and_flagged(app_client: Any, admin: str) -> None:
    result = _ingest(
        app_client,
        admin,
        _record("face.unknown_visitor", occurred_at="2099-01-01T00:00:00+00:00"),
    )
    assert result["status"] == "rejected"
    assert result["findings"][0]["rule"] == "future_dated_activity_record"


def test_duplicate_is_idempotent_and_reused_id_is_flagged(
    app_client: Any, admin: str
) -> None:
    record = _record("access.denied", door_id="front", event_id="cam-1")
    first = _ingest(app_client, admin, record)
    again = _ingest(app_client, admin, record)
    assert (first["status"], again["status"]) == ("stored", "duplicate")
    altered = _ingest(app_client, admin, {**record, "door_id": "garage"})
    assert altered["status"] == "stored"
    assert altered["event_uid"] != "cam-1"
    assert "event_id_conflict_rekeyed" in altered["warnings"]
    assert any(f["rule"] == "event_id_reuse" for f in altered["findings"])


def test_monitoring_never_creates_access_decisions(app_client: Any, admin: str) -> None:
    _tampered_grant(app_client, admin)
    assert app_client.get(f"{V1}/events/access", headers=_auth(admin)).json() == []
    summary = app_client.get(f"{V1}/dashboard/summary", headers=_auth(admin)).json()
    assert summary["access_all_time"]["total"] == 0
    assert summary["unacknowledged_active_incidents"] == 1
    assert summary["active_incidents_by_severity"]["high"] == 1


def test_unknown_member_claim_is_kept_out_of_foreign_keys(
    app_client: Any, admin: str
) -> None:
    result = _ingest(
        app_client, admin, _record("access.denied", door_id="front", member_id=999)
    )
    assert result["status"] == "stored"
    assert any(f["rule"] == "visitor_identity_conflict" for f in result["findings"])


# --- failed operator logins (real login endpoint) -------------------------------------


def test_failed_login_burst_creates_an_incident(app_client: Any, admin: str) -> None:
    for _ in range(5):
        response = app_client.post(
            f"{V1}/auth/login",
            json={"email": ADMIN_PAYLOAD["email"], "password": "wrong-password"},
        )
        assert response.status_code == 401
    incidents = app_client.get(f"{V1}/incidents", headers=_auth(admin)).json()
    assert [i["category"] for i in incidents] == ["failed_login_burst"]
    events = app_client.get(
        f"{V1}/events/security", params={"limit": 200}, headers=_auth(admin)
    ).json()
    assert sum(e["event_type"] == "auth.login_failed" for e in events) == 5


# --- notifications --------------------------------------------------------------------


def test_unconfigured_channels_are_recorded_and_nothing_is_sent(
    app_client: Any, admin: str
) -> None:
    transport = FakeTransport({})
    _configure(app_client, transport=transport)
    finding = _tampered_grant(app_client, admin)
    assert finding["notification_queued"] is True
    rows = _notifications(app_client, admin, finding["incident_id"])
    assert [(r["channel"], r["status"]) for r in rows] == [
        ("whatsapp", "not_configured"),
        ("sms", "not_configured"),
    ]
    assert not any(r["delivery_confirmed"] for r in rows)
    assert transport.requests == []


def test_whatsapp_accepted_is_not_delivered_until_the_webhook_says_so(
    app_client: Any, admin: str
) -> None:
    _configure(
        app_client,
        transport=FakeTransport({"graph.facebook.com": WA_OK}),
        with_whatsapp=True,
    )
    finding = _tampered_grant(app_client, admin)
    (row,) = _notifications(app_client, admin, finding["incident_id"])
    assert (row["status"], row["delivery_confirmed"]) == ("accepted", False)
    assert row["recipient_masked"] == "+91******3210"
    assert row["delivered_at"] is None

    assert _wa_webhook(app_client, "delivered").json() == {"processed": 1}
    (row,) = _notifications(app_client, admin, finding["incident_id"])
    assert (row["status"], row["delivery_confirmed"]) == ("delivered", True)
    assert row["delivered_at"] is not None


def test_webhook_with_bad_signature_changes_nothing(
    app_client: Any, admin: str
) -> None:
    _configure(
        app_client,
        transport=FakeTransport({"graph.facebook.com": WA_OK}),
        with_whatsapp=True,
    )
    finding = _tampered_grant(app_client, admin)
    assert _wa_webhook(app_client, "delivered", secret="forged").status_code == 403
    (row,) = _notifications(app_client, admin, finding["incident_id"])
    assert row["status"] == "accepted"


def test_webhook_refused_when_no_app_secret_is_configured(app_client: Any) -> None:
    _configure(app_client, transport=None, whatsapp_app_secret="")
    assert _wa_webhook(app_client, "delivered", secret="").status_code == 403


def test_whatsapp_error_falls_back_to_sms(app_client: Any, admin: str) -> None:
    _configure(
        app_client,
        transport=FakeTransport(
            {"graph.facebook.com": WA_ERR, "api.twilio.com": SMS_OK}
        ),
        with_whatsapp=True,
        with_sms=True,
    )
    finding = _tampered_grant(app_client, admin)
    rows = _notifications(app_client, admin, finding["incident_id"])
    assert [(r["channel"], r["status"]) for r in rows] == [
        ("whatsapp", "send_failed"),
        ("sms", "accepted"),
    ]
    assert rows[0]["error_code"] == "190"
    assert rows[1]["provider_message_id"] == SMS_SID


def test_both_channels_failing_is_recorded_as_failed(
    app_client: Any, admin: str
) -> None:
    _configure(
        app_client,
        transport=FakeTransport(
            {"graph.facebook.com": WA_ERR, "api.twilio.com": (500, {"message": "x"})}
        ),
        with_whatsapp=True,
        with_sms=True,
    )
    finding = _tampered_grant(app_client, admin)
    rows = _notifications(app_client, admin, finding["incident_id"])
    assert [r["status"] for r in rows] == ["send_failed", "send_failed"]
    assert not any(r["delivery_confirmed"] for r in rows)


def test_whatsapp_failure_reported_later_triggers_sms_fallback_once(
    app_client: Any, admin: str
) -> None:
    _configure(
        app_client,
        transport=FakeTransport(
            {"graph.facebook.com": WA_OK, "api.twilio.com": SMS_OK}
        ),
        with_whatsapp=True,
        with_sms=True,
    )
    finding = _tampered_grant(app_client, admin)
    _wa_webhook(app_client, "failed")
    _wa_webhook(app_client, "failed")  # repeated report: no second fallback
    rows = _notifications(app_client, admin, finding["incident_id"])
    assert [(r["channel"], r["status"], r["trigger_reason"]) for r in rows] == [
        ("whatsapp", "failed", "created"),
        ("sms", "accepted", "fallback"),
    ]


def test_sms_delivery_confirmed_by_polling_twilio(app_client: Any, admin: str) -> None:
    transport = FakeTransport(
        {
            f"Messages/{SMS_SID}.json": (200, {"sid": SMS_SID, "status": "delivered"}),
            "Messages.json": SMS_OK,
        }
    )
    _configure(app_client, transport=transport, with_sms=True)
    finding = _tampered_grant(app_client, admin)
    rows = _notifications(app_client, admin, finding["incident_id"])
    sms_row = next(r for r in rows if r["channel"] == "sms")
    assert sms_row["status"] == "accepted"
    refreshed = app_client.post(
        f"{V1}/notifications/{sms_row['id']}/refresh", headers=_auth(admin)
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["status"] == "delivered"
    assert refreshed.json()["delivery_confirmed"] is True


def test_signed_twilio_callback_updates_status(app_client: Any, admin: str) -> None:
    _configure(
        app_client, transport=FakeTransport({"api.twilio.com": SMS_OK}), with_sms=True
    )
    finding = _tampered_grant(app_client, admin)
    params = {
        "MessageSid": SMS_SID,
        "MessageStatus": "undelivered",
        "ErrorCode": "30003",
    }
    body = urllib.parse.urlencode(params)
    headers = {
        "X-Twilio-Signature": _twilio_sig("tw-token", CALLBACK, params),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    forged = app_client.post(
        f"{V1}/notifications/webhooks/twilio",
        content=body,
        headers={**headers, "X-Twilio-Signature": "forged"},
    )
    assert forged.status_code == 403
    ok = app_client.post(
        f"{V1}/notifications/webhooks/twilio", content=body, headers=headers
    )
    assert ok.json() == {"processed": 1}
    sms_row = next(
        r
        for r in _notifications(app_client, admin, finding["incident_id"])
        if r["channel"] == "sms"
    )
    assert (sms_row["status"], sms_row["error_code"]) == ("failed", "30003")


def test_channel_status_lists_problems_without_secrets(
    app_client: Any, admin: str
) -> None:
    _configure(app_client, transport=None, with_whatsapp=True, whatsapp_access_token="")
    response = app_client.get(f"{V1}/notifications/channels", headers=_auth(admin))
    assert response.status_code == 200
    whatsapp, sms = response.json()
    assert whatsapp["configured"] is False
    assert "WHATSAPP_ACCESS_TOKEN is not set" in whatsapp["problems"]
    assert sms["configured"] is False
    assert "wa-token" not in response.text and APP_SECRET not in response.text


# --- incident actions -----------------------------------------------------------------


def test_acknowledge_investigate_resolve_are_admin_only_and_audited(
    app_client: Any, admin: str
) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine
    from app.models.audit_log import AuditLog

    viewer = _user(app_client, admin, "viewer@example.com", "viewer")
    incident_id = _tampered_grant(app_client, admin)["incident_id"]
    url = f"{V1}/incidents/{incident_id}"
    for action in ("acknowledge", "investigate"):
        assert (
            app_client.post(f"{url}/{action}", headers=_auth(viewer)).status_code == 403
        )
    assert (
        app_client.post(
            f"{url}/resolve",
            json={"resolution": "resolved", "resolution_notes": "checked"},
            headers=_auth(viewer),
        ).status_code
        == 403
    )

    acked = app_client.post(f"{url}/acknowledge", headers=_auth(admin)).json()
    assert acked["acknowledged_at"] is not None and acked["status"] == "open"
    again = app_client.post(f"{url}/acknowledge", headers=_auth(admin)).json()
    assert again["acknowledged_at"] == acked["acknowledged_at"], "idempotent"

    investigating = app_client.post(f"{url}/investigate", headers=_auth(admin)).json()
    assert investigating["status"] == "investigating"

    missing_notes = app_client.post(
        f"{url}/resolve", json={"resolution": "resolved"}, headers=_auth(admin)
    )
    assert missing_notes.status_code == 422
    resolved = app_client.post(
        f"{url}/resolve",
        json={"resolution": "false_positive", "resolution_notes": "Test record."},
        headers=_auth(admin),
    ).json()
    assert resolved["status"] == "false_positive" and resolved["closed_at"]

    with Session(get_writer_engine()) as db:
        actions = list(
            db.execute(
                select(AuditLog.action).where(AuditLog.entity_type == "incident")
            ).scalars()
        )
    assert actions.count("incident.create") == 1
    assert actions.count("incident.acknowledge") == 1
    assert actions.count("incident.update") == 2


def test_viewer_sees_reasons_but_not_notifications_member_sees_nothing(
    app_client: Any, admin: str
) -> None:
    viewer = _user(app_client, admin, "viewer@example.com", "viewer")
    member = _user(app_client, admin, "member@example.com", "member")
    incident_id = _tampered_grant(app_client, admin)["incident_id"]

    detail = app_client.get(f"{V1}/incidents/{incident_id}", headers=_auth(viewer))
    assert detail.status_code == 200
    assert detail.json()["detections"][0]["reason"]
    assert detail.json()["attack_chain"] is None
    for path in (f"/incidents/{incident_id}/notifications", "/notifications"):
        assert app_client.get(f"{V1}{path}", headers=_auth(viewer)).status_code == 403
    assert app_client.get(f"{V1}/incidents", headers=_auth(member)).status_code == 403
    assert (
        app_client.post(
            f"{V1}/incidents/{incident_id}/notify", headers=_auth(viewer)
        ).status_code
        == 403
    )


def test_acknowledged_incident_is_not_renotified_but_manual_notify_works(
    app_client: Any, admin: str
) -> None:
    from app.services import notification_service

    _configure(
        app_client,
        transport=FakeTransport({"graph.facebook.com": WA_OK}),
        with_whatsapp=True,
    )
    incident_id = _tampered_grant(app_client, admin)["incident_id"]
    app_client.post(f"{V1}/incidents/{incident_id}/acknowledge", headers=_auth(admin))

    from sqlalchemy.orm import Session

    from app.database.session import get_writer_engine

    with Session(get_writer_engine()) as db:
        skipped = notification_service.notify_incident(
            db,
            incident_id,
            trigger_reason="escalated",
            settings=app_client.app.state.settings,
            transport=app_client.app.state.notification_transport,
        )
    assert skipped.attempted is False

    manual = app_client.post(
        f"{V1}/incidents/{incident_id}/notify", headers=_auth(admin)
    )
    assert manual.status_code == 202
    assert (
        "delivery is shown only once the provider confirms" in manual.json()["message"]
    )
    rows = _notifications(app_client, admin, incident_id)
    assert [r["trigger_reason"] for r in rows] == ["created", "manual"]
