"""WhatsApp/SMS clients, fallback, webhook verification and status rules.

Stdlib only: providers are exercised through a fake transport that records
requests and returns scripted responses. No network access, no real
credentials. These tests show the code never reports delivery without a
provider report, and that fallback and failures are recorded honestly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.parse
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from app.notifications import dispatcher, sms, types, whatsapp
from app.notifications.transport import HttpResponse, TransportError, UrllibTransport

ALERT = types.IncidentAlert(
    incident_uid="inc-abc",
    severity="high",
    title="Repeated denied access at front",
    reason="4 denied access decisions at front within 10 minutes (threshold 3).",
    occurred_at=datetime(2026, 11, 19, 14, 0, tzinfo=UTC),
)
WA_ID = "wamid.HBgLOTE5ODc2NTQzMjEwFQIAERgS"
SMS_SID = "SM" + "a" * 32
ACCOUNT = "AC" + "b" * 32


class FakeTransport:
    """Scripted responses per URL fragment. Raises when told to."""

    def __init__(self, script: Mapping[str, Any]) -> None:
        self.script = dict(script)
        self.requests: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse:
        self.requests.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body}
        )
        for fragment, answer in self.script.items():
            if fragment in url:
                if isinstance(answer, Exception):
                    raise answer
                status, payload = answer
                return HttpResponse(status, json.dumps(payload).encode())
        raise AssertionError(f"unexpected request to {url}")


def settings(**overrides: Any) -> dispatcher.NotificationSettings:
    values: dict[str, Any] = {
        "whatsapp_enabled": True,
        "whatsapp_access_token": "wa-token-secret",
        "whatsapp_phone_number_id": "1234567890",
        "whatsapp_api_version": "v25.0",
        "whatsapp_template_name": None,
        "whatsapp_template_language": "en",
        "whatsapp_recipient": "+919876543210",
        "sms_enabled": True,
        "twilio_account_sid": ACCOUNT,
        "twilio_auth_token": "tw-token-secret",
        "twilio_from_number": "+15005550006",
        "sms_recipient": "+919876543210",
    }
    values.update(overrides)
    return dispatcher.NotificationSettings(**values)


WA_OK = (200, {"messages": [{"id": WA_ID}]})
WA_ERR = (401, {"error": {"code": 190, "message": "Invalid OAuth access token."}})
SMS_OK = (201, {"sid": SMS_SID, "status": "queued"})
SMS_ERR = (400, {"code": 21211, "message": "The 'To' number is not valid."})


class Recorder:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def skipped(self, setup: dispatcher.ChannelSetup, reason: str) -> None:
        self.rows.append(
            {"channel": setup.channel, "status": "not_configured", "reason": reason}
        )

    def started(self, setup: dispatcher.ChannelSetup) -> object:
        row = {"channel": setup.channel, "status": "pending"}
        self.rows.append(row)
        return row

    def finished(self, handle: object, result: types.SendResult) -> None:
        assert isinstance(handle, dict)
        handle["status"] = result.status
        handle["id"] = result.provider_message_id
        handle["error"] = result.error_code


def run(
    transport: FakeTransport, **overrides: Any
) -> tuple[list[dispatcher.AttemptOutcome], Recorder]:
    recorder = Recorder()
    setups = dispatcher.build_setups(settings(**overrides), transport)
    return dispatcher.dispatch(ALERT, setups, recorder), recorder


# --- dispatch and fallback ------------------------------------------------------------


def test_whatsapp_accepted_means_no_sms_and_no_delivery_claim() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_OK})
    outcomes, recorder = run(transport)
    assert [r["channel"] for r in recorder.rows] == ["whatsapp"]
    assert recorder.rows[0]["status"] == types.STATUS_ACCEPTED
    assert recorder.rows[0]["id"] == WA_ID
    assert not types.delivery_confirmed(recorder.rows[0]["status"])
    assert "delivery not yet confirmed" in dispatcher.summarise(outcomes)


def test_whatsapp_error_falls_back_to_sms() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_ERR, "api.twilio.com": SMS_OK})
    outcomes, recorder = run(transport)
    assert [(r["channel"], r["status"]) for r in recorder.rows] == [
        ("whatsapp", types.STATUS_SEND_FAILED),
        ("sms", types.STATUS_ACCEPTED),
    ]
    assert recorder.rows[0]["error"] == "190"
    assert "accepted by the sms provider" in dispatcher.summarise(outcomes)


def test_network_failure_falls_back_to_sms() -> None:
    transport = FakeTransport(
        {"graph.facebook.com": TransportError("URLError"), "api.twilio.com": SMS_OK}
    )
    _outcomes, recorder = run(transport)
    assert recorder.rows[0]["status"] == types.STATUS_SEND_FAILED
    assert recorder.rows[0]["error"] == "transport"
    assert recorder.rows[1]["status"] == types.STATUS_ACCEPTED


def test_unconfigured_whatsapp_goes_straight_to_sms_and_is_recorded() -> None:
    transport = FakeTransport({"api.twilio.com": SMS_OK})
    _outcomes, recorder = run(transport, whatsapp_enabled=False)
    assert recorder.rows[0] == {
        "channel": "whatsapp",
        "status": "not_configured",
        "reason": "WHATSAPP_ENABLED is not true",
    }
    assert recorder.rows[1]["status"] == types.STATUS_ACCEPTED
    assert all("graph.facebook.com" not in r["url"] for r in transport.requests)


def test_both_channels_failing_is_reported_as_nothing_sent() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_ERR, "api.twilio.com": SMS_ERR})
    outcomes, recorder = run(transport)
    assert [r["status"] for r in recorder.rows] == [types.STATUS_SEND_FAILED] * 2
    assert (
        dispatcher.summarise(outcomes)
        == "every configured channel failed; nothing was sent"
    )


def test_nothing_configured_sends_nothing_and_says_so() -> None:
    transport = FakeTransport({})
    outcomes, recorder = run(transport, whatsapp_enabled=False, sms_enabled=False)
    assert transport.requests == []
    assert [r["status"] for r in recorder.rows] == ["not_configured"] * 2
    assert "nothing was sent" in dispatcher.summarise(outcomes)


def test_sms_not_configured_after_whatsapp_failure() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_ERR})
    _outcomes, recorder = run(transport, twilio_auth_token="")
    assert recorder.rows[1]["status"] == "not_configured"
    assert "TWILIO_AUTH_TOKEN is not set" in recorder.rows[1]["reason"]


def test_a_crashing_sender_still_falls_back() -> None:
    class Broken:
        def send(self, alert: types.IncidentAlert) -> types.SendResult:
            raise RuntimeError("bug")

    transport = FakeTransport({"api.twilio.com": SMS_OK})
    setups = dispatcher.build_setups(settings(), transport)
    setups[0] = dispatcher.ChannelSetup(
        "whatsapp", "meta_whatsapp_cloud", None, (), Broken()
    )
    recorder = Recorder()
    dispatcher.dispatch(ALERT, setups, recorder)
    assert recorder.rows[0]["error"] == "internal_error"
    assert recorder.rows[1]["status"] == types.STATUS_ACCEPTED


@pytest.mark.parametrize(
    "overrides,problem",
    [
        ({"whatsapp_phone_number_id": "abc"}, "WHATSAPP_PHONE_NUMBER_ID"),
        ({"whatsapp_recipient": "9876543210"}, "HOMEOWNER_WHATSAPP_NUMBER"),
        ({"whatsapp_api_version": "25"}, "WHATSAPP_API_VERSION"),
        ({"whatsapp_access_token": ""}, "WHATSAPP_ACCESS_TOKEN"),
    ],
)
def test_incomplete_whatsapp_configuration_is_explained(
    overrides: dict[str, Any], problem: str
) -> None:
    setups = dispatcher.build_setups(settings(**overrides), FakeTransport({}))
    assert not setups[0].usable
    assert any(problem in p for p in setups[0].problems)


def test_settings_repr_never_shows_tokens() -> None:
    text = repr(settings())
    assert "wa-token-secret" not in text and "tw-token-secret" not in text


# --- provider requests ----------------------------------------------------------------


def test_whatsapp_text_request_shape() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_OK})
    run(transport)
    req = transport.requests[0]
    assert req["url"] == "https://graph.facebook.com/v25.0/1234567890/messages"
    assert req["headers"]["Authorization"] == "Bearer wa-token-secret"
    body = json.loads(req["body"])
    assert body["to"] == "919876543210"
    assert body["type"] == "text"
    assert "inc-abc" in body["text"]["body"]


def test_whatsapp_template_parameters_are_flattened() -> None:
    alert = types.IncidentAlert(
        "inc-1",
        "medium",
        "Title\twith\ttabs",
        "line one\nline two     spaced",
        ALERT.occurred_at,
    )
    cfg = whatsapp.WhatsAppConfig(
        "t", "1234567890", "+919876543210", template_name="security_alert"
    )
    payload = whatsapp.build_payload(cfg, alert)
    params = [p["text"] for p in payload["template"]["components"][0]["parameters"]]
    assert len(params) == 4
    assert params[1] == "Title with tabs"
    assert params[2] == "line one line two spaced"
    assert all("\n" not in p and "\t" not in p and "    " not in p for p in params)


def test_twilio_request_shape() -> None:
    transport = FakeTransport({"graph.facebook.com": WA_ERR, "api.twilio.com": SMS_OK})
    run(transport)
    req = transport.requests[1]
    assert (
        req["url"]
        == f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT}/Messages.json"
    )
    expected = base64.b64encode(f"{ACCOUNT}:tw-token-secret".encode()).decode()
    assert req["headers"]["Authorization"] == f"Basic {expected}"
    form = dict(urllib.parse.parse_qsl(req["body"].decode()))
    assert form["To"] == "+919876543210"
    assert form["From"] == "+15005550006"
    assert "inc-abc" in form["Body"] and len(form["Body"]) <= 480


def test_messages_carry_only_server_generated_incident_fields() -> None:
    text = whatsapp.alert_text(ALERT) + sms.sms_text(ALERT)
    for forbidden in ("embedding", "password", "token", "@"):
        assert forbidden not in text.lower()


def test_whatsapp_200_without_message_id_is_not_accepted() -> None:
    transport = FakeTransport(
        {"graph.facebook.com": (200, {"unexpected": True}), "api.twilio.com": SMS_OK}
    )
    _outcomes, recorder = run(transport)
    assert recorder.rows[0]["status"] == types.STATUS_SEND_FAILED


def test_twilio_immediate_failure_status_is_not_accepted() -> None:
    transport = FakeTransport(
        {
            "graph.facebook.com": WA_ERR,
            "api.twilio.com": (201, {"sid": SMS_SID, "status": "failed"}),
        }
    )
    _outcomes, recorder = run(transport)
    assert recorder.rows[1]["status"] == types.STATUS_SEND_FAILED


def test_transport_refuses_plain_http() -> None:
    with pytest.raises(TransportError):
        UrllibTransport().request("POST", "http://example.com", headers={})


# --- status reports -------------------------------------------------------------------


@pytest.mark.parametrize(
    "current,reported,expected",
    [
        ("accepted", "sent", "sent"),
        ("sent", "delivered", "delivered"),
        ("delivered", "read", "read"),
        ("read", "delivered", "read"),  # out-of-order report ignored
        ("delivered", "sent", "delivered"),
        ("accepted", "failed", "failed"),
        ("delivered", "failed", "delivered"),  # never un-deliver
        ("failed", "delivered", "failed"),  # terminal
        ("send_failed", "delivered", "send_failed"),
        ("not_configured", "sent", "not_configured"),
        ("accepted", "bogus", "accepted"),
    ],
)
def test_status_never_moves_backwards(
    current: str, reported: str, expected: str
) -> None:
    assert types.next_status(current, reported) == expected


def test_only_delivered_and_read_count_as_confirmed() -> None:
    confirmed = {s for s in types.STATUSES if types.delivery_confirmed(s)}
    assert confirmed == {"delivered", "read"}


def _wa_webhook(
    status: str, message_id: str = WA_ID, errors: Any = None
) -> dict[str, Any]:
    item: dict[str, Any] = {"id": message_id, "status": status, "timestamp": "1"}
    if errors:
        item["errors"] = errors
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "1",
                "changes": [{"field": "messages", "value": {"statuses": [item]}}],
            }
        ],
    }


def test_whatsapp_webhook_parsing() -> None:
    (report,) = whatsapp.parse_status_webhook(_wa_webhook("delivered"))
    assert (report.provider_message_id, report.status) == (WA_ID, "delivered")
    (failed,) = whatsapp.parse_status_webhook(
        _wa_webhook(
            "failed", errors=[{"code": 131026, "title": "Message undeliverable"}]
        )
    )
    assert failed.status == "failed" and failed.error_code == "131026"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"entry": "x"},
        {"entry": [{"changes": [{"value": {"statuses": [{"status": "delivered"}]}}]}]},
        _wa_webhook("deleted"),
    ],
)
def test_whatsapp_webhook_ignores_unknown_shapes(payload: Any) -> None:
    assert whatsapp.parse_status_webhook(payload) == []


def test_whatsapp_signature_verification() -> None:
    body = json.dumps(_wa_webhook("delivered")).encode()
    good = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    assert whatsapp.verify_signature("app-secret", body, good)
    assert not whatsapp.verify_signature("app-secret", body + b" ", good)
    assert not whatsapp.verify_signature("other", body, good)
    assert not whatsapp.verify_signature("", body, good), "no secret configured: refuse"
    assert not whatsapp.verify_signature("app-secret", body, None)


def test_whatsapp_subscription_handshake() -> None:
    assert whatsapp.verify_subscription("vt", "subscribe", "vt", "12345") == "12345"
    assert whatsapp.verify_subscription("vt", "subscribe", "wrong", "12345") is None
    assert whatsapp.verify_subscription("", "subscribe", "", "12345") is None
    assert whatsapp.verify_subscription("vt", "subscribe", "vt", "<script>") is None


def _twilio_sig(token: str, url: str, params: dict[str, str]) -> str:
    data = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    return base64.b64encode(
        hmac.new(token.encode(), data.encode(), hashlib.sha1).digest()
    ).decode()


def test_twilio_signature_verification() -> None:
    url = "https://home.example/api/v1/notifications/webhooks/twilio"
    params = {
        "MessageSid": SMS_SID,
        "MessageStatus": "delivered",
        "AccountSid": ACCOUNT,
    }
    sig = _twilio_sig("tw-token", url, params)
    assert sms.verify_twilio_signature("tw-token", url, params, sig)
    assert not sms.verify_twilio_signature(
        "tw-token", url, {**params, "MessageStatus": "failed"}, sig
    )
    assert not sms.verify_twilio_signature("", url, params, sig)
    assert not sms.verify_twilio_signature("tw-token", url + "x", params, sig)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("queued", "accepted"),
        ("sent", "sent"),
        ("delivered", "delivered"),
        ("undelivered", "failed"),
    ],
)
def test_twilio_callback_mapping(raw: str, expected: str) -> None:
    report = sms.parse_status_callback({"MessageSid": SMS_SID, "MessageStatus": raw})
    assert report is not None and report.status == expected


def test_twilio_callback_rejects_bad_sid() -> None:
    assert (
        sms.parse_status_callback({"MessageSid": "nope", "MessageStatus": "delivered"})
        is None
    )


def test_twilio_fetch_status() -> None:
    cfg = sms.TwilioConfig(ACCOUNT, "tok", "+15005550006", "+919876543210")
    transport = FakeTransport(
        {f"Messages/{SMS_SID}.json": (200, {"sid": SMS_SID, "status": "delivered"})}
    )
    report = sms.TwilioSmsClient(cfg, transport).fetch_status(SMS_SID)
    assert report is not None and report.status == "delivered"
    assert transport.requests[0]["method"] == "GET"
    unreachable = FakeTransport({"Messages": TransportError("timeout")})
    assert sms.TwilioSmsClient(cfg, unreachable).fetch_status(SMS_SID) is None


def test_masking_and_e164() -> None:
    assert types.mask_number("+919876543210") == "+91******3210"
    assert types.valid_e164("+919876543210")
    assert not types.valid_e164("09876543210")
    assert not types.valid_e164("+0123456789")
