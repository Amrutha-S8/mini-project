"""SMS fallback through the Twilio Messaging API.

``POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json`` with
HTTP Basic auth. A ``201`` with a message SID means *accepted* (Twilio status
``queued``/``accepted``), not delivered. Delivery is confirmed only by
Twilio's later status: from the status-callback webhook (signed with
``X-Twilio-Signature``) or by fetching the message, which works on a laptop
without a public URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.notifications.transport import HttpTransport, TransportError
from app.notifications.types import (
    STATUS_ACCEPTED,
    STATUS_DELIVERED,
    STATUS_FAILED,
    STATUS_READ,
    STATUS_SEND_FAILED,
    STATUS_SENT,
    IncidentAlert,
    SendResult,
    StatusReport,
    clip,
    valid_e164,
)

TWILIO_BASE = "https://api.twilio.com/2010-04-01"
_SID = re.compile(r"AC[0-9a-fA-F]{32}")
_MESSAGE_SID = re.compile(r"(SM|MM)[0-9a-fA-F]{32}")
_STATUS_MAP = {
    "queued": STATUS_ACCEPTED,
    "accepted": STATUS_ACCEPTED,
    "scheduled": STATUS_ACCEPTED,
    "sending": STATUS_ACCEPTED,
    "sent": STATUS_SENT,
    "delivered": STATUS_DELIVERED,
    "read": STATUS_READ,
    "undelivered": STATUS_FAILED,
    "failed": STATUS_FAILED,
    "canceled": STATUS_FAILED,
}


@dataclass(frozen=True)
class TwilioConfig:
    account_sid: str
    auth_token: str = field(repr=False)
    from_number: str
    recipient: str
    status_callback_url: str | None = None

    def problems(self) -> list[str]:
        found = []
        if not _SID.fullmatch(self.account_sid or ""):
            found.append("TWILIO_ACCOUNT_SID is missing or malformed")
        if not self.auth_token:
            found.append("TWILIO_AUTH_TOKEN is not set")
        if not valid_e164(self.from_number or ""):
            found.append("TWILIO_FROM_NUMBER must be E.164")
        if not valid_e164(self.recipient or ""):
            found.append("HOMEOWNER_SMS_NUMBER must be E.164")
        if self.status_callback_url and not self.status_callback_url.startswith(
            "https://"
        ):
            found.append("TWILIO_STATUS_CALLBACK_URL must be https")
        return found


def sms_text(alert: IncidentAlert) -> str:
    when = alert.occurred_at.strftime("%Y-%m-%d %H:%M UTC")
    text = (
        f"Smart Home alert [{alert.severity.upper()}]: {alert.title}. "
        f"{alert.reason} ({alert.incident_uid}, {when})"
    )
    return " ".join(text.split())[:480]


def _auth_header(config: TwilioConfig) -> str:
    raw = f"{config.account_sid}:{config.auth_token}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _parse(body: bytes) -> Mapping[str, Any]:
    try:
        parsed = json.loads(body or b"{}")
    except ValueError:
        return {}
    return parsed if isinstance(parsed, Mapping) else {}


class TwilioSmsClient:
    def __init__(self, config: TwilioConfig, transport: HttpTransport) -> None:
        self._config = config
        self._transport = transport

    def send(self, alert: IncidentAlert) -> SendResult:
        cfg = self._config
        form = {"To": cfg.recipient, "From": cfg.from_number, "Body": sms_text(alert)}
        if cfg.status_callback_url:
            form["StatusCallback"] = cfg.status_callback_url
        try:
            response = self._transport.request(
                "POST",
                f"{TWILIO_BASE}/Accounts/{cfg.account_sid}/Messages.json",
                headers={
                    "Authorization": _auth_header(cfg),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body=urllib.parse.urlencode(form).encode("ascii"),
            )
        except TransportError as exc:
            return SendResult(
                STATUS_SEND_FAILED, error_code="transport", error_message=clip(str(exc))
            )
        parsed = _parse(response.body)
        sid = str(parsed.get("sid") or "")
        raw_status = str(parsed.get("status") or "").lower()
        if 200 <= response.status < 300 and _MESSAGE_SID.fullmatch(sid):
            status = _STATUS_MAP.get(raw_status, STATUS_ACCEPTED)
            if status == STATUS_FAILED:
                return SendResult(
                    STATUS_SEND_FAILED,
                    provider_message_id=sid,
                    provider_status=raw_status,
                    http_status=response.status,
                    error_code=clip(str(parsed.get("error_code"))),
                    error_message=clip(str(parsed.get("error_message") or raw_status)),
                )
            return SendResult(
                STATUS_ACCEPTED,
                provider_message_id=sid,
                provider_status=raw_status or "accepted",
                http_status=response.status,
            )
        return SendResult(
            STATUS_SEND_FAILED,
            http_status=response.status,
            error_code=clip(str(parsed.get("code") or f"http_{response.status}")),
            error_message=clip(
                str(parsed.get("message") or "provider did not return a message sid")
            ),
        )

    def fetch_status(self, message_sid: str) -> StatusReport | None:
        """Ask Twilio for the current status. None if it cannot be read."""
        if not _MESSAGE_SID.fullmatch(message_sid):
            return None
        cfg = self._config
        try:
            response = self._transport.request(
                "GET",
                f"{TWILIO_BASE}/Accounts/{cfg.account_sid}/Messages/{message_sid}.json",
                headers={"Authorization": _auth_header(cfg)},
            )
        except TransportError:
            return None
        if response.status != 200:
            return None
        parsed = _parse(response.body)
        raw = str(parsed.get("status") or "").lower()
        if raw not in _STATUS_MAP:
            return None
        return StatusReport(
            provider_message_id=message_sid,
            status=_STATUS_MAP[raw],
            provider_status=raw,
            error_code=clip(str(parsed["error_code"]))
            if parsed.get("error_code")
            else None,
            error_message=clip(str(parsed["error_message"]))
            if parsed.get("error_message")
            else None,
        )


# --- status callback ------------------------------------------------------------------


def verify_twilio_signature(
    auth_token: str, url: str, params: Mapping[str, str], header: str | None
) -> bool:
    """Twilio's scheme: base64(HMAC-SHA1(token, url + sorted key+value pairs))."""
    if not auth_token or not header:
        return False
    data = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = hmac.new(auth_token.encode("utf-8"), data.encode("utf-8"), hashlib.sha1)
    expected = base64.b64encode(digest.digest()).decode("ascii")
    return hmac.compare_digest(expected, header)


def parse_status_callback(params: Mapping[str, str]) -> StatusReport | None:
    sid = params.get("MessageSid") or params.get("SmsSid") or ""
    raw = (params.get("MessageStatus") or params.get("SmsStatus") or "").lower()
    if not _MESSAGE_SID.fullmatch(sid) or raw not in _STATUS_MAP:
        return None
    return StatusReport(
        provider_message_id=sid,
        status=_STATUS_MAP[raw],
        provider_status=raw,
        error_code=clip(params.get("ErrorCode")) if params.get("ErrorCode") else None,
        error_message=clip(params.get("ErrorMessage"))
        if params.get("ErrorMessage")
        else None,
    )
