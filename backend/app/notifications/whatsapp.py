"""WhatsApp Cloud API client, webhook signature check and status parsing.

Sends through ``POST https://graph.facebook.com/{version}/{phone-number-id}/
messages`` with a bearer token. Outside the 24-hour customer-service window
Meta only delivers approved templates, so a configured template is used when
``template_name`` is set; otherwise a plain text message is sent, which Meta
accepts only inside that window.

The template must have exactly four body variables:
``{{1}}`` severity, ``{{2}}`` title, ``{{3}}`` reason, ``{{4}}`` incident id
and time.

A ``200`` response with a message id means *accepted*, not delivered. Meta
reports ``sent``, ``delivered``, ``read`` and ``failed`` later through the
webhook, which is verified with the app secret (``X-Hub-Signature-256``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
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

GRAPH_BASE = "https://graph.facebook.com"
_VERSION = re.compile(r"v\d{1,3}\.\d")
_PHONE_ID = re.compile(r"[0-9]{5,30}")
_STATUS_MAP = {
    "sent": STATUS_SENT,
    "delivered": STATUS_DELIVERED,
    "read": STATUS_READ,
    "failed": STATUS_FAILED,
}


@dataclass(frozen=True)
class WhatsAppConfig:
    access_token: str = field(repr=False)
    phone_number_id: str
    recipient: str
    api_version: str = "v25.0"
    template_name: str | None = None
    template_language: str = "en"

    def problems(self) -> list[str]:
        """Why this configuration cannot be used (empty when complete)."""
        found = []
        if not self.access_token:
            found.append("WHATSAPP_ACCESS_TOKEN is not set")
        if not _PHONE_ID.fullmatch(self.phone_number_id or ""):
            found.append("WHATSAPP_PHONE_NUMBER_ID is missing or not numeric")
        if not valid_e164(self.recipient or ""):
            found.append("HOMEOWNER_WHATSAPP_NUMBER must be E.164, e.g. +919876543210")
        if not _VERSION.fullmatch(self.api_version or ""):
            found.append("WHATSAPP_API_VERSION must look like v25.0")
        return found


def _template_param(text: str, limit: int) -> str:
    """Meta rejects template parameters with newlines, tabs or 4+ spaces."""
    flat = " ".join(text.split())
    return flat[:limit] or "-"


def alert_text(alert: IncidentAlert) -> str:
    when = alert.occurred_at.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"Smart Home Security alert [{alert.severity.upper()}]\n"
        f"{alert.title}\n"
        f"Reason: {alert.reason}\n"
        f"Time: {when}\n"
        f"Incident: {alert.incident_uid}\n"
        "Open the app to review. The door is controlled only by the AccessEngine."
    )[:1000]


def build_payload(config: WhatsAppConfig, alert: IncidentAlert) -> dict[str, Any]:
    to = config.recipient.lstrip("+")
    if config.template_name:
        when = alert.occurred_at.strftime("%Y-%m-%d %H:%M UTC")
        params = [
            _template_param(alert.severity.upper(), 20),
            _template_param(alert.title, 120),
            _template_param(alert.reason, 600),
            _template_param(f"{alert.incident_uid} at {when}", 120),
        ]
        return {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": {
                "name": config.template_name,
                "language": {"code": config.template_language},
                "components": [
                    {
                        "type": "body",
                        "parameters": [{"type": "text", "text": p} for p in params],
                    }
                ],
            },
        }
    return {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"preview_url": False, "body": alert_text(alert)},
    }


def _error_from(body: Mapping[str, Any]) -> tuple[str | None, str | None]:
    error = body.get("error")
    if isinstance(error, Mapping):
        return clip(str(error.get("code"))), clip(str(error.get("message", "")))
    return None, None


class WhatsAppCloudClient:
    def __init__(self, config: WhatsAppConfig, transport: HttpTransport) -> None:
        self._config = config
        self._transport = transport

    def send(self, alert: IncidentAlert) -> SendResult:
        cfg = self._config
        url = f"{GRAPH_BASE}/{cfg.api_version}/{cfg.phone_number_id}/messages"
        body = json.dumps(build_payload(cfg, alert)).encode("utf-8")
        try:
            response = self._transport.request(
                "POST",
                url,
                headers={
                    "Authorization": f"Bearer {cfg.access_token}",
                    "Content-Type": "application/json",
                },
                body=body,
            )
        except TransportError as exc:
            return SendResult(
                STATUS_SEND_FAILED, error_code="transport", error_message=clip(str(exc))
            )
        try:
            parsed = json.loads(response.body or b"{}")
        except ValueError:
            parsed = {}
        if not isinstance(parsed, Mapping):
            parsed = {}
        messages = parsed.get("messages")
        message_id = None
        if isinstance(messages, list) and messages and isinstance(messages[0], Mapping):
            raw_id = messages[0].get("id")
            message_id = str(raw_id) if raw_id else None
        if 200 <= response.status < 300 and message_id:
            return SendResult(
                STATUS_ACCEPTED,
                provider_message_id=clip(message_id, 128),
                provider_status="accepted",
                http_status=response.status,
            )
        code, message = _error_from(parsed)
        return SendResult(
            STATUS_SEND_FAILED,
            http_status=response.status,
            error_code=code or f"http_{response.status}",
            error_message=message or "provider did not return a message id",
        )


# --- webhooks -------------------------------------------------------------------------


def verify_signature(app_secret: str, raw_body: bytes, header: str | None) -> bool:
    """Check ``X-Hub-Signature-256: sha256=<hex>`` over the raw request body."""
    if not app_secret or not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(
        app_secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def verify_subscription(
    verify_token: str, mode: str | None, token: str | None, challenge: str | None
) -> str | None:
    """The webhook-setup handshake. Returns the challenge to echo, or None."""
    if (
        verify_token
        and mode == "subscribe"
        and token is not None
        and challenge is not None
        and hmac.compare_digest(verify_token, token)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", challenge)
    ):
        return challenge
    return None


def parse_status_webhook(payload: Any) -> list[StatusReport]:
    """Status reports from a webhook body. Unknown shapes yield nothing."""
    reports: list[StatusReport] = []
    if not isinstance(payload, Mapping):
        return reports
    for entry in payload.get("entry") or []:
        if not isinstance(entry, Mapping):
            continue
        for change in entry.get("changes") or []:
            value = change.get("value") if isinstance(change, Mapping) else None
            if not isinstance(value, Mapping):
                continue
            for item in value.get("statuses") or []:
                if not isinstance(item, Mapping):
                    continue
                message_id = item.get("id")
                raw = str(item.get("status", "")).lower()
                if not message_id or raw not in _STATUS_MAP:
                    continue
                code = message = None
                errors = item.get("errors")
                if (
                    isinstance(errors, list)
                    and errors
                    and isinstance(errors[0], Mapping)
                ):
                    code = clip(str(errors[0].get("code")))
                    message = clip(
                        str(errors[0].get("title") or errors[0].get("message") or "")
                    )
                reports.append(
                    StatusReport(
                        provider_message_id=clip(str(message_id), 128) or "",
                        status=_STATUS_MAP[raw],
                        provider_status=raw,
                        error_code=code,
                        error_message=message,
                    )
                )
    return reports
