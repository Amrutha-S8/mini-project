"""Shared notification types and status rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Final

CHANNEL_WHATSAPP: Final = "whatsapp"
CHANNEL_SMS: Final = "sms"
CHANNELS = (CHANNEL_WHATSAPP, CHANNEL_SMS)

PROVIDER_WHATSAPP: Final = "meta_whatsapp_cloud"
PROVIDER_TWILIO: Final = "twilio"

#: Row created, provider not called yet.
STATUS_PENDING: Final = "pending"
#: Channel skipped because it has no complete configuration. Nothing was sent.
STATUS_NOT_CONFIGURED: Final = "not_configured"
#: The provider call failed or was refused. Nothing was sent.
STATUS_SEND_FAILED: Final = "send_failed"
#: The provider accepted the request. Delivery is NOT confirmed.
STATUS_ACCEPTED: Final = "accepted"
#: The provider reports it handed the message on. Delivery is NOT confirmed.
STATUS_SENT: Final = "sent"
#: The provider confirms delivery to the handset.
STATUS_DELIVERED: Final = "delivered"
#: The provider confirms the message was read (WhatsApp only).
STATUS_READ: Final = "read"
#: The provider reports that delivery failed after accepting the message.
STATUS_FAILED: Final = "failed"

STATUSES = (
    STATUS_PENDING,
    STATUS_NOT_CONFIGURED,
    STATUS_SEND_FAILED,
    STATUS_ACCEPTED,
    STATUS_SENT,
    STATUS_DELIVERED,
    STATUS_READ,
    STATUS_FAILED,
)

#: Progress order for provider status reports. Reports can arrive out of
#: order; a lower rank never overwrites a higher one.
_RANK = {
    STATUS_PENDING: 0,
    STATUS_ACCEPTED: 1,
    STATUS_SENT: 2,
    STATUS_DELIVERED: 3,
    STATUS_READ: 4,
}
_TERMINAL_FAILURES = frozenset(
    {STATUS_FAILED, STATUS_SEND_FAILED, STATUS_NOT_CONFIGURED}
)


def delivery_confirmed(status: str) -> bool:
    return status in (STATUS_DELIVERED, STATUS_READ)


def next_status(current: str, reported: str) -> str:
    """The status after a provider report, never moving backwards.

    A failure report after a confirmed delivery is ignored; a failure report
    before it wins. Nothing moves a terminal failure.
    """
    if current in _TERMINAL_FAILURES:
        return current
    if reported == STATUS_FAILED:
        return current if delivery_confirmed(current) else STATUS_FAILED
    if reported not in _RANK:
        return current
    return reported if _RANK[reported] > _RANK.get(current, 0) else current


_E164 = re.compile(r"\+[1-9][0-9]{7,14}")


def valid_e164(number: str) -> bool:
    return bool(_E164.fullmatch(number))


def mask_number(number: str) -> str:
    """``+919876543210`` -> ``+91******3210``. Stored instead of the number."""
    if len(number) <= 7:
        return "*" * len(number)
    return number[:3] + "*" * (len(number) - 7) + number[-4:]


@dataclass(frozen=True)
class IncidentAlert:
    """What a notification says. Built only from server-generated fields."""

    incident_uid: str
    severity: str
    title: str
    reason: str
    occurred_at: datetime


@dataclass(frozen=True)
class SendResult:
    """Outcome of one provider call."""

    status: str  # STATUS_ACCEPTED or STATUS_SEND_FAILED
    provider_message_id: str | None = None
    provider_status: str | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_message: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status == STATUS_ACCEPTED


@dataclass(frozen=True)
class StatusReport:
    """A provider's report about one message (from a webhook or a poll)."""

    provider_message_id: str
    status: str
    provider_status: str
    error_code: str | None = None
    error_message: str | None = None


def clip(text: str | None, limit: int = 300) -> str | None:
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text[:limit]
