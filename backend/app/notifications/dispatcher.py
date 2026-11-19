"""Channel order and fallback: WhatsApp first, SMS when WhatsApp cannot send.

``dispatch`` tries each channel in order and stops at the first provider that
*accepts* the message. A channel without a complete configuration is
recorded as ``not_configured`` and skipped; nothing is pretended. If every
channel fails or is unconfigured, the attempts say so and nobody is told the
homeowner was notified.

A message accepted by WhatsApp but later reported ``failed`` by its webhook
is handed to SMS by the service (``fallback_channels``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.notifications.sms import TwilioConfig, TwilioSmsClient
from app.notifications.transport import HttpTransport
from app.notifications.types import (
    CHANNEL_SMS,
    CHANNEL_WHATSAPP,
    PROVIDER_TWILIO,
    PROVIDER_WHATSAPP,
    STATUS_NOT_CONFIGURED,
    STATUS_SEND_FAILED,
    IncidentAlert,
    SendResult,
    mask_number,
)
from app.notifications.whatsapp import WhatsAppCloudClient, WhatsAppConfig


class Sender(Protocol):
    def send(self, alert: IncidentAlert) -> SendResult: ...


@dataclass(frozen=True)
class ChannelSetup:
    channel: str
    provider: str
    recipient_masked: str | None
    #: Empty when the channel can be used.
    problems: tuple[str, ...]
    sender: Sender | None

    @property
    def usable(self) -> bool:
        return not self.problems and self.sender is not None


@dataclass(frozen=True)
class NotificationSettings:
    """Plain values copied from application settings. Secrets never logged."""

    whatsapp_enabled: bool
    whatsapp_access_token: str
    whatsapp_phone_number_id: str
    whatsapp_api_version: str
    whatsapp_template_name: str | None
    whatsapp_template_language: str
    whatsapp_recipient: str
    sms_enabled: bool
    twilio_account_sid: str
    twilio_auth_token: str
    twilio_from_number: str
    sms_recipient: str
    twilio_status_callback_url: str | None = None

    def __repr__(self) -> str:  # never print tokens
        return (
            f"NotificationSettings(whatsapp_enabled={self.whatsapp_enabled}, "
            f"sms_enabled={self.sms_enabled})"
        )


class AttemptRecorder(Protocol):
    def skipped(self, setup: ChannelSetup, reason: str) -> None: ...

    def started(self, setup: ChannelSetup) -> object: ...

    def finished(self, handle: object, result: SendResult) -> None: ...


def build_setups(
    settings: NotificationSettings, transport: HttpTransport
) -> list[ChannelSetup]:
    """WhatsApp then SMS, each with the reasons it cannot be used (if any)."""
    setups = []

    wa = WhatsAppConfig(
        access_token=settings.whatsapp_access_token,
        phone_number_id=settings.whatsapp_phone_number_id,
        recipient=settings.whatsapp_recipient,
        api_version=settings.whatsapp_api_version,
        template_name=settings.whatsapp_template_name or None,
        template_language=settings.whatsapp_template_language or "en",
    )
    wa_problems = (
        ["WHATSAPP_ENABLED is not true"] if not settings.whatsapp_enabled else []
    ) + wa.problems()
    setups.append(
        ChannelSetup(
            channel=CHANNEL_WHATSAPP,
            provider=PROVIDER_WHATSAPP,
            recipient_masked=mask_number(wa.recipient) if wa.recipient else None,
            problems=tuple(wa_problems),
            sender=None if wa_problems else WhatsAppCloudClient(wa, transport),
        )
    )

    tw = TwilioConfig(
        account_sid=settings.twilio_account_sid,
        auth_token=settings.twilio_auth_token,
        from_number=settings.twilio_from_number,
        recipient=settings.sms_recipient,
        status_callback_url=settings.twilio_status_callback_url or None,
    )
    sms_problems = (
        ["SMS_ENABLED is not true"] if not settings.sms_enabled else []
    ) + tw.problems()
    setups.append(
        ChannelSetup(
            channel=CHANNEL_SMS,
            provider=PROVIDER_TWILIO,
            recipient_masked=mask_number(tw.recipient) if tw.recipient else None,
            problems=tuple(sms_problems),
            sender=None if sms_problems else TwilioSmsClient(tw, transport),
        )
    )
    return setups


@dataclass(frozen=True)
class AttemptOutcome:
    channel: str
    status: str
    result: SendResult | None


def dispatch(
    alert: IncidentAlert,
    setups: Sequence[ChannelSetup],
    recorder: AttemptRecorder,
) -> list[AttemptOutcome]:
    """Try channels in order until one provider accepts. Records every attempt."""
    outcomes: list[AttemptOutcome] = []
    for setup in setups:
        if not setup.usable:
            reason = "; ".join(setup.problems) or "not configured"
            recorder.skipped(setup, reason)
            outcomes.append(AttemptOutcome(setup.channel, STATUS_NOT_CONFIGURED, None))
            continue
        handle = recorder.started(setup)
        assert setup.sender is not None
        try:
            result = setup.sender.send(alert)
        except Exception as exc:  # noqa: BLE001 - a bug must not stop the fallback
            result = SendResult(
                STATUS_SEND_FAILED,
                error_code="internal_error",
                error_message=type(exc).__name__,
            )
        recorder.finished(handle, result)
        outcomes.append(AttemptOutcome(setup.channel, result.status, result))
        if result.accepted:
            break
    return outcomes


def fallback_channels(
    setups: Sequence[ChannelSetup], failed: str
) -> list[ChannelSetup]:
    """Channels after ``failed`` in the configured order."""
    names = [s.channel for s in setups]
    if failed not in names:
        return []
    return list(setups[names.index(failed) + 1 :])


def summarise(outcomes: Sequence[AttemptOutcome]) -> str:
    """Plain words for logs and the API. Never claims delivery."""
    accepted = [
        o.channel for o in outcomes if o.result is not None and o.result.accepted
    ]
    if accepted:
        return f"accepted by the {accepted[0]} provider; delivery not yet confirmed"
    if all(o.status == STATUS_NOT_CONFIGURED for o in outcomes):
        return "no notification channel is configured; nothing was sent"
    return "every configured channel failed; nothing was sent"
