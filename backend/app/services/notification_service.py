"""Homeowner notifications for incidents, with persisted attempts (M20).

Every attempt is a ``notifications`` row written *before* the provider is
called and updated with the provider's answer, so a crash leaves a visible
``pending`` row rather than nothing. Channels without configuration are
recorded as ``not_configured``. Delivery is set only from provider reports:

* WhatsApp: the signed status webhook (``sent``/``delivered``/``read``/
  ``failed``). A ``failed`` report after acceptance triggers the SMS fallback.
* SMS: the signed Twilio status callback, or ``refresh_status`` which asks
  Twilio for the message's current status.

Message content is built from server-generated incident fields only: no
member names, contact details, images or embeddings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import utc_now
from app.core.config import Settings
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.database.session import new_writer_session
from app.models.incident import IncidentRecord
from app.models.incident_detection import IncidentDetection
from app.models.notification import NotificationRecord
from app.notifications.dispatcher import (
    AttemptOutcome,
    ChannelSetup,
    NotificationSettings,
    build_setups,
    dispatch,
    fallback_channels,
    summarise,
)
from app.notifications.sms import TwilioConfig, TwilioSmsClient
from app.notifications.transport import HttpTransport, UrllibTransport
from app.notifications.types import (
    CHANNEL_SMS,
    CHANNEL_WHATSAPP,
    PROVIDER_TWILIO,
    STATUS_ACCEPTED,
    STATUS_DELIVERED,
    STATUS_FAILED,
    STATUS_NOT_CONFIGURED,
    STATUS_PENDING,
    STATUS_READ,
    STATUS_SENT,
    IncidentAlert,
    SendResult,
    StatusReport,
    clip,
    next_status,
)

logger = get_logger(__name__)

TRIGGER_MANUAL = "manual"
TRIGGER_FALLBACK = "fallback"
_ACTIVE = ("open", "investigating")
#: Statuses meaning a provider took the message (for the cooldown).
_TAKEN = (STATUS_ACCEPTED, STATUS_SENT, STATUS_DELIVERED, STATUS_READ)


def notification_settings(settings: Settings) -> NotificationSettings:
    return NotificationSettings(
        whatsapp_enabled=settings.whatsapp_enabled,
        whatsapp_access_token=settings.whatsapp_access_token,
        whatsapp_phone_number_id=settings.whatsapp_phone_number_id.strip(),
        whatsapp_api_version=settings.whatsapp_api_version.strip(),
        whatsapp_template_name=settings.whatsapp_template_name.strip() or None,
        whatsapp_template_language=settings.whatsapp_template_language.strip(),
        whatsapp_recipient=settings.homeowner_whatsapp_number.strip(),
        sms_enabled=settings.sms_enabled,
        twilio_account_sid=settings.twilio_account_sid.strip(),
        twilio_auth_token=settings.twilio_auth_token,
        twilio_from_number=settings.twilio_from_number.strip(),
        sms_recipient=(
            settings.homeowner_sms_number.strip()
            or settings.homeowner_whatsapp_number.strip()
        ),
        twilio_status_callback_url=settings.twilio_status_callback_url.strip() or None,
    )


def default_transport(settings: Settings) -> HttpTransport:
    return UrllibTransport(timeout_seconds=settings.notification_timeout_seconds)


def channel_overview(settings: Settings) -> list[dict[str, Any]]:
    """Which channels can send, and why not. Never includes secret values."""
    setups = build_setups(notification_settings(settings), default_transport(settings))
    return [
        {
            "channel": s.channel,
            "provider": s.provider,
            "configured": s.usable,
            "recipient_masked": s.recipient_masked,
            "problems": list(s.problems),
            "delivery_confirmation": (
                "signed webhook POST /api/v1/notifications/webhooks/whatsapp"
                if s.channel == CHANNEL_WHATSAPP
                else "Twilio status callback or POST /notifications/{id}/refresh"
            ),
        }
        for s in setups
    ]


# --- recording attempts ---------------------------------------------------------------


class _DbRecorder:
    """Writes one ``notifications`` row per attempt and commits each step."""

    def __init__(self, db: Session, incident_id: int, trigger: str) -> None:
        self._db = db
        self._incident_id = incident_id
        self._trigger = trigger
        self.rows: list[NotificationRecord] = []

    def _new(self, setup: ChannelSetup, status: str) -> NotificationRecord:
        row = NotificationRecord(
            incident_id=self._incident_id,
            channel=setup.channel,
            provider=setup.provider,
            recipient_masked=setup.recipient_masked,
            trigger_reason=self._trigger,
            status=status,
        )
        self._db.add(row)
        self.rows.append(row)
        return row

    def skipped(self, setup: ChannelSetup, reason: str) -> None:
        row = self._new(setup, STATUS_NOT_CONFIGURED)
        row.error_code = "not_configured"
        row.error_message = clip(reason)
        self._db.commit()

    def started(self, setup: ChannelSetup) -> object:
        row = self._new(setup, STATUS_PENDING)
        self._db.commit()  # visible even if the provider call never returns
        return row

    def finished(self, handle: object, result: SendResult) -> None:
        assert isinstance(handle, NotificationRecord)
        now = utc_now()
        handle.status = result.status
        handle.provider_message_id = result.provider_message_id
        handle.provider_status = result.provider_status
        handle.http_status = result.http_status
        handle.error_code = clip(result.error_code, 64)
        handle.error_message = clip(result.error_message)
        if result.accepted:
            handle.sent_at = now
        else:
            handle.failed_at = now
        self._db.commit()


def _alert(db: Session, incident: IncidentRecord) -> IncidentAlert:
    reason = db.execute(
        select(IncidentDetection.reason)
        .where(IncidentDetection.incident_id == incident.id)
        .order_by(IncidentDetection.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return IncidentAlert(
        incident_uid=incident.incident_uid,
        severity=incident.severity,
        title=incident.title,
        reason=reason or incident.title,
        occurred_at=incident.last_event_at or incident.opened_at,
    )


@dataclass(frozen=True)
class NotifyOutcome:
    attempted: bool
    summary: str
    notification_ids: tuple[int, ...]


def _recently_notified(db: Session, incident_id: int, *, since: datetime) -> bool:
    return (
        db.execute(
            select(NotificationRecord.id)
            .where(NotificationRecord.incident_id == incident_id)
            .where(NotificationRecord.status.in_(_TAKEN))
            .where(NotificationRecord.created_at >= since)
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )


def notify_incident(
    db: Session,
    incident_id: int,
    *,
    trigger_reason: str,
    settings: Settings,
    transport: HttpTransport | None = None,
    now: datetime | None = None,
) -> NotifyOutcome:
    """Notify the homeowner about one incident, with WhatsApp -> SMS fallback.

    Automatic triggers skip closed or acknowledged incidents and respect the
    cooldown. A manual trigger (an admin pressing "notify") always tries.
    """
    now = now or utc_now()
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise NotFoundError("Incident not found")
    if trigger_reason != TRIGGER_MANUAL:
        if incident.status not in _ACTIVE or incident.acknowledged_at is not None:
            return NotifyOutcome(False, "incident closed or acknowledged; skipped", ())
        cooldown = timedelta(minutes=settings.notification_cooldown_minutes)
        if _recently_notified(db, incident.id, since=now - cooldown):
            return NotifyOutcome(False, "notified recently; cooldown active", ())

    setups = build_setups(
        notification_settings(settings), transport or default_transport(settings)
    )
    recorder = _DbRecorder(db, incident.id, trigger_reason)
    outcomes: list[AttemptOutcome] = dispatch(_alert(db, incident), setups, recorder)
    return NotifyOutcome(
        attempted=True,
        summary=summarise(outcomes),
        notification_ids=tuple(r.id for r in recorder.rows),
    )


def notify_in_background(
    incident_id: int,
    trigger_reason: str,
    settings: Settings,
    transport: HttpTransport | None,
) -> None:
    """Job body for the task runner: own session, own commit."""
    db = new_writer_session()
    try:
        outcome = notify_incident(
            db,
            incident_id,
            trigger_reason=trigger_reason,
            settings=settings,
            transport=transport,
        )
        db.commit()
        logger.info(
            "incident notification",
            extra={"context": {"incident_id": incident_id, "result": outcome.summary}},
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --- provider status reports ----------------------------------------------------------


def apply_status_report(
    db: Session, provider: str, report: StatusReport, *, now: datetime | None = None
) -> tuple[NotificationRecord | None, bool]:
    """Apply one provider report. Returns (row, newly_failed)."""
    now = now or utc_now()
    row = db.execute(
        select(NotificationRecord)
        .where(NotificationRecord.provider == provider)
        .where(NotificationRecord.provider_message_id == report.provider_message_id)
    ).scalar_one_or_none()
    if row is None:
        return None, False
    before = row.status
    after = next_status(before, report.status)
    row.status_checked_at = now
    if after == before:
        db.flush()
        return row, False
    row.status = after
    row.provider_status = clip(report.provider_status, 32)
    if after in (STATUS_DELIVERED, STATUS_READ) and row.delivered_at is None:
        row.delivered_at = now
    if after == STATUS_FAILED:
        if row.failed_at is None:
            row.failed_at = now
        row.error_code = clip(report.error_code, 64)
        row.error_message = clip(report.error_message)
    db.flush()
    return row, after == STATUS_FAILED


def _fallback_after_failure(
    db: Session,
    row: NotificationRecord,
    *,
    settings: Settings,
    transport: HttpTransport | None,
) -> None:
    """A WhatsApp message failed after acceptance: try the next channel once."""
    if row.channel != CHANNEL_WHATSAPP:
        return
    already = db.execute(
        select(NotificationRecord.id)
        .where(NotificationRecord.incident_id == row.incident_id)
        .where(NotificationRecord.channel == CHANNEL_SMS)
        .where(NotificationRecord.trigger_reason == TRIGGER_FALLBACK)
        .limit(1)
    ).scalar_one_or_none()
    if already is not None:
        return
    incident = db.get(IncidentRecord, row.incident_id)
    if incident is None:
        return
    setups = build_setups(
        notification_settings(settings), transport or default_transport(settings)
    )
    rest = fallback_channels(setups, CHANNEL_WHATSAPP)
    recorder = _DbRecorder(db, incident.id, TRIGGER_FALLBACK)
    dispatch(_alert(db, incident), rest, recorder)


def handle_status_reports(
    db: Session,
    provider: str,
    reports: list[StatusReport],
    *,
    settings: Settings,
    transport: HttpTransport | None = None,
) -> int:
    """Apply verified webhook reports; run the SMS fallback for WhatsApp failures."""
    applied = 0
    for report in reports:
        row, newly_failed = apply_status_report(db, provider, report)
        if row is None:
            continue
        applied += 1
        db.commit()
        if newly_failed:
            _fallback_after_failure(db, row, settings=settings, transport=transport)
    return applied


def refresh_status(
    db: Session,
    notification_id: int,
    *,
    settings: Settings,
    transport: HttpTransport | None = None,
) -> NotificationRecord:
    """Ask Twilio for the status of one SMS. WhatsApp has no status API."""
    row = db.get(NotificationRecord, notification_id)
    if row is None:
        raise NotFoundError("Notification not found")
    if row.provider != PROVIDER_TWILIO or not row.provider_message_id:
        raise ValidationError(
            "only accepted SMS messages can be refreshed; WhatsApp status "
            "arrives through its webhook"
        )
    ns = notification_settings(settings)
    config = TwilioConfig(
        account_sid=ns.twilio_account_sid,
        auth_token=ns.twilio_auth_token,
        from_number=ns.twilio_from_number,
        recipient=ns.sms_recipient,
    )
    if config.problems():
        raise ValidationError("SMS is not configured: " + "; ".join(config.problems()))
    client = TwilioSmsClient(config, transport or default_transport(settings))
    report = client.fetch_status(row.provider_message_id)
    if report is None:
        row.status_checked_at = utc_now()
        db.flush()
        return row
    updated, _failed = apply_status_report(db, PROVIDER_TWILIO, report)
    return updated or row


def list_for_incident(db: Session, incident_id: int) -> list[NotificationRecord]:
    return list(
        db.execute(
            select(NotificationRecord)
            .where(NotificationRecord.incident_id == incident_id)
            .order_by(NotificationRecord.id)
        ).scalars()
    )


def list_recent(db: Session, *, limit: int = 50) -> list[NotificationRecord]:
    return list(
        db.execute(
            select(NotificationRecord)
            .order_by(NotificationRecord.id.desc())
            .limit(max(1, min(limit, 200)))
        ).scalars()
    )
