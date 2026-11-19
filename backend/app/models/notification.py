"""``notifications`` — every homeowner notification attempt (migration 0005).

One row per channel attempt, including channels skipped because they are not
configured, so the record shows exactly what was and was not sent. The
recipient is stored masked. ``delivered``/``read`` require a provider message
id and a delivery time (CHECK), and are only set from the provider's own
status report. Rows cannot be deleted; the channel, provider, recipient and
trigger never change, and provider ids and timestamps can be set only once.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, UtcDateTime
from app.models._guards import attach_append_only_guards

STATUS_DEFAULT = "pending"


class NotificationRecord(Base):
    __tablename__ = "notifications"
    __table_args__ = (
        CheckConstraint("channel IN ('whatsapp', 'sms')", name="channel_valid"),
        CheckConstraint(
            "provider IN ('meta_whatsapp_cloud', 'twilio')", name="provider_valid"
        ),
        CheckConstraint(
            "status IN ('pending', 'not_configured', 'send_failed', 'accepted', "
            "'sent', 'delivered', 'read', 'failed')",
            name="status_valid",
        ),
        CheckConstraint(
            "trigger_reason IN ('created', 'escalated', 'fallback', 'manual')",
            name="trigger_reason_valid",
        ),
        CheckConstraint(
            "status NOT IN ('delivered', 'read') OR "
            "(provider_message_id IS NOT NULL AND delivered_at IS NOT NULL)",
            name="delivery_confirmed_by_provider",
        ),
        CheckConstraint(
            "status NOT IN ('accepted', 'sent') OR provider_message_id IS NOT NULL",
            name="accepted_has_provider_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id"), nullable=False, index=True
    )
    channel: Mapped[str] = mapped_column(String(20), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    recipient_masked: Mapped[str | None] = mapped_column(String(32), nullable=True)
    trigger_reason: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=STATUS_DEFAULT,
        server_default=STATUS_DEFAULT,
        index=True,
    )
    provider_message_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    provider_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )
    #: When the provider accepted the message (not a delivery time).
    sent_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    #: Set only from a provider delivery report.
    delivered_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    status_checked_at: Mapped[datetime | None] = mapped_column(
        UtcDateTime, nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<NotificationRecord id={self.id} status={self.status!r}>"


attach_append_only_guards(NotificationRecord.__table__)
