"""Notification records, channel configuration and provider status webhooks.

The webhook routes are the only public routes here. They accept nothing
unless the provider's signature verifies with a secret from ``.env``:
WhatsApp's ``X-Hub-Signature-256`` (app secret) and Twilio's
``X-Twilio-Signature`` (auth token, over the configured callback URL). An
unconfigured secret means every call is refused. They only update delivery
status; they cannot read data, change incidents or touch the door.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.deps import AdminUser, DbDep, SettingsDep
from app.api.v1.incidents import notification_public
from app.notifications import sms, whatsapp
from app.notifications.types import PROVIDER_TWILIO, PROVIDER_WHATSAPP
from app.schemas.events import ChannelStatus, NotificationPublic
from app.services import notification_service

router = APIRouter(prefix="/notifications", tags=["notifications"])

_MAX_WEBHOOK_BYTES = 256 * 1024


async def raw_body(request: Request) -> bytes:
    body = await request.body()
    return body[: _MAX_WEBHOOK_BYTES + 1]


RawBody = Annotated[bytes, Depends(raw_body)]


def _refused() -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"error": {"code": "forbidden", "message": "Forbidden"}},
    )


@router.get("", response_model=list[NotificationPublic])
def list_notifications(
    db: DbDep,
    admin: AdminUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[NotificationPublic]:
    """Recent notification attempts, newest first. Admin only."""
    return [
        notification_public(r)
        for r in notification_service.list_recent(db, limit=limit)
    ]


@router.get("/channels", response_model=list[ChannelStatus])
def channel_status(admin: AdminUser, settings: SettingsDep) -> list[ChannelStatus]:
    """Whether WhatsApp and SMS can send, and which settings are missing.

    Lists setting names only; no token, secret or full number is returned.
    """
    return [ChannelStatus(**c) for c in notification_service.channel_overview(settings)]


@router.post("/{notification_id}/refresh", response_model=NotificationPublic)
def refresh_notification(
    notification_id: int,
    db: DbDep,
    admin: AdminUser,
    request: Request,
    settings: SettingsDep,
) -> NotificationPublic:
    """Ask Twilio for an SMS's current status (works without a public URL)."""
    row = notification_service.refresh_status(
        db,
        notification_id,
        settings=settings,
        transport=request.app.state.notification_transport,
    )
    return notification_public(row)


@router.get("/webhooks/whatsapp")
def whatsapp_subscribe(
    settings: SettingsDep,
    mode: Annotated[str | None, Query(alias="hub.mode")] = None,
    token: Annotated[str | None, Query(alias="hub.verify_token")] = None,
    challenge: Annotated[str | None, Query(alias="hub.challenge")] = None,
) -> Response:
    """Meta's webhook setup handshake (verify token from ``.env``)."""
    echoed = whatsapp.verify_subscription(
        settings.whatsapp_webhook_verify_token, mode, token, challenge
    )
    if echoed is None:
        return _refused()
    return PlainTextResponse(echoed)


@router.post("/webhooks/whatsapp")
def whatsapp_status(
    db: DbDep,
    settings: SettingsDep,
    request: Request,
    body: RawBody,
) -> Response:
    """Delivery status from WhatsApp. Signature-verified; else 403."""
    if len(body) > _MAX_WEBHOOK_BYTES or not whatsapp.verify_signature(
        settings.whatsapp_app_secret,
        body,
        request.headers.get("x-hub-signature-256"),
    ):
        return _refused()
    try:
        payload = json.loads(body)
    except ValueError:
        return JSONResponse(status_code=400, content={"processed": 0})
    applied = notification_service.handle_status_reports(
        db,
        PROVIDER_WHATSAPP,
        whatsapp.parse_status_webhook(payload),
        settings=settings,
        transport=request.app.state.notification_transport,
    )
    return JSONResponse({"processed": applied})


@router.post("/webhooks/twilio")
def twilio_status(
    db: DbDep,
    settings: SettingsDep,
    request: Request,
    body: RawBody,
) -> Response:
    """Twilio status callback. Signature checked against the configured URL."""
    if len(body) > _MAX_WEBHOOK_BYTES:
        return _refused()
    params = dict(
        urllib.parse.parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
    )
    callback_url = settings.twilio_status_callback_url.strip()
    if not callback_url or not sms.verify_twilio_signature(
        settings.twilio_auth_token,
        callback_url,
        params,
        request.headers.get("x-twilio-signature"),
    ):
        return _refused()
    report = sms.parse_status_callback(params)
    applied = notification_service.handle_status_reports(
        db,
        PROVIDER_TWILIO,
        [report] if report else [],
        settings=settings,
        transport=request.app.state.notification_transport,
    )
    return JSONResponse({"processed": applied})
