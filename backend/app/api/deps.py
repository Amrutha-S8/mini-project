"""FastAPI dependencies: authentication, RBAC, request context.

Default-deny: a route without an explicit auth dependency must fail closed
(SR-AUTHZ-01). Roles are read from the server-side user record at request time,
never trusted from the token alone (SR-AUTHZ-05).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import (
    AccountInactiveError,
    AuthenticationError,
    AuthorizationError,
    SessionRevokedError,
)
from app.core.rate_limit import LoginThrottle
from app.core.security import decode_access_token
from app.core.tasks import TaskRunner
from app.database.session import get_readonly_session, get_session
from app.models.user import ROLE_ADMIN, ROLE_MEMBER, ROLE_VIEWER, User
from app.notifications.transport import HttpTransport
from app.services import auth_service

#: ``auto_error=False`` so a missing header raises our own 401 envelope rather
#: than FastAPI's default shape.
_bearer = HTTPBearer(auto_error=False)


def get_app_settings(request: Request) -> Settings:
    """The settings this application instance was created with.

    Reading ``request.app.state.settings`` rather than the process-wide cached
    ``get_settings()`` means ``create_app(settings)`` is honoured by request
    handling too. Otherwise a token could be signed with one secret and the
    database opened from another configuration.
    """
    settings: Settings = request.app.state.settings
    return settings


SettingsDep = Annotated[Settings, Depends(get_app_settings)]


def get_login_throttle(request: Request) -> LoginThrottle:
    """The throttle created with this application instance (fresh per app)."""
    throttle: LoginThrottle = request.app.state.login_throttle
    return throttle


LoginThrottleDep = Annotated[LoginThrottle, Depends(get_login_throttle)]


@dataclass(frozen=True)
class Notifier:
    """Schedules homeowner notifications without blocking the request."""

    settings: Settings
    runner: TaskRunner
    transport: HttpTransport | None

    def incident(self, incident_id: int, trigger_reason: str) -> None:
        from app.services import notification_service

        self.runner.submit(
            notification_service.notify_in_background,
            incident_id,
            trigger_reason,
            self.settings,
            self.transport,
        )


def get_notifier(request: Request) -> Notifier:
    return Notifier(
        settings=request.app.state.settings,
        runner=request.app.state.task_runner,
        transport=request.app.state.notification_transport,
    )


NotifierDep = Annotated[Notifier, Depends(get_notifier)]
DbDep = Annotated[Session, Depends(get_session)]
ReadOnlyDbDep = Annotated[Session, Depends(get_readonly_session)]


def client_ip(request: Request) -> str | None:
    """Best-effort client IP for audit records."""
    if request.client is not None:
        return request.client.host
    return None


def get_current_user(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer)
    ] = None,
) -> User:
    """Resolve the authenticated operator, or raise 401.

    Any token problem — missing, malformed, wrong algorithm, expired, wrong
    type, no session claim, revoked or expired session — resolves to an
    ``AuthenticationError``. No branch returns a user on uncertainty.

    The session id is stored on ``request.state.session_id`` so logout can
    revoke the session this very token belongs to.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError()

    try:
        claims = decode_access_token(credentials.credentials, settings=settings)
    except jwt.PyJWTError as exc:
        raise AuthenticationError() from exc

    try:
        user_id = int(claims["sub"])
        session_id = int(claims["sid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError() from exc

    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationError()
    if not user.is_active:
        raise AccountInactiveError()
    # Finding S2: the token is only as alive as its server-side session.
    if not auth_service.access_session_is_live(
        db, session_id=session_id, user_id=user.id
    ):
        raise SessionRevokedError()
    request.state.session_id = session_id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(*allowed_roles: str):
    """Dependency factory enforcing role membership (SR-AUTHZ-02)."""

    def _guard(user: CurrentUser) -> User:
        if user.role not in allowed_roles:
            raise AuthorizationError()
        return user

    return _guard


require_admin = require_role(ROLE_ADMIN)
AdminUser = Annotated[User, Depends(require_admin)]

#: Roles allowed to read household-wide summaries (incidents, security
#: events) without individual member identities (owner decisions R-1, D-3).
HOUSEHOLD_READERS = (ROLE_ADMIN, ROLE_VIEWER)
ALL_ROLES = (ROLE_ADMIN, ROLE_VIEWER, ROLE_MEMBER)


def ensure_role(user: User, *allowed_roles: str) -> None:
    """Raise 403 unless ``user.role`` is one of ``allowed_roles``.

    For routes that take ``CurrentUser`` because several roles may call them
    but each role sees different data. The role always comes from the
    database row loaded in ``get_current_user``, never from the token.
    """
    if user.role not in allowed_roles:
        raise AuthorizationError()


def current_session_id(request: Request) -> int | None:
    """Session id of the access token that authenticated this request."""
    value = getattr(request.state, "session_id", None)
    return value if isinstance(value, int) else None
