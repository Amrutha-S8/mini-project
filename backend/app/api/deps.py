"""FastAPI dependencies: authentication, RBAC, request context.

Default-deny: a route without an explicit auth dependency must fail closed
(SR-AUTHZ-01). Roles are read from the server-side user record at request time,
never trusted from the token alone (SR-AUTHZ-05).
"""

from __future__ import annotations

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
)
from app.core.rate_limit import LoginThrottle
from app.core.security import decode_access_token
from app.database.session import get_readonly_session, get_session
from app.models.user import ROLE_ADMIN, User

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
DbDep = Annotated[Session, Depends(get_session)]
ReadOnlyDbDep = Annotated[Session, Depends(get_readonly_session)]


def client_ip(request: Request) -> str | None:
    """Best-effort client IP for audit records."""
    if request.client is not None:
        return request.client.host
    return None


def get_current_user(
    db: DbDep,
    settings: SettingsDep,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer)
    ] = None,
) -> User:
    """Resolve the authenticated operator, or raise 401.

    Any token problem — missing, malformed, wrong algorithm, expired, wrong
    type — resolves to ``AuthenticationError``. No branch returns a user on
    uncertainty.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError()

    try:
        claims = decode_access_token(credentials.credentials, settings=settings)
    except jwt.PyJWTError as exc:
        raise AuthenticationError() from exc

    subject = claims.get("sub")
    if subject is None:
        raise AuthenticationError()

    try:
        user_id = int(subject)
    except (TypeError, ValueError) as exc:
        raise AuthenticationError() from exc

    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationError()
    if not user.is_active:
        raise AccountInactiveError()
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
