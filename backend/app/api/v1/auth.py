"""Authentication endpoints: register, login, refresh, logout, me."""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from app.api.deps import (
    AdminUser,
    CurrentUser,
    DbDep,
    LoginThrottleDep,
    SettingsDep,
    client_ip,
)
from app.core.errors import AuthenticationError, RateLimitedError, ValidationError
from app.core.logging import get_logger
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserPublic,
)
from app.services import auth_service
from app.utils.validators import PasswordPolicyError

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger(__name__)


def _token_pair(access: str, refresh: str, settings: SettingsDep) -> TokenPair:
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED
)
def register(
    payload: RegisterRequest,
    db: DbDep,
    admin: AdminUser,
    request: Request,
) -> UserPublic:
    """Create an operator account. Admin only (SR-AUTHZ-01, SR-AUTHZ-03).

    Self-registration is not offered: an operator account can approve HOLD
    decisions and manage household members, so accounts are issued by an
    existing admin. The first admin is created with the ``create-admin`` CLI.

    Returns 409 if the email is taken. The response never includes the hash.
    """
    try:
        user = auth_service.register_user(
            db,
            email=str(payload.email),
            password=payload.password,
            full_name=payload.full_name,
            role=payload.role,
            actor_user_id=admin.id,
            actor_ip=client_ip(request),
        )
    except PasswordPolicyError as exc:
        raise ValidationError(str(exc)) from exc
    return UserPublic.model_validate(user)


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    db: DbDep,
    settings: SettingsDep,
    throttle: LoginThrottleDep,
    request: Request,
) -> LoginResponse:
    """Exchange credentials for a token pair.

    Every credential failure returns the same 401 (SR-AUTH-12). Repeated
    failures from one client for one email, or too many attempts from one
    client, return 429 with Retry-After (SR-AUTH-13, DD-05).
    """
    ip = client_ip(request)
    email = str(payload.email)
    delay = throttle.before_login(ip, email)
    if delay is not None:
        logger.warning("login throttled", extra={"context": {"ip": ip}})
        raise RateLimitedError(delay)
    try:
        user, access, refresh = auth_service.authenticate(
            db,
            email=email,
            password=payload.password,
            settings=settings,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthenticationError:
        throttle.login_failed(ip, email)
        raise
    throttle.login_succeeded(ip, email)
    return LoginResponse(
        user=UserPublic.model_validate(user),
        tokens=_token_pair(access, refresh, settings),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(
    payload: RefreshRequest,
    db: DbDep,
    settings: SettingsDep,
    throttle: LoginThrottleDep,
    request: Request,
) -> TokenPair:
    """Rotate a refresh token.

    Replaying an already-rotated token revokes the whole session family
    (SR-AUTH-08). Rate limited per client IP (SR-AUTH-13).
    """
    delay = throttle.before_refresh(client_ip(request))
    if delay is not None:
        raise RateLimitedError(delay)
    _user, access, new_refresh = auth_service.refresh_tokens(
        db,
        refresh_token=payload.refresh_token,
        settings=settings,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _token_pair(access, new_refresh, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: RefreshRequest,
    db: DbDep,
    settings: SettingsDep,
    request: Request,
    user: CurrentUser,
) -> None:
    """Revoke the session server-side. Idempotent (SR-AUTH-10)."""
    auth_service.logout(
        db,
        refresh_token=payload.refresh_token,
        settings=settings,
        actor_user_id=user.id,
        ip_address=client_ip(request),
    )


@router.get("/me", response_model=UserPublic)
def me(user: CurrentUser) -> UserPublic:
    """Current operator. Requires a valid access token."""
    return UserPublic.model_validate(user)
