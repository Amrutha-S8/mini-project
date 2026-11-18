"""M01 — Auth & Session service.

Governs who may *operate the system*. It has no bearing on who may open the
door; that is M08's exclusive authority from Day 4 (SR-AUTH-01).

Implements registration, login with progressive lockout, refresh-token
rotation with replay detection, and logout revocation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import Settings
from app.core.errors import (
    AccountInactiveError,
    DuplicateEmailError,
    InvalidCredentialsError,
    SessionRevokedError,
    TokenReuseError,
)
from app.core.logging import get_logger
from app.models.audit_log import (
    ACTION_LOGIN_FAILURE,
    ACTION_LOGIN_SUCCESS,
    ACTION_LOGOUT,
    ACTION_TOKEN_REFRESH,
    ACTION_TOKEN_REUSE_DETECTED,
    ACTION_USER_CREATE,
    OUTCOME_FAILURE,
)
from app.models.session import (
    REVOKED_LOGOUT,
    REVOKED_REUSE,
    REVOKED_ROTATION,
    SessionRecord,
)
from app.models.user import ROLE_ADMIN, ROLE_VIEWER, User
from app.services import audit_service
from app.utils.validators import normalise_email, validate_password_policy

logger = get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _commit_then_raise(db: Session, error: Exception) -> NoReturn:
    """Persist security-relevant failure state, then raise.

    ``get_session()`` rolls the request transaction back when an exception
    leaves the endpoint. Without this commit, the very records a failed request
    must leave behind - the failed-login counter, the lockout timestamp, the
    failure audit entry and the token-reuse family revocation - would be
    discarded, so lockout would never trigger and reuse detection would never
    revoke anything (SR-AUTH-08, SR-AUTH-11, SR-AUDIT-03).
    """
    db.commit()
    raise error


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.execute(
        select(User).where(User.email == normalise_email(email))
    ).scalar_one_or_none()


def register_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str,
    role: str = ROLE_VIEWER,
    actor_user_id: int | None = None,
    actor_ip: str | None = None,
) -> User:
    """Create an operator account.

    ``actor_user_id`` is the admin who issued the account. ``None`` means the
    account was created by a system process (the ``create-admin`` CLI), which
    the audit log records as ``system`` rather than as the new user.

    Raises:
        DuplicateEmailError: if the email is already registered.
        PasswordPolicyError: if the password fails policy.
    """
    validate_password_policy(password)
    normalised = normalise_email(email)

    if get_user_by_email(db, normalised) is not None:
        raise DuplicateEmailError()

    user = User(
        email=normalised,
        password_hash=security.hash_password(password),
        full_name=full_name.strip(),
        role=role,
        is_active=True,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        # Unique index is the authoritative guard against a race between the
        # existence check above and this insert.
        db.rollback()
        raise DuplicateEmailError() from exc

    audit_service.record(
        db,
        action=ACTION_USER_CREATE,
        entity_type="user",
        entity_id=user.id,
        actor_user_id=actor_user_id,
        actor_ip=actor_ip,
        after={"email": user.email, "role": user.role},
    )
    return user


class AdminAlreadyExistsError(Exception):
    """Raised by :func:`create_first_admin` when an admin is already present."""


def create_first_admin(
    db: Session, *, email: str, password: str, full_name: str
) -> User:
    """Bootstrap the first administrator. Used only by the ``create-admin`` CLI.

    Refuses to run if any admin account exists, so the CLI cannot be used as a
    back door to mint further admins on a live system. Additional admins are
    issued through ``POST /auth/register`` by an existing admin, which is
    authenticated and audited with the issuing admin as actor.
    """
    existing = db.execute(
        select(User.id).where(User.role == ROLE_ADMIN).limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        raise AdminAlreadyExistsError(
            "an admin account already exists; create further admins through "
            "the authenticated API"
        )
    return register_user(
        db,
        email=email,
        password=password,
        full_name=full_name,
        role=ROLE_ADMIN,
        actor_user_id=None,
        actor_ip=None,
    )


def _is_locked(user: User, *, now: datetime) -> bool:
    return user.locked_until is not None and user.locked_until > now


def _register_failure(db: Session, user: User) -> None:
    """Count the failure for monitoring. Never locks the account (DD-05).

    Throttling is per (client IP, email) in app.core.rate_limit, so an
    attacker's failures cannot lock the legitimate owner out.
    """
    user.failed_login_count = (user.failed_login_count or 0) + 1
    db.flush()


def authenticate(
    db: Session,
    *,
    email: str,
    password: str,
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, str, str]:
    """Verify credentials and open a session.

    Returns ``(user, access_token, refresh_token_plaintext)``. The plaintext
    refresh token is returned to the caller once and never stored.

    Every failure - unknown email, wrong password, locked or inactive account -
    raises the same ``InvalidCredentialsError`` after the same Argon2id work,
    so neither the response nor its timing reveals account state
    (SR-AUTH-12). The real reason is recorded in the audit log.
    """
    now = _utcnow()
    user = get_user_by_email(db, email)

    if user is None:
        # Spend comparable effort on a dummy verify so a missing account is not
        # distinguishable by response time alone.
        security.verify_password(password, _DUMMY_HASH)
        audit_service.record(
            db,
            action=ACTION_LOGIN_FAILURE,
            entity_type="user",
            entity_id=None,
            actor_label="anonymous",
            actor_ip=ip_address,
            outcome=OUTCOME_FAILURE,
            after={"reason": "unknown_email"},
        )
        _commit_then_raise(db, InvalidCredentialsError())

    # Always verify first: one Argon2id check on every path for an existing
    # account, before any account-state branch.
    password_ok = security.verify_password(password, user.password_hash)

    if _is_locked(user, now=now):
        audit_service.record(
            db,
            action=ACTION_LOGIN_FAILURE,
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
            actor_ip=ip_address,
            outcome=OUTCOME_FAILURE,
            after={"reason": "account_locked"},
        )
        _commit_then_raise(db, InvalidCredentialsError())

    if not password_ok:
        _register_failure(db, user)
        audit_service.record(
            db,
            action=ACTION_LOGIN_FAILURE,
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
            actor_ip=ip_address,
            outcome=OUTCOME_FAILURE,
            after={
                "reason": "bad_password",
                "failed_login_count": user.failed_login_count,
            },
        )
        _commit_then_raise(db, InvalidCredentialsError())

    if not user.is_active:
        audit_service.record(
            db,
            action=ACTION_LOGIN_FAILURE,
            entity_type="user",
            entity_id=user.id,
            actor_user_id=user.id,
            actor_ip=ip_address,
            outcome=OUTCOME_FAILURE,
            after={"reason": "inactive"},
        )
        _commit_then_raise(db, InvalidCredentialsError())

    # Success: clear lockout state.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now

    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)

    access_token = security.create_access_token(
        subject=str(user.id), role=user.role, settings=settings
    )
    refresh_plain = _open_session(
        db,
        user=user,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
        parent_session_id=None,
    )

    audit_service.record(
        db,
        action=ACTION_LOGIN_SUCCESS,
        entity_type="user",
        entity_id=user.id,
        actor_user_id=user.id,
        actor_ip=ip_address,
    )
    db.flush()
    return user, access_token, refresh_plain


def _open_session(
    db: Session,
    *,
    user: User,
    settings: Settings,
    ip_address: str | None,
    user_agent: str | None,
    parent_session_id: int | None,
) -> str:
    """Create a session row and return the plaintext refresh token."""
    refresh_plain = security.generate_refresh_token()
    record = SessionRecord(
        user_id=user.id,
        refresh_token_hash=security.hash_refresh_token(
            refresh_plain, secret_key=settings.secret_key
        ),
        parent_session_id=parent_session_id,
        ip_address=ip_address,
        user_agent=(user_agent or None),
        issued_at=_utcnow(),
        expires_at=_utcnow() + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(record)
    db.flush()
    return refresh_plain


def _revoke_family(db: Session, root: SessionRecord, *, reason: str) -> int:
    """Revoke a session and every descendant in its rotation lineage."""
    now = _utcnow()
    revoked = 0
    frontier = [root.id]
    seen: set[int] = set()
    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        rows = db.execute(
            select(SessionRecord).where(SessionRecord.id == current)
        ).scalars()
        for row in rows:
            if row.revoked_at is None:
                row.revoked_at = now
                row.revoked_reason = reason
                revoked += 1
        children = db.execute(
            select(SessionRecord.id).where(SessionRecord.parent_session_id == current)
        ).scalars()
        frontier.extend(children)
    db.flush()
    return revoked


def refresh_tokens(
    db: Session,
    *,
    refresh_token: str,
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[User, str, str]:
    """Rotate a refresh token.

    Replay of an already-rotated token is treated as theft: the entire session
    family is revoked and the event is audited (SR-AUTH-08).
    """
    token_hash = security.hash_refresh_token(
        refresh_token, secret_key=settings.secret_key
    )
    record = db.execute(
        select(SessionRecord).where(SessionRecord.refresh_token_hash == token_hash)
    ).scalar_one_or_none()

    if record is None:
        raise SessionRevokedError()

    now = _utcnow()

    if record.revoked_at is not None:
        if record.revoked_reason != REVOKED_ROTATION:
            # Logged out, admin-revoked, or already revoked for reuse. Reusing
            # it is not evidence of theft - a stale client tab does this - so
            # it is refused without raising a false theft alarm.
            raise SessionRevokedError()

        # The token was rotated: a newer token in this lineage exists. Two
        # parties holding one lineage means the token was stolen.
        revoked = _revoke_family(db, record, reason=REVOKED_REUSE)
        audit_service.record(
            db,
            action=ACTION_TOKEN_REUSE_DETECTED,
            entity_type="session",
            entity_id=record.id,
            actor_user_id=record.user_id,
            actor_ip=ip_address,
            outcome=OUTCOME_FAILURE,
            after={"revoked_sessions": revoked},
        )
        _commit_then_raise(db, TokenReuseError())

    if record.is_expired(now=now):
        raise SessionRevokedError()

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise AccountInactiveError()

    # Rotate: mark the presented session rotated, open a child session.
    record.revoked_at = now
    record.revoked_reason = REVOKED_ROTATION

    new_refresh = _open_session(
        db,
        user=user,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
        parent_session_id=record.id,
    )
    access_token = security.create_access_token(
        subject=str(user.id), role=user.role, settings=settings
    )
    audit_service.record(
        db,
        action=ACTION_TOKEN_REFRESH,
        entity_type="session",
        entity_id=record.id,
        actor_user_id=user.id,
        actor_ip=ip_address,
    )
    db.flush()
    return user, access_token, new_refresh


def logout(
    db: Session,
    *,
    refresh_token: str,
    settings: Settings,
    actor_user_id: int | None = None,
    ip_address: str | None = None,
) -> bool:
    """Revoke the presented session server-side (SR-AUTH-10).

    Returns True when a live session was revoked. Returns False when the token
    is unknown or already revoked — logout is idempotent and must not leak
    whether the token existed.
    """
    token_hash = security.hash_refresh_token(
        refresh_token, secret_key=settings.secret_key
    )
    record = db.execute(
        select(SessionRecord).where(SessionRecord.refresh_token_hash == token_hash)
    ).scalar_one_or_none()

    if record is None or record.revoked_at is not None:
        return False

    record.revoked_at = _utcnow()
    record.revoked_reason = REVOKED_LOGOUT
    audit_service.record(
        db,
        action=ACTION_LOGOUT,
        entity_type="session",
        entity_id=record.id,
        actor_user_id=actor_user_id or record.user_id,
        actor_ip=ip_address,
    )
    db.flush()
    return True


#: Fixed Argon2id hash of a random throwaway value, used to equalise timing on
#: the unknown-email path. Generated once at import, never a real credential.
_DUMMY_HASH = security.hash_password(security.generate_refresh_token())
