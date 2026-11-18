"""Password hashing and JWT handling.

Uses the APPROVED primitives with no substitution:
  * Argon2id via ``argon2-cffi``  (SR-AUTH-02)
  * JWT via ``PyJWT``            (SR-AUTH-06, SR-AUTH-09)

Hand-rolled JWT is deliberately absent — the token path is delegated entirely
to PyJWT so that algorithm confusion and ``alg: none`` handling are the
library's well-tested responsibility, not ours.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

#: Argon2id parameters. Defaults from argon2-cffi are already Argon2id; these
#: values are stated explicitly so a future change is visible in review.
_TIME_COST: Final[int] = 3
_MEMORY_COST_KIB: Final[int] = 65536  # 64 MiB
_PARALLELISM: Final[int] = 2
_HASH_LEN: Final[int] = 32
_SALT_LEN: Final[int] = 16

_hasher = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST_KIB,
    parallelism=_PARALLELISM,
    hash_len=_HASH_LEN,
    salt_len=_SALT_LEN,
)

# JWT ``typ`` claim values. These are label strings, not credentials.
TOKEN_TYPE_ACCESS: Final[str] = "access"  # noqa: S105 - claim label
TOKEN_TYPE_REFRESH: Final[str] = "refresh"  # noqa: S105 - claim label


# --- Passwords ---------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Returns the encoded hash string.

    The plaintext is never logged, stored, or returned (SR-AUTH-03).
    """
    if not password:
        raise ValueError("password must not be empty")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification via argon2-cffi.

    Returns False for a mismatch or a malformed stored hash rather than
    raising, so callers cannot distinguish the two cases.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash used weaker parameters than current policy."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


# --- Refresh-token hashing ---------------------------------------------------


def generate_refresh_token() -> str:
    """Cryptographically random opaque refresh token."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str, *, secret_key: str) -> str:
    """Keyed HMAC-SHA256 of a refresh token.

    Only the hash is persisted (DATABASE_DESIGN.md section 3.5), so a stolen
    database yields no usable tokens. HMAC rather than a bare digest means an
    attacker also needs the signing secret to precompute matches.
    """
    return hmac.new(
        secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def refresh_token_matches(token: str, stored_hash: str, *, secret_key: str) -> bool:
    """Constant-time comparison of a presented token against its stored hash."""
    return hmac.compare_digest(
        hash_refresh_token(token, secret_key=secret_key), stored_hash
    )


# --- JWT ---------------------------------------------------------------------


def create_access_token(
    *,
    subject: str,
    role: str,
    settings: Settings,
    expires_delta: timedelta | None = None,
) -> str:
    """Mint a short-lived access token.

    Claims include ``sub``, ``role``, ``exp``, ``iat``, ``jti`` and ``typ``
    (SR-AUTH-09). ``typ`` prevents a refresh token being replayed as an access
    token.
    """
    now = datetime.now(UTC)
    expire = now + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "typ": TOKEN_TYPE_ACCESS,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, *, settings: Settings) -> dict[str, Any]:
    """Verify and decode an access token.

    The accepted algorithm is pinned to the configured one, which is what
    closes algorithm-confusion and ``alg: none`` attacks. Expiry is verified by
    PyJWT. Raises ``jwt.PyJWTError`` subclasses on any failure.
    """
    claims: dict[str, Any] = jwt.decode(
        token,
        settings.secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "iat", "sub"]},
    )
    if claims.get("typ") != TOKEN_TYPE_ACCESS:
        raise jwt.InvalidTokenError("not an access token")
    return claims
