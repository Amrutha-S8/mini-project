"""Reusable validation helpers.

Pure stdlib so they are testable without Pydantic installed.
"""

from __future__ import annotations

import re

#: SR-AUTH-04: length and uniqueness matter more than composition rules.
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

#: Small denylist. A production deployment should check a larger corpus.
#:
#: Every entry is at least ``MIN_PASSWORD_LENGTH`` characters on purpose. The
#: length check runs first, so a shorter entry could never be reached and would
#: be dead configuration that quietly misleads whoever reads this list.
COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "qwertyuiop12",
        "letmein12345",
        "administrator",
        "changeme1234",
        "smarthome123",
        "password1234",
        "passwordpassword",
        "securepassword",
        "smarthomesecurity",
    }
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")


class PasswordPolicyError(ValueError):
    """Raised when a candidate password fails policy."""


def normalise_email(email: str) -> str:
    """Trim and lowercase. Email comparison must be case-insensitive."""
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    """Structural check only.

    ``email-validator`` via Pydantic's ``EmailStr`` is the authoritative check
    at the API boundary; this helper exists for service-layer guards and tests.
    """
    candidate = email.strip()
    if not candidate or len(candidate) > 320:
        return False
    return bool(_EMAIL_RE.match(candidate))


def validate_password_policy(password: str) -> None:
    """Enforce SR-AUTH-04. Raises ``PasswordPolicyError`` on failure."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters"
        )
    if password.strip().lower() in COMMON_PASSWORDS:
        raise PasswordPolicyError("Password is too common")


# --- Signing secret (SR-AUTH-06, SR-STORE-09, DD-05) -------------------------

#: Values that must never be used, in any environment.
PLACEHOLDER_SECRETS = frozenset(
    {"CHANGE_ME_INSECURE_PLACEHOLDER", "changeme", "secret"}  # noqa: S105
)
MIN_SECRET_LENGTH = 32
MIN_SECRET_DISTINCT_CHARS = 10
GENERATE_SECRET_HINT = 'python -c "import secrets; print(secrets.token_urlsafe(48))"'  # noqa: S105 - shell command, not a secret


def validate_secret_key(value: str) -> str:
    """Return the stripped secret, or raise ValueError.

    Error messages never include the value itself.
    """
    candidate = value.strip()
    if not candidate or candidate in PLACEHOLDER_SECRETS:
        raise ValueError(
            f"SECRET_KEY is not set. Generate one with: {GENERATE_SECRET_HINT}"
        )
    if len(candidate) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters. "
            f"Generate one with: {GENERATE_SECRET_HINT}"
        )
    if len(set(candidate)) < MIN_SECRET_DISTINCT_CHARS:
        raise ValueError("SECRET_KEY has too little variety; generate a random one")
    return candidate


# --- CORS origins (SR-STORE-19) ---------------------------------------------

_ORIGIN = re.compile(r"(https?)://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:\d{1,5})?")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})


def parse_cors_origins(raw: str, *, production: bool) -> list[str]:
    """Comma-separated origins -> validated, de-duplicated list.

    Rejects '*', paths, trailing slashes and, in production, plain http to
    anything except localhost.
    """
    origins: list[str] = []
    for part in raw.split(","):
        origin = part.strip()
        if not origin:
            continue
        if origin == "*":
            raise ValueError("CORS_ALLOWED_ORIGINS must not contain '*'")
        match = _ORIGIN.fullmatch(origin)
        if match is None:
            raise ValueError(
                f"invalid CORS origin {origin!r}: use scheme://host[:port]"
            )
        if (
            production
            and match.group(1) == "http"
            and match.group(2) not in _LOCAL_HOSTS
        ):
            raise ValueError(f"CORS origin {origin!r} must use https in production")
        if origin not in origins:
            origins.append(origin)
    return origins
