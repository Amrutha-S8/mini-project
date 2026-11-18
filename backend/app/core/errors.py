"""Typed domain exceptions and the public API error envelope.

Internal details — stack traces, SQL, file paths, library versions — must never
reach a client (SR-STORE-17). Every domain error maps to a stable status code
and a machine-readable ``code``.

Pure stdlib: importable without FastAPI so it can be unit-tested standalone.
"""

from __future__ import annotations

import math
from typing import Any


class DomainError(Exception):
    """Base class for expected, handled application errors."""

    status_code: int = 400
    code: str = "domain_error"
    message: str = "Request could not be processed"
    #: Extra response headers such as Retry-After. Never contains secrets.
    headers: dict[str, str] | None = None

    def __init__(
        self, message: str | None = None, *, details: dict[str, Any] | None = None
    ) -> None:
        self.message = message or self.message
        self.details = details or {}
        super().__init__(self.message)

    def to_envelope(self) -> dict[str, Any]:
        """Client-safe representation. Contains no internals."""
        envelope: dict[str, Any] = {
            "error": {"code": self.code, "message": self.message}
        }
        if self.details:
            envelope["error"]["details"] = self.details
        return envelope


# --- Authentication / authorisation -----------------------------------------


class AuthenticationError(DomainError):
    """Credentials missing, malformed, expired, or rejected."""

    status_code = 401
    code = "unauthenticated"
    message = "Authentication required"


class InvalidCredentialsError(AuthenticationError):
    """Wrong email or password.

    The message is deliberately identical whether or not the account exists, so
    the endpoint does not become a user-enumeration oracle (SR-AUTH-12).
    """

    code = "invalid_credentials"
    message = "Incorrect email or password"


class RateLimitedError(DomainError):
    """Too many attempts from one client (SR-AUTH-13).

    Identical whether or not the submitted account exists (SR-AUTH-12).
    """

    status_code = 429
    code = "rate_limited"
    message = "Too many attempts. Try again later."

    def __init__(self, retry_after_seconds: float) -> None:
        super().__init__()
        self.headers = {"Retry-After": str(max(1, math.ceil(retry_after_seconds)))}


class AccountInactiveError(AuthenticationError):
    code = "account_inactive"
    message = "Account is not active"


class SessionRevokedError(AuthenticationError):
    code = "session_revoked"
    message = "Session is no longer valid"


class TokenReuseError(AuthenticationError):
    """A rotated refresh token was replayed — treated as theft (SR-AUTH-08)."""

    code = "token_reuse_detected"
    message = "Session is no longer valid"


class AuthorizationError(DomainError):
    status_code = 403
    code = "forbidden"
    message = "You do not have permission to perform this action"


# --- Resources ---------------------------------------------------------------


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"
    message = "Resource not found"


class ConflictError(DomainError):
    status_code = 409
    code = "conflict"
    message = "Resource already exists"


class DuplicateEmailError(ConflictError):
    code = "email_already_registered"
    message = "An account with that email already exists"


class ValidationError(DomainError):
    status_code = 422
    code = "validation_error"
    message = "Request validation failed"


class ReadOnlyViolationError(DomainError):
    """A write was attempted through the read-only (AI-tier) session.

    Raising this is a security event, not a routine error (SR-AI-05/06).
    """

    status_code = 500
    code = "read_only_violation"
    message = "Write attempted on a read-only session"


def generic_envelope() -> dict[str, Any]:
    """Envelope for unexpected errors. Leaks nothing."""
    return {
        "error": {
            "code": "internal_error",
            "message": "An internal error occurred",
        }
    }
