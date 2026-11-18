"""Pydantic request/response models for authentication.

Validation happens at the trust boundary (SR-STORE-15). No response model ever
carries a password hash, refresh-token hash, or embedding (SR-STORE-03).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.utils.validators import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    validate_password_policy,
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )
    full_name: str = Field(min_length=1, max_length=200)
    #: Least privilege by default; an admin must ask for more explicitly.
    role: Literal["admin", "member", "viewer"] = "viewer"

    @field_validator("password")
    @classmethod
    def _check_policy(cls, value: str) -> str:
        try:
            validate_password_policy(value)
        except PasswordPolicyError as exc:
            raise ValueError(str(exc)) from exc
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=512)


class TokenPair(BaseModel):
    """Issued on login and on refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth scheme name, not a secret
    expires_in: int = Field(description="Access-token lifetime in seconds")


class UserPublic(BaseModel):
    """Client-safe user projection. Deliberately excludes password_hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class LoginResponse(BaseModel):
    user: UserPublic
    tokens: TokenPair
