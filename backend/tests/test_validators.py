"""Tests for stdlib validation helpers (SR-AUTH-04, SR-STORE-09, SR-STORE-19)."""

from __future__ import annotations

import secrets

import pytest

from app.utils.validators import (
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    is_valid_email,
    normalise_email,
    parse_cors_origins,
    validate_password_policy,
    validate_secret_key,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("User@Example.COM", "user@example.com"),
        ("  spaced@example.com  ", "spaced@example.com"),
        ("already@lower.com", "already@lower.com"),
    ],
)
def test_normalise_email(raw: str, expected: str) -> None:
    assert normalise_email(raw) == expected


@pytest.mark.parametrize(
    "email",
    ["a@b.co", "first.last@sub.example.org", "x+tag@example.com"],
)
def test_valid_emails_accepted(email: str) -> None:
    assert is_valid_email(email) is True


@pytest.mark.parametrize(
    "email",
    ["", "no-at-sign", "@example.com", "user@", "user@host", "a b@example.com"],
)
def test_invalid_emails_rejected(email: str) -> None:
    assert is_valid_email(email) is False


def test_email_length_cap() -> None:
    assert is_valid_email("a" * 400 + "@example.com") is False


def test_password_minimum_length_enforced() -> None:
    with pytest.raises(PasswordPolicyError, match="at least"):
        validate_password_policy("a" * (MIN_PASSWORD_LENGTH - 1))


def test_password_at_minimum_length_accepted() -> None:
    validate_password_policy("Zq7" + "x" * (MIN_PASSWORD_LENGTH - 3))


def test_password_maximum_length_enforced() -> None:
    with pytest.raises(PasswordPolicyError, match="at most"):
        validate_password_policy("a" * 500)


def test_common_password_rejected() -> None:
    """Uses a denylisted value that also satisfies the length rule, so the
    'too common' branch is the one actually under test."""
    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_policy("password1234")


def test_common_password_check_is_case_insensitive() -> None:
    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_policy("PassWord1234")


def test_every_denylist_entry_is_reachable() -> None:
    """A denylist entry shorter than the minimum length could never fire."""
    from app.utils.validators import COMMON_PASSWORDS

    too_short = [p for p in COMMON_PASSWORDS if len(p) < MIN_PASSWORD_LENGTH]
    assert not too_short, f"unreachable denylist entries: {sorted(too_short)}"


# --- signing secret (DD-05) ----------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "CHANGE_ME_INSECURE_PLACEHOLDER",
        "changeme",
        "short-but-set",
        "a" * 64,
    ],
)
def test_weak_secrets_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        validate_secret_key(value)


def test_rejected_secret_never_appears_in_error() -> None:
    weak = "MyLeakableSecret"
    with pytest.raises(ValueError) as exc:
        validate_secret_key(weak)
    assert weak not in str(exc.value)


def test_generated_secret_accepted_and_stripped() -> None:
    value = secrets.token_urlsafe(48)
    assert validate_secret_key(f"  {value}\n") == value


# --- CORS origins ----------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "*",
        "http://localhost:5173/app",
        "http://localhost:5173/",
        "localhost:5173",
        "ftp://example.com",
        "http://local host",
    ],
)
def test_invalid_origins_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_cors_origins(raw, production=False)


def test_plain_http_rejected_in_production_except_localhost() -> None:
    with pytest.raises(ValueError, match="https"):
        parse_cors_origins("http://home.example", production=True)
    assert parse_cors_origins("http://localhost:5173", production=True) == [
        "http://localhost:5173"
    ]
    assert parse_cors_origins("http://127.0.0.1:5173", production=True) == [
        "http://127.0.0.1:5173"
    ]


def test_origins_trimmed_and_deduplicated() -> None:
    raw = " http://localhost:5173 ,http://localhost:5173,, https://home.example"
    assert parse_cors_origins(raw, production=False) == [
        "http://localhost:5173",
        "https://home.example",
    ]


def test_empty_origin_list_allowed() -> None:
    assert parse_cors_origins("", production=True) == []
