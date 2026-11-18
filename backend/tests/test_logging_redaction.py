"""Tests that secrets never reach the logs (SR-AUDIT-10)."""

from __future__ import annotations

from app.core.logging import REDACTED, redact_mapping, redact_text


def test_password_in_free_text_is_redacted() -> None:
    assert "hunter2" not in redact_text("login failed password=hunter2")
    assert REDACTED in redact_text("login failed password=hunter2")


def test_token_colon_form_is_redacted() -> None:
    out = redact_text('{"access_token": "abc123def456"}')
    assert "abc123def456" not in out


def test_jwt_like_string_is_redacted() -> None:
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123"
    out = redact_text(f"bearer {jwt_like}")
    assert jwt_like not in out
    assert REDACTED in out


def test_mapping_sensitive_keys_redacted() -> None:
    payload = {
        "email": "user@example.com",
        "password": "hunter2",
        "refresh_token": "tok_abc",
        "password_hash": "$argon2id$v=19$...",
    }
    out = redact_mapping(payload)
    assert out["email"] == "user@example.com"
    assert out["password"] == REDACTED
    assert out["refresh_token"] == REDACTED
    assert out["password_hash"] == REDACTED


def test_mapping_redaction_is_recursive() -> None:
    out = redact_mapping({"outer": {"inner": {"secret": "s3cr3t"}}})
    assert out["outer"]["inner"]["secret"] == REDACTED


def test_binary_values_are_summarised_not_logged() -> None:
    """Embedding bytes must never be serialised into a log line."""
    out = redact_mapping({"embedding_blob": b"\x00" * 2048})
    assert out["embedding_blob"] == "<2048 bytes>"


def test_embedding_key_is_redacted() -> None:
    out = redact_mapping({"embedding": [0.1, 0.2, 0.3]})
    assert out["embedding"] == REDACTED


def test_non_sensitive_values_preserved() -> None:
    out = redact_mapping({"user_id": 7, "action": "login.success"})
    assert out == {"user_id": 7, "action": "login.success"}


# --- %-style argument handling (regression for defect D10) -------------------


def _capture(message: str, *args: object) -> tuple[str, str]:
    """Log through the real filter + formatter; return (output, stderr)."""
    import contextlib
    import io
    import logging

    from app.core.logging import JsonFormatter, RedactionFilter

    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    logger = logging.getLogger("tests.redaction.capture")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        logger.info(message, *args)
    return out.getvalue(), err.getvalue()


def test_secret_passed_as_percent_arg_is_redacted() -> None:
    """``logger.info("password=%s", pw)`` must not leak ``pw`` anywhere."""
    output, stderr = _capture("login failed password=%s", "hunter2-SECRET")
    assert "hunter2-SECRET" not in output
    assert "hunter2-SECRET" not in stderr, "secret leaked via logging error path"


def test_percent_args_message_is_still_emitted() -> None:
    """Redaction must not swallow the log line."""
    output, stderr = _capture("login failed for user_id=%s", 42)
    assert "user_id=42" in output
    assert stderr == ""


def test_jwt_passed_as_percent_arg_is_redacted() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123"
    output, stderr = _capture("bearer %s", token)
    assert token not in output
    assert token not in stderr
