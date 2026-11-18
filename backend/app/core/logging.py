"""Structured JSON logging with secret redaction.

Logs must never contain passwords, tokens, refresh-token values, API keys or
embedding vectors (SR-AUDIT-10). Redaction is applied by a filter so that an
accidental ``logger.info(f"... {password}")`` is still scrubbed before output.

Pure stdlib — no third-party dependency.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

#: Keys whose values are replaced wholesale in structured ``extra`` payloads.
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "password_hash",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "refresh_token",
        "refresh_token_hash",
        "authorization",
        "api_key",
        "embedding",
    }
)

REDACTED = "***REDACTED***"

#: Catches ``password=hunter2`` and the JSON form ``"access_token": "ey..."``.
#: The optional quote after the key name matters: in JSON a closing quote sits
#: between the key and the colon, and an earlier version of this pattern missed
#: that case entirely, letting JSON-formatted tokens through to the log.
_INLINE_SECRET = re.compile(
    r"(?i)\b("
    + "|".join(sorted(SENSITIVE_KEYS, key=len, reverse=True))
    + r")\b[\"']?\s*[=:]\s*[\"']?([^\s\"',}]+)[\"']?"
)

#: Catches bare JWT-looking strings.
_JWT_LIKE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+")


def redact_text(text: str) -> str:
    """Scrub secret-looking substrings from a free-text message."""
    scrubbed = _INLINE_SECRET.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return _JWT_LIKE.sub(REDACTED, scrubbed)


def redact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive keys in a structured payload."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            clean[key] = REDACTED
        elif isinstance(value, dict):
            clean[key] = redact_mapping(value)
        elif isinstance(value, (bytes, bytearray)):
            clean[key] = f"<{len(value)} bytes>"
        elif isinstance(value, str):
            clean[key] = redact_text(value)
        else:
            clean[key] = value
    return clean


class RedactionFilter(logging.Filter):
    """Applies redaction to every record before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Merge %-style args into the message BEFORE redacting. Redacting
        # ``record.msg`` alone is unsafe: "password=%s" becomes
        # "password=***REDACTED***", the later ``msg % args`` then raises, and
        # logging's error handler prints the raw args - the secret - to stderr.
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = redact_text(message)
        record.args = None
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            # ``context`` is an ad-hoc attribute supplied via logger(extra=...),
            # so it is set dynamically rather than declared on LogRecord.
            record.context = redact_mapping(context)  # type: ignore[attr-defined]
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        correlation_id = getattr(record, "correlation_id", None)
        if correlation_id:
            payload["correlation_id"] = correlation_id
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            payload["context"] = context
        exc_type = record.exc_info[0] if record.exc_info else None
        if exc_type is not None:
            # Type name only. The traceback is never serialised into a log line
            # that may be shipped off-host.
            payload["exception"] = exc_type.__name__
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON handler and redaction filter on the root logger."""
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.strip().upper(), logging.INFO))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
