"""Normalised security events (modules M10/M11/M13 core, stdlib only).

Every module reports what happened as a raw mapping. ``normalise_event``
validates it and turns it into one ``SecurityEvent`` shape with a UTC
timestamp, a known type, a severity, provenance and redacted details. Invalid
input raises ``EventValidationError``; it is never silently stored.

Unknown visitors are identified only by an opaque ``visitor_key`` (a session
or cluster handle). No real-world identity is ever attached to them here.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from app.domain.evidence import InvalidEvidenceRef, validate_evidence_ref


class EventValidationError(ValueError):
    pass


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise EventValidationError(f"unknown severity {value!r}") from None


class Modality(StrEnum):
    """Which security layer produced the evidence (used for correlation)."""

    BIOMETRIC = "biometric"
    ACCESS = "access"
    DOOR = "door"
    AUTH = "auth"
    API = "api"
    ADMIN = "admin"
    AI_AGENT = "ai_agent"
    SYSTEM = "system"
    NOTIFICATION = "notification"


@dataclass(frozen=True)
class EventType:
    name: str
    modality: Modality
    default_severity: Severity
    suspicious: bool = False


_TYPES: dict[str, EventType] = {
    t.name: t
    for t in [
        EventType("access.allowed", Modality.ACCESS, Severity.INFO),
        EventType("access.denied", Modality.ACCESS, Severity.LOW, suspicious=True),
        EventType("access.hold", Modality.ACCESS, Severity.LOW),
        EventType("access.hold_approved", Modality.ACCESS, Severity.INFO),
        EventType("access.hold_rejected", Modality.ACCESS, Severity.LOW),
        EventType("face.unknown_visitor", Modality.BIOMETRIC, Severity.LOW, True),
        EventType("face.uncertain_match", Modality.BIOMETRIC, Severity.LOW, True),
        EventType("face.multiple_faces", Modality.BIOMETRIC, Severity.LOW),
        EventType("face.poor_quality", Modality.BIOMETRIC, Severity.INFO),
        EventType("face.liveness_failed", Modality.BIOMETRIC, Severity.HIGH, True),
        EventType("door.unlocked", Modality.DOOR, Severity.INFO),
        EventType("door.relocked", Modality.DOOR, Severity.INFO),
        EventType("door.unlock_rejected", Modality.DOOR, Severity.HIGH, True),
        EventType("door.lockdown_entered", Modality.DOOR, Severity.MEDIUM),
        EventType("door.lockdown_released", Modality.DOOR, Severity.MEDIUM),
        EventType("door.manual_control", Modality.DOOR, Severity.LOW),
        EventType("auth.login_succeeded", Modality.AUTH, Severity.INFO),
        EventType("auth.login_failed", Modality.AUTH, Severity.LOW, True),
        EventType("auth.login_throttled", Modality.AUTH, Severity.MEDIUM, True),
        EventType("auth.token_reuse", Modality.AUTH, Severity.HIGH, True),
        EventType("auth.session_revoked", Modality.AUTH, Severity.INFO),
        EventType("api.unauthorized", Modality.API, Severity.LOW, True),
        EventType("api.forbidden", Modality.API, Severity.MEDIUM, True),
        EventType("api.invalid_input", Modality.API, Severity.INFO),
        EventType("admin.permission_changed", Modality.ADMIN, Severity.MEDIUM),
        EventType(
            "admin.permission_change_denied", Modality.ADMIN, Severity.HIGH, True
        ),
        EventType("admin.member_changed", Modality.ADMIN, Severity.LOW),
        EventType("admin.enrollment_changed", Modality.ADMIN, Severity.MEDIUM),
        EventType("ai.policy_violation", Modality.AI_AGENT, Severity.HIGH, True),
        EventType("ai.tool_denied", Modality.AI_AGENT, Severity.MEDIUM, True),
        EventType("system.camera_error", Modality.SYSTEM, Severity.MEDIUM),
        EventType("system.error", Modality.SYSTEM, Severity.MEDIUM),
        EventType("notification.sent", Modality.NOTIFICATION, Severity.INFO),
        EventType("notification.failed", Modality.NOTIFICATION, Severity.LOW),
    ]
}

EVENT_TYPES: Mapping[str, EventType] = _TYPES
OUTCOMES = frozenset({"succeeded", "blocked", "failed", "observed"})

_SENSITIVE = re.compile(
    r"(?i)(password|secret|token|authorization|api[_-]?key|embedding|cookie)"
)
_ID = re.compile(r"[A-Za-z0-9._:@/-]{1,128}")
_MAX_DETAIL_ITEMS = 50
_MAX_TEXT = 500


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    event_type: str
    modality: Modality
    severity: Severity
    occurred_at: datetime
    received_at: datetime
    source_module: str
    outcome: str
    suspicious: bool
    member_id: int | None = None
    user_id: int | None = None
    visitor_key: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
    ip_address: str | None = None
    door_id: str | None = None
    camera_id: str | None = None
    decision_id: str | None = None
    evidence_ref: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    timestamp_assumed_utc: bool = False


def parse_timestamp(value: Any) -> tuple[datetime, bool]:
    """Return (aware UTC datetime, was_naive). Rejects nonsense."""
    naive = False
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if not 0 <= value < 4_102_444_800:  # before 2100
            raise EventValidationError("epoch timestamp out of range")
        return datetime.fromtimestamp(float(value), tz=UTC), False
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise EventValidationError(f"unparseable timestamp {value!r}") from None
    else:
        raise EventValidationError("timestamp missing or of unsupported type")
    if dt.tzinfo is None or dt.utcoffset() is None:
        dt, naive = dt.replace(tzinfo=UTC), True
    return dt.astimezone(UTC), naive


def _identifier(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None or value == "":
        return None
    text = str(value).strip()
    if not _ID.fullmatch(text):
        raise EventValidationError(f"{key} has invalid characters or length")
    return text


def _evidence_ref(raw: Mapping[str, Any]) -> str | None:
    """Strict relative path inside the evidence directory (finding P1)."""
    value = raw.get("evidence_ref")
    if value is None or value == "":
        return None
    try:
        return validate_evidence_ref(value)
    except InvalidEvidenceRef as exc:
        raise EventValidationError(str(exc)) from None


def _int_or_none(raw: Mapping[str, Any], key: str) -> int | None:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EventValidationError(f"{key} must be a non-negative integer")
    return value


def redact_details(details: Mapping[str, Any], depth: int = 0) -> dict[str, Any]:
    """Drop secret-looking keys, summarise binary data, cap size and depth."""
    if depth > 3:
        return {"_truncated": True}
    clean: dict[str, Any] = {}
    for i, (key, value) in enumerate(details.items()):
        if i >= _MAX_DETAIL_ITEMS:
            clean["_truncated"] = True
            break
        name = str(key)[:64]
        if _SENSITIVE.search(name):
            clean[name] = "***REDACTED***"
        elif isinstance(value, (bytes, bytearray, memoryview)):
            clean[name] = f"<{len(value)} bytes>"
        elif isinstance(value, Mapping):
            clean[name] = redact_details(value, depth + 1)
        elif isinstance(value, str):
            clean[name] = value[:_MAX_TEXT]
        elif isinstance(value, (int, float, bool)) or value is None:
            clean[name] = value
        elif isinstance(value, (list, tuple)):
            clean[name] = [str(v)[:_MAX_TEXT] for v in list(value)[:_MAX_DETAIL_ITEMS]]
        else:
            clean[name] = str(value)[:_MAX_TEXT]
    return clean


def normalise_event(raw: Mapping[str, Any], *, received_at: datetime) -> SecurityEvent:
    if not isinstance(raw, Mapping):
        raise EventValidationError("event must be a mapping")
    type_name = str(raw.get("event_type", "")).strip()
    etype = EVENT_TYPES.get(type_name)
    if etype is None:
        raise EventValidationError(f"unknown event_type {type_name!r}")
    source = str(raw.get("source_module", "")).strip()
    if not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", source):
        raise EventValidationError("source_module is required (lowercase identifier)")
    occurred_at, naive = parse_timestamp(raw.get("occurred_at"))
    received, _ = parse_timestamp(received_at)
    outcome = str(raw.get("outcome", "observed")).strip().lower()
    if outcome not in OUTCOMES:
        raise EventValidationError(f"outcome must be one of {sorted(OUTCOMES)}")
    severity = (
        Severity.parse(raw["severity"])
        if raw.get("severity") is not None
        else etype.default_severity
    )
    details = raw.get("details") or {}
    if not isinstance(details, Mapping):
        raise EventValidationError("details must be a mapping")
    event_id = _identifier(raw, "event_id") or uuid.uuid4().hex
    return SecurityEvent(
        event_id=event_id,
        event_type=etype.name,
        modality=etype.modality,
        severity=severity,
        occurred_at=occurred_at,
        received_at=received,
        source_module=source,
        outcome=outcome,
        suspicious=etype.suspicious
        or (outcome == "blocked" and severity >= Severity.MEDIUM),
        member_id=_int_or_none(raw, "member_id"),
        user_id=_int_or_none(raw, "user_id"),
        visitor_key=_identifier(raw, "visitor_key"),
        session_id=_identifier(raw, "session_id"),
        request_id=_identifier(raw, "request_id"),
        correlation_id=_identifier(raw, "correlation_id"),
        ip_address=_identifier(raw, "ip_address"),
        door_id=_identifier(raw, "door_id"),
        camera_id=_identifier(raw, "camera_id"),
        decision_id=_identifier(raw, "decision_id"),
        evidence_ref=_evidence_ref(raw),
        details=redact_details(details),
        timestamp_assumed_utc=naive,
    )
