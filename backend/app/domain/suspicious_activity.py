"""Suspicious activity and tamper-attempt detection (module M13 core, stdlib only).

Rule-based and explainable. Each rule looks at one newly recorded
``SecurityEvent`` plus the recent stored history and returns zero or more
``Finding`` objects with a severity, a plain-language reason and the ids of
the events that triggered it. Findings become incidents in
``app.services.monitoring_service``.

Defensive and read-only by construction:

* this module has no reference to the AccessEngine, the virtual door,
  permissions or the database session. It cannot unlock, approve, deny or
  change anything; its only output is a ``Finding``;
* every activity record is untrusted input. Claims inside a record (a
  decision id, a member id, a timestamp) are checked against ``TrustedFacts``
  supplied by the server from its own tables, never believed;
* reasons never contain names, contact details, images or embeddings, only
  the validated identifiers already on the event (door, camera) and counts.

False positives are handled explicitly: single failures never raise an
incident, repeated denials of one registered member (usually an expired
schedule) are LOW and do not notify, and quiet-hour access by a registered
member is LOW and does not notify.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, tzinfo
from typing import Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.domain.events import SecurityEvent, Severity

# --- rule names (stored as incident ``category`` and detection ``detector_rule``)

RULE_REPEATED_DENIED = "repeated_denied_access"
RULE_REPEATED_UNKNOWN = "repeated_unknown_visitor"
RULE_FAILED_LOGIN_BURST = "failed_login_burst"
RULE_TOKEN_REUSE = "session_token_reuse"  # noqa: S105 - rule name
RULE_FORGED_DECISION = "forged_or_replayed_decision"
RULE_DECISION_MISMATCH = "decision_record_mismatch"
RULE_UNVERIFIED_GRANT = "unverified_access_grant"
RULE_IDENTITY_CONFLICT = "visitor_identity_conflict"
RULE_BACKDATED = "backdated_activity_record"
RULE_FUTURE_TIMESTAMP = "future_dated_activity_record"
RULE_EVENT_ID_REUSE = "event_id_reuse"
RULE_MALFORMED_BURST = "malformed_activity_records"
RULE_QUIET_HOURS = "quiet_hours_access"

ALL_RULES = (
    RULE_REPEATED_DENIED,
    RULE_REPEATED_UNKNOWN,
    RULE_FAILED_LOGIN_BURST,
    RULE_TOKEN_REUSE,
    RULE_FORGED_DECISION,
    RULE_DECISION_MISMATCH,
    RULE_UNVERIFIED_GRANT,
    RULE_IDENTITY_CONFLICT,
    RULE_BACKDATED,
    RULE_FUTURE_TIMESTAMP,
    RULE_EVENT_ID_REUSE,
    RULE_MALFORMED_BURST,
    RULE_QUIET_HOURS,
)

#: Event types that state an access outcome, and the decision they claim.
_CLAIMED_DECISION = {
    "access.allowed": "allow",
    "access.denied": "deny",
    "access.hold": "hold",
    "door.unlocked": "allow",
}
#: Event types that claim someone got in.
_GRANT_TYPES = frozenset({"access.allowed", "door.unlocked"})
#: Event types whose timestamps describe physical activity at the door.
_PHYSICAL_MODALITIES = frozenset({"access", "door", "biometric"})


class TrustedFacts(Protocol):
    """Server-side lookups. Implemented over the database by the service."""

    def decision_of(self, decision_id: str) -> str | None:
        """The AccessEngine's stored decision ('allow'/'deny'/'hold') or None."""

    def member_status(self, member_id: int) -> str | None:
        """The stored member status ('active'/'inactive'/'revoked') or None."""


@dataclass(frozen=True)
class DetectionConfig:
    denied_window: timedelta = timedelta(minutes=10)
    denied_threshold: int = 3
    denied_high_threshold: int = 6
    unknown_window: timedelta = timedelta(minutes=30)
    unknown_threshold: int = 3
    login_window: timedelta = timedelta(minutes=10)
    login_threshold: int = 5
    login_high_threshold: int = 10
    malformed_window: timedelta = timedelta(minutes=10)
    malformed_threshold: int = 5
    max_record_age: timedelta = timedelta(hours=24)
    max_future_skew: timedelta = timedelta(minutes=2)
    quiet_start: time = time(1, 0)
    quiet_end: time = time(5, 0)
    timezone: str = "UTC"

    @property
    def longest_window(self) -> timedelta:
        return max(
            self.denied_window,
            self.unknown_window,
            self.login_window,
            self.malformed_window,
        )

    def tz(self) -> tzinfo:
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            return ZoneInfo("UTC")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    reason: str
    #: Findings with the same key within the merge window join one incident.
    dedupe_key: str
    #: The newly recorded event that triggered the finding.
    trigger_event_id: str
    #: Every event id the finding is based on, oldest first.
    event_ids: tuple[str, ...] = field(default=())


def _within(
    history: Sequence[SecurityEvent], event: SecurityEvent, window: timedelta
) -> list[SecurityEvent]:
    start = event.occurred_at - window
    return [
        e
        for e in history
        if start <= e.occurred_at <= event.occurred_at and e.event_id != event.event_id
    ]


def _ids(events: Sequence[SecurityEvent]) -> tuple[str, ...]:
    return tuple(e.event_id for e in sorted(events, key=lambda e: e.occurred_at))


def _minutes(window: timedelta) -> int:
    return max(1, int(window.total_seconds() // 60))


# --- access-pattern rules -------------------------------------------------------------


def _repeated_denied(
    event: SecurityEvent, history: Sequence[SecurityEvent], cfg: DetectionConfig
) -> Finding | None:
    if event.event_type != "access.denied":
        return None
    same_door = [
        e
        for e in _within(history, event, cfg.denied_window)
        if e.event_type == "access.denied" and e.door_id == event.door_id
    ]
    group = [*same_door, event]
    if len(group) < cfg.denied_threshold:
        return None
    door = event.door_id or "unknown door"
    members = {e.member_id for e in group}
    if len(members) == 1 and None not in members:
        severity = Severity.LOW
        reason = (
            f"{len(group)} denied access decisions for the same registered "
            f"member at {door} within {_minutes(cfg.denied_window)} minutes. "
            "Often an expired or out-of-hours permission; review the schedule."
        )
    else:
        severity = (
            Severity.HIGH
            if len(group) >= cfg.denied_high_threshold
            else Severity.MEDIUM
        )
        reason = (
            f"{len(group)} denied access decisions at {door} within "
            f"{_minutes(cfg.denied_window)} minutes (threshold "
            f"{cfg.denied_threshold})."
        )
    return Finding(
        rule=RULE_REPEATED_DENIED,
        severity=severity,
        title=f"Repeated denied access at {door}",
        reason=reason,
        dedupe_key=f"{RULE_REPEATED_DENIED}:{door}",
        trigger_event_id=event.event_id,
        event_ids=_ids(group),
    )


def _repeated_unknown(
    event: SecurityEvent, history: Sequence[SecurityEvent], cfg: DetectionConfig
) -> Finding | None:
    if event.event_type != "face.unknown_visitor":
        return None
    recent = [
        e
        for e in _within(history, event, cfg.unknown_window)
        if e.event_type == "face.unknown_visitor"
    ]
    if event.visitor_key is not None:
        scope = f"visitor {event.visitor_key}"
        matches = [e for e in recent if e.visitor_key == event.visitor_key]
        what = "the same unknown visitor was seen"
    else:
        scope = f"camera {event.camera_id or 'unknown'}"
        matches = [
            e
            for e in recent
            if e.visitor_key is None and e.camera_id == event.camera_id
        ]
        what = "unknown visitors were seen"
    group = [*matches, event]
    if len(group) < cfg.unknown_threshold:
        return None
    return Finding(
        rule=RULE_REPEATED_UNKNOWN,
        severity=Severity.MEDIUM,
        title="Repeated unknown visitor at the door",
        reason=(
            f"{what} {len(group)} times within {_minutes(cfg.unknown_window)} "
            f"minutes ({scope}). The door stays locked for unknown visitors."
        ),
        dedupe_key=f"{RULE_REPEATED_UNKNOWN}:{scope}",
        trigger_event_id=event.event_id,
        event_ids=_ids(group),
    )


def _failed_login_burst(
    event: SecurityEvent, history: Sequence[SecurityEvent], cfg: DetectionConfig
) -> Finding | None:
    types = {"auth.login_failed", "auth.login_throttled"}
    if event.event_type not in types or event.ip_address is None:
        return None
    group = [
        *(
            e
            for e in _within(history, event, cfg.login_window)
            if e.event_type in types and e.ip_address == event.ip_address
        ),
        event,
    ]
    if len(group) < cfg.login_threshold:
        return None
    severity = (
        Severity.HIGH if len(group) >= cfg.login_high_threshold else Severity.MEDIUM
    )
    return Finding(
        rule=RULE_FAILED_LOGIN_BURST,
        severity=severity,
        title="Repeated failed operator logins",
        reason=(
            f"{len(group)} failed or throttled logins from one client address "
            f"within {_minutes(cfg.login_window)} minutes (threshold "
            f"{cfg.login_threshold}). Accounts are not locked; the client is "
            "throttled."
        ),
        dedupe_key=f"{RULE_FAILED_LOGIN_BURST}:{event.ip_address}",
        trigger_event_id=event.event_id,
        event_ids=_ids(group),
    )


def _single_event_rules(event: SecurityEvent) -> Finding | None:
    if event.event_type == "auth.token_reuse":
        return Finding(
            rule=RULE_TOKEN_REUSE,
            severity=Severity.HIGH,
            title="Operator session token reused",
            reason=(
                "An already-rotated refresh token was presented again, which "
                "indicates a copied token. The whole session family was revoked."
            ),
            dedupe_key=f"{RULE_TOKEN_REUSE}:{event.user_id}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    if event.event_type == "door.unlock_rejected":
        door = event.door_id or "unknown door"
        return Finding(
            rule=RULE_FORGED_DECISION,
            severity=Severity.HIGH,
            title=f"Rejected unlock command at {door}",
            reason=(
                "The virtual door refused an unlock command carrying a forged, "
                "stale or replayed decision. The door stayed locked."
            ),
            dedupe_key=f"{RULE_FORGED_DECISION}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    return None


# --- record-integrity (tamper) rules --------------------------------------------------


def _decision_claims(event: SecurityEvent, facts: TrustedFacts) -> Finding | None:
    claimed = _CLAIMED_DECISION.get(event.event_type)
    if claimed is None:
        return None
    door = event.door_id or "unknown door"
    if event.decision_id is None:
        if event.event_type not in _GRANT_TYPES:
            return None
        return Finding(
            rule=RULE_UNVERIFIED_GRANT,
            severity=Severity.HIGH,
            title=f"Access grant without a decision record at {door}",
            reason=(
                f"A record claims '{event.event_type}' but carries no AccessEngine "
                "decision reference. Only the AccessEngine can grant access, so "
                "the record is unverifiable."
            ),
            dedupe_key=f"{RULE_UNVERIFIED_GRANT}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    stored = facts.decision_of(event.decision_id)
    if stored is None:
        return Finding(
            rule=RULE_DECISION_MISMATCH,
            severity=Severity.HIGH,
            title=f"Activity record references an unknown decision at {door}",
            reason=(
                f"A '{event.event_type}' record references a decision the "
                "AccessEngine never recorded. The record may be forged."
            ),
            dedupe_key=f"{RULE_DECISION_MISMATCH}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    if stored != claimed:
        return Finding(
            rule=RULE_DECISION_MISMATCH,
            severity=Severity.HIGH,
            title=f"Activity record contradicts the AccessEngine at {door}",
            reason=(
                f"A record claims '{claimed.upper()}' for a decision the "
                f"AccessEngine recorded as '{stored.upper()}'. The stored "
                "decision is authoritative; the record may have been altered."
            ),
            dedupe_key=f"{RULE_DECISION_MISMATCH}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    return None


def _identity_claims(event: SecurityEvent, facts: TrustedFacts) -> Finding | None:
    door = event.door_id or event.camera_id or "the door"
    if event.member_id is not None and event.visitor_key is not None:
        return Finding(
            rule=RULE_IDENTITY_CONFLICT,
            severity=Severity.MEDIUM,
            title="Conflicting visitor information",
            reason=(
                "One record carries both an unknown-visitor key and a registered "
                "member reference. Unknown visitors are never linked to members, "
                "so the record is inconsistent."
            ),
            dedupe_key=f"{RULE_IDENTITY_CONFLICT}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    if event.member_id is None:
        return None
    status = facts.member_status(event.member_id)
    if status is None:
        return Finding(
            rule=RULE_IDENTITY_CONFLICT,
            severity=Severity.MEDIUM,
            title="Record references a member that does not exist",
            reason=(
                "An activity record references a registered-member id that is not "
                "in the household registry."
            ),
            dedupe_key=f"{RULE_IDENTITY_CONFLICT}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    if status != "active" and event.event_type in _GRANT_TYPES:
        return Finding(
            rule=RULE_IDENTITY_CONFLICT,
            severity=Severity.HIGH,
            title=f"Granted access recorded for a {status} member",
            reason=(
                f"A record claims access was granted to a member whose status is "
                f"'{status}'. The AccessEngine denies {status} members, so the "
                "record conflicts with the registry."
            ),
            dedupe_key=f"{RULE_IDENTITY_CONFLICT}:{door}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    return None


def _timestamp_claims(event: SecurityEvent, cfg: DetectionConfig) -> Finding | None:
    if event.modality.value not in _PHYSICAL_MODALITIES:
        return None
    source = event.source_module
    if event.occurred_at > event.received_at + cfg.max_future_skew:
        ahead = int((event.occurred_at - event.received_at).total_seconds())
        return Finding(
            rule=RULE_FUTURE_TIMESTAMP,
            severity=Severity.MEDIUM,
            title="Activity record dated in the future",
            reason=(
                f"A record from '{source}' is dated {ahead}s after the server "
                "received it. Device clock fault or manipulated timestamp."
            ),
            dedupe_key=f"{RULE_FUTURE_TIMESTAMP}:{source}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    if event.received_at - event.occurred_at > cfg.max_record_age:
        hours = int((event.received_at - event.occurred_at).total_seconds() // 3600)
        return Finding(
            rule=RULE_BACKDATED,
            severity=Severity.MEDIUM,
            title="Backdated activity record",
            reason=(
                f"A record from '{source}' describes door activity {hours} hours "
                "before it was received. Late uploads of door activity are not "
                "expected; the record may have been backdated."
            ),
            dedupe_key=f"{RULE_BACKDATED}:{source}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    return None


def _event_id_reuse(event: SecurityEvent) -> Finding | None:
    if "event_id_conflict" not in event.details:
        return None
    return Finding(
        rule=RULE_EVENT_ID_REUSE,
        severity=Severity.MEDIUM,
        title="Event id reused for different content",
        reason=(
            f"A record from '{event.source_module}' reused an existing event id "
            "with different content (possible replay or edited record). It was "
            "stored under a new id."
        ),
        dedupe_key=f"{RULE_EVENT_ID_REUSE}:{event.source_module}",
        trigger_event_id=event.event_id,
        event_ids=(event.event_id,),
    )


def _malformed_burst(
    event: SecurityEvent, history: Sequence[SecurityEvent], cfg: DetectionConfig
) -> Finding | None:
    if event.event_type != "api.invalid_input":
        return None
    scope = event.ip_address or event.source_module
    if event.details.get("reason") == "too_far_in_future":
        return Finding(
            rule=RULE_FUTURE_TIMESTAMP,
            severity=Severity.MEDIUM,
            title="Activity record dated in the future was rejected",
            reason=(
                "An activity record was rejected because its timestamp was too "
                "far in the future. Device clock fault or manipulated timestamp."
            ),
            dedupe_key=f"{RULE_FUTURE_TIMESTAMP}:{scope}",
            trigger_event_id=event.event_id,
            event_ids=(event.event_id,),
        )
    group = [
        *(
            e
            for e in _within(history, event, cfg.malformed_window)
            if e.event_type == "api.invalid_input"
            and (e.ip_address or e.source_module) == scope
        ),
        event,
    ]
    if len(group) < cfg.malformed_threshold:
        return None
    return Finding(
        rule=RULE_MALFORMED_BURST,
        severity=Severity.MEDIUM,
        title="Repeated malformed activity records",
        reason=(
            f"{len(group)} activity records from one source were rejected as "
            f"invalid within {_minutes(cfg.malformed_window)} minutes (threshold "
            f"{cfg.malformed_threshold}). Possible probing or a faulty device."
        ),
        dedupe_key=f"{RULE_MALFORMED_BURST}:{scope}",
        trigger_event_id=event.event_id,
        event_ids=_ids(group),
    )


def _quiet_hours(event: SecurityEvent, cfg: DetectionConfig) -> Finding | None:
    if event.event_type != "access.allowed" or event.member_id is None:
        return None
    local = event.occurred_at.astimezone(cfg.tz()).time()
    start, end = cfg.quiet_start, cfg.quiet_end
    inside = start <= local < end if start <= end else (local >= start or local < end)
    if not inside:
        return None
    return Finding(
        rule=RULE_QUIET_HOURS,
        severity=Severity.LOW,
        title="Access during quiet hours",
        reason=(
            f"A registered member was allowed in at {local.strftime('%H:%M')} "
            f"({cfg.timezone}), inside the quiet hours "
            f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')}. Informational."
        ),
        dedupe_key=f"{RULE_QUIET_HOURS}:{event.member_id}",
        trigger_event_id=event.event_id,
        event_ids=(event.event_id,),
    )


def evaluate(
    event: SecurityEvent,
    history: Sequence[SecurityEvent],
    facts: TrustedFacts,
    config: DetectionConfig | None = None,
) -> list[Finding]:
    """All findings for ``event`` given the recent ``history``.

    ``history`` should hold the stored events from at least
    ``config.longest_window`` before the event; it may include the event
    itself, which is ignored. Deterministic for the same input.
    """
    cfg = config or DetectionConfig()
    candidates = [
        _repeated_denied(event, history, cfg),
        _repeated_unknown(event, history, cfg),
        _failed_login_burst(event, history, cfg),
        _single_event_rules(event),
        _decision_claims(event, facts),
        _identity_claims(event, facts),
        _timestamp_claims(event, cfg),
        _event_id_reuse(event),
        _malformed_burst(event, history, cfg),
        _quiet_hours(event, cfg),
    ]
    return [f for f in candidates if f is not None]


def should_notify(severity: Severity, minimum: Severity) -> bool:
    """LOW findings never notify, whatever the configured minimum."""
    return severity >= max(minimum, Severity.MEDIUM)


def parse_quiet_hours(text: str) -> tuple[time, time]:
    """Parse ``"HH:MM-HH:MM"``; raises ``ValueError`` on bad input."""
    start_text, sep, end_text = text.partition("-")
    if not sep:
        raise ValueError("quiet hours must look like 01:00-05:00")
    start = datetime.strptime(start_text.strip(), "%H:%M").time()
    end = datetime.strptime(end_text.strip(), "%H:%M").time()
    if start == end:
        raise ValueError("quiet hours start and end must differ")
    return start, end
