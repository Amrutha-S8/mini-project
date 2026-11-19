"""Suspicious activity and tamper detection rules (stdlib; runs everywhere).

Covers each rule's positive case and the false positives it must avoid, and
that the module cannot reach the door, the AccessEngine or the database.
"""

from __future__ import annotations

import ast
import itertools
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.domain import suspicious_activity as sa
from app.domain.events import SecurityEvent, Severity, normalise_event

T0 = datetime(2026, 11, 19, 14, 0, tzinfo=UTC)
_ids = itertools.count(1)


class Facts:
    def __init__(
        self,
        decisions: dict[str, str] | None = None,
        members: dict[int, str] | None = None,
    ) -> None:
        self.decisions = decisions or {}
        self.members = members or {}

    def decision_of(self, decision_id: str) -> str | None:
        return self.decisions.get(decision_id)

    def member_status(self, member_id: int) -> str | None:
        return self.members.get(member_id)


def ev(
    event_type: str, at: datetime = T0, received: datetime | None = None, **kw: Any
) -> SecurityEvent:
    raw = {
        "event_id": f"e{next(_ids)}",
        "event_type": event_type,
        "source_module": kw.pop("source_module", "camera"),
        "occurred_at": at,
        **kw,
    }
    return normalise_event(raw, received_at=received or at)


def rules(
    event: SecurityEvent,
    history: list[SecurityEvent] | None = None,
    facts: Facts | None = None,
    **cfg: Any,
) -> dict[str, sa.Finding]:
    found = sa.evaluate(
        event, history or [], facts or Facts(), sa.DetectionConfig(**cfg)
    )
    return {f.rule: f for f in found}


# --- repeated denied access -----------------------------------------------------------


def test_single_denial_is_not_suspicious() -> None:
    assert sa.RULE_REPEATED_DENIED not in rules(ev("access.denied", door_id="front"))


def test_two_denials_stay_below_threshold() -> None:
    first = ev("access.denied", T0, door_id="front")
    second = ev("access.denied", T0 + timedelta(minutes=1), door_id="front")
    assert sa.RULE_REPEATED_DENIED not in rules(second, [first])


def test_three_unknown_denials_at_one_door_raise_medium() -> None:
    history = [
        ev("access.denied", T0 + timedelta(minutes=i), door_id="front")
        for i in range(2)
    ]
    current = ev("access.denied", T0 + timedelta(minutes=3), door_id="front")
    finding = rules(current, history)[sa.RULE_REPEATED_DENIED]
    assert finding.severity == Severity.MEDIUM
    assert finding.trigger_event_id == current.event_id
    assert finding.event_ids == (*[h.event_id for h in history], current.event_id)
    assert "3 denied access decisions at front" in finding.reason


def test_six_denials_raise_high() -> None:
    history = [
        ev("access.denied", T0 + timedelta(seconds=30 * i), door_id="front")
        for i in range(5)
    ]
    current = ev("access.denied", T0 + timedelta(minutes=3), door_id="front")
    assert rules(current, history)[sa.RULE_REPEATED_DENIED].severity == Severity.HIGH


def test_denials_outside_the_window_do_not_count() -> None:
    old = [
        ev("access.denied", T0 - timedelta(minutes=30 + i), door_id="front")
        for i in range(4)
    ]
    current = ev("access.denied", T0, door_id="front")
    assert sa.RULE_REPEATED_DENIED not in rules(current, old)


def test_denials_at_other_doors_do_not_count() -> None:
    other = [ev("access.denied", T0, door_id="garage") for _ in range(4)]
    current = ev("access.denied", T0 + timedelta(minutes=1), door_id="front")
    assert sa.RULE_REPEATED_DENIED not in rules(current, other)


def test_one_registered_member_repeatedly_denied_is_low() -> None:
    """False positive: usually an expired schedule, so LOW and no notification."""
    history = [
        ev("access.denied", T0 + timedelta(minutes=i), door_id="front", member_id=7)
        for i in range(3)
    ]
    current = ev(
        "access.denied", T0 + timedelta(minutes=4), door_id="front", member_id=7
    )
    finding = rules(current, history, Facts(members={7: "active"}))[
        sa.RULE_REPEATED_DENIED
    ]
    assert finding.severity == Severity.LOW
    assert not sa.should_notify(finding.severity, Severity.LOW)


# --- unknown visitors -----------------------------------------------------------------


def test_same_unknown_visitor_three_times_is_medium() -> None:
    history = [
        ev("face.unknown_visitor", T0 + timedelta(minutes=5 * i), visitor_key="v-1")
        for i in range(2)
    ]
    current = ev("face.unknown_visitor", T0 + timedelta(minutes=12), visitor_key="v-1")
    finding = rules(current, history)[sa.RULE_REPEATED_UNKNOWN]
    assert finding.severity == Severity.MEDIUM
    assert "v-1" in finding.dedupe_key


def test_different_unknown_visitors_are_not_grouped() -> None:
    history = [ev("face.unknown_visitor", T0, visitor_key=f"v-{i}") for i in range(4)]
    current = ev("face.unknown_visitor", T0 + timedelta(minutes=1), visitor_key="v-new")
    assert sa.RULE_REPEATED_UNKNOWN not in rules(current, history)


# --- operator logins ------------------------------------------------------------------


def test_a_few_mistyped_passwords_are_not_an_incident() -> None:
    history = [
        ev("auth.login_failed", T0, source_module="auth", ip_address="10.0.0.2")
        for _ in range(3)
    ]
    current = ev(
        "auth.login_failed",
        T0 + timedelta(minutes=1),
        source_module="auth",
        ip_address="10.0.0.2",
    )
    assert sa.RULE_FAILED_LOGIN_BURST not in rules(current, history)


def test_failed_login_burst_from_one_address() -> None:
    history = [
        ev("auth.login_failed", T0, source_module="auth", ip_address="10.0.0.2")
        for _ in range(4)
    ]
    current = ev(
        "auth.login_throttled",
        T0 + timedelta(minutes=1),
        source_module="auth",
        ip_address="10.0.0.2",
    )
    assert (
        rules(current, history)[sa.RULE_FAILED_LOGIN_BURST].severity == Severity.MEDIUM
    )


def test_failures_from_different_addresses_are_not_grouped() -> None:
    history = [
        ev("auth.login_failed", T0, source_module="auth", ip_address=f"10.0.0.{i}")
        for i in range(6)
    ]
    current = ev("auth.login_failed", T0, source_module="auth", ip_address="10.0.0.99")
    assert sa.RULE_FAILED_LOGIN_BURST not in rules(current, history)


def test_token_reuse_and_rejected_unlock_are_high_immediately() -> None:
    reuse = rules(ev("auth.token_reuse", source_module="auth", user_id=3))
    assert reuse[sa.RULE_TOKEN_REUSE].severity == Severity.HIGH
    rejected = rules(ev("door.unlock_rejected", source_module="door", door_id="front"))
    assert rejected[sa.RULE_FORGED_DECISION].severity == Severity.HIGH


# --- tampered or conflicting records --------------------------------------------------


def test_allowed_record_without_decision_reference_is_flagged() -> None:
    found = rules(ev("access.allowed", door_id="front"))
    assert found[sa.RULE_UNVERIFIED_GRANT].severity == Severity.HIGH


def test_denied_record_without_decision_reference_is_not_tampering() -> None:
    assert sa.RULE_UNVERIFIED_GRANT not in rules(ev("access.denied", door_id="front"))


def test_record_referencing_an_unknown_decision_is_flagged() -> None:
    found = rules(ev("access.allowed", door_id="front", decision_id="d-404"))
    assert "never recorded" in found[sa.RULE_DECISION_MISMATCH].reason


def test_record_contradicting_the_engine_is_flagged() -> None:
    facts = Facts(decisions={"d-1": "deny"})
    found = rules(ev("door.unlocked", door_id="front", decision_id="d-1"), facts=facts)
    finding = found[sa.RULE_DECISION_MISMATCH]
    assert finding.severity == Severity.HIGH
    assert "'ALLOW'" in finding.reason and "'DENY'" in finding.reason


def test_record_matching_the_engine_is_not_flagged() -> None:
    facts = Facts(decisions={"d-1": "allow"}, members={4: "active"})
    found = rules(
        ev("access.allowed", T0, door_id="front", decision_id="d-1", member_id=4),
        facts=facts,
    )
    assert sa.RULE_DECISION_MISMATCH not in found
    assert sa.RULE_UNVERIFIED_GRANT not in found
    assert sa.RULE_IDENTITY_CONFLICT not in found


def test_unknown_visitor_record_claiming_a_member_is_conflicting() -> None:
    found = rules(
        ev("face.unknown_visitor", visitor_key="v-9", member_id=2),
        facts=Facts(members={2: "active"}),
    )
    assert found[sa.RULE_IDENTITY_CONFLICT].severity == Severity.MEDIUM


def test_record_for_a_nonexistent_member_is_conflicting() -> None:
    found = rules(ev("access.denied", door_id="front", member_id=999))
    assert "not in the household registry" in found[sa.RULE_IDENTITY_CONFLICT].reason


def test_granted_access_for_a_revoked_member_is_high() -> None:
    facts = Facts(decisions={"d-2": "allow"}, members={5: "revoked"})
    found = rules(
        ev("access.allowed", door_id="front", decision_id="d-2", member_id=5),
        facts=facts,
    )
    assert found[sa.RULE_IDENTITY_CONFLICT].severity == Severity.HIGH


def test_backdated_door_record_is_flagged() -> None:
    event = ev("access.denied", T0 - timedelta(days=2), received=T0, door_id="front")
    assert sa.RULE_BACKDATED in rules(event)


def test_slightly_late_record_is_normal() -> None:
    event = ev(
        "access.denied", T0 - timedelta(minutes=10), received=T0, door_id="front"
    )
    assert sa.RULE_BACKDATED not in rules(event)


def test_future_dated_record_is_flagged_but_small_skew_is_not() -> None:
    ahead = ev("face.unknown_visitor", T0 + timedelta(minutes=4), received=T0)
    assert sa.RULE_FUTURE_TIMESTAMP in rules(ahead)
    skew = ev("face.unknown_visitor", T0 + timedelta(seconds=30), received=T0)
    assert sa.RULE_FUTURE_TIMESTAMP not in rules(skew)


def test_auth_events_are_not_judged_on_upload_delay() -> None:
    event = ev(
        "auth.login_failed", T0 - timedelta(days=3), received=T0, source_module="auth"
    )
    assert sa.RULE_BACKDATED not in rules(event)


def test_event_id_reuse_is_flagged() -> None:
    event = ev("access.denied", door_id="front", details={"event_id_conflict": "e-1"})
    assert sa.RULE_EVENT_ID_REUSE in rules(event)


def test_repeated_malformed_records_and_far_future_rejections() -> None:
    history = [
        ev(
            "api.invalid_input",
            T0,
            source_module="monitoring.ingest",
            ip_address="10.1.1.1",
        )
        for _ in range(4)
    ]
    current = ev(
        "api.invalid_input",
        T0,
        source_module="monitoring.ingest",
        ip_address="10.1.1.1",
    )
    assert sa.RULE_MALFORMED_BURST in rules(current, history)
    single = ev(
        "api.invalid_input", source_module="monitoring.ingest", ip_address="10.1.1.1"
    )
    assert rules(single) == {}
    future = ev(
        "api.invalid_input",
        source_module="monitoring.ingest",
        details={"reason": "too_far_in_future"},
    )
    assert sa.RULE_FUTURE_TIMESTAMP in rules(future)


# --- quiet hours (informational) ------------------------------------------------------


def test_quiet_hours_access_is_low_and_never_notifies() -> None:
    facts = Facts(decisions={"d-3": "allow"}, members={1: "active"})
    night = ev(
        "access.allowed",
        datetime(2026, 11, 19, 2, 30, tzinfo=UTC),
        door_id="front",
        decision_id="d-3",
        member_id=1,
    )
    finding = rules(night, facts=facts)[sa.RULE_QUIET_HOURS]
    assert finding.severity == Severity.LOW
    assert not sa.should_notify(finding.severity, Severity.LOW)
    day = ev(
        "access.allowed",
        datetime(2026, 11, 19, 9, 0, tzinfo=UTC),
        door_id="front",
        decision_id="d-3",
        member_id=1,
    )
    assert sa.RULE_QUIET_HOURS not in rules(day, facts=facts)


def test_quiet_hours_use_the_household_timezone() -> None:
    facts = Facts(decisions={"d-4": "allow"}, members={1: "active"})
    # 21:00 UTC is 02:30 in Asia/Kolkata (UTC+05:30).
    event = ev(
        "access.allowed",
        datetime(2026, 11, 19, 21, 0, tzinfo=UTC),
        door_id="front",
        decision_id="d-4",
        member_id=1,
    )
    assert sa.RULE_QUIET_HOURS in rules(event, facts=facts, timezone="Asia/Kolkata")
    assert sa.RULE_QUIET_HOURS not in rules(event, facts=facts)


def test_quiet_hours_wrapping_midnight() -> None:
    facts = Facts(decisions={"d-5": "allow"}, members={1: "active"})
    event = ev(
        "access.allowed",
        datetime(2026, 11, 19, 23, 30, tzinfo=UTC),
        door_id="front",
        decision_id="d-5",
        member_id=1,
    )
    assert sa.RULE_QUIET_HOURS in rules(
        event, facts=facts, quiet_start=time(23, 0), quiet_end=time(6, 0)
    )


@pytest.mark.parametrize("text", ["", "0100-0500", "25:00-03:00", "02:00-02:00"])
def test_bad_quiet_hours_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        sa.parse_quiet_hours(text)


# --- general properties ---------------------------------------------------------------


def test_normal_allowed_access_produces_no_finding() -> None:
    facts = Facts(decisions={"d-6": "allow"}, members={1: "active"})
    event = ev("access.allowed", T0, door_id="front", decision_id="d-6", member_id=1)
    assert rules(event, facts=facts) == {}


def test_reasons_never_contain_member_ids_or_visitor_names() -> None:
    facts = Facts(members={7: "revoked"})
    findings = sa.evaluate(
        ev("access.allowed", door_id="front", member_id=7, decision_id="d-x"), [], facts
    )
    assert findings
    for f in findings:
        assert "7" not in f.reason


def test_should_notify_never_for_low() -> None:
    assert not sa.should_notify(Severity.LOW, Severity.INFO)
    assert sa.should_notify(Severity.MEDIUM, Severity.MEDIUM)
    assert not sa.should_notify(Severity.MEDIUM, Severity.HIGH)
    assert sa.should_notify(Severity.CRITICAL, Severity.HIGH)


def test_evaluate_is_deterministic() -> None:
    history = [ev("access.denied", T0, door_id="front") for _ in range(3)]
    current = ev("access.denied", T0 + timedelta(minutes=1), door_id="front")
    assert sa.evaluate(current, history, Facts()) == sa.evaluate(
        current, history, Facts()
    )


def test_detector_cannot_reach_the_door_engine_or_database() -> None:
    """Structural guarantee: the module imports nothing that could act."""
    source = Path(sa.__file__).read_text(encoding="utf-8")
    imported = {
        (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported <= {
        "__future__",
        "collections.abc",
        "dataclasses",
        "datetime",
        "typing",
        "zoneinfo",
        "app.domain.events",
    }
