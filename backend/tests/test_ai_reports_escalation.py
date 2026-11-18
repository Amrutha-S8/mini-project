"""Deterministic reports and escalation recommendations, built from the real core.

Incidents come from ``app.domain.attack_chain.reconstruct`` over normalised
events, not from hand-made objects, so these tests exercise the same path a
running system would.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.ai.core.escalation import Level, recommend
from app.ai.core.reports import (
    Period,
    ReportAccessDenied,
    incident_category,
    render_incident_report,
    render_period_report,
    report_window,
    summarise_period,
)
from app.ai.core.types import UserContext
from app.domain.attack_chain import Incident, reconstruct
from app.domain.events import SecurityEvent, Severity, normalise_event

T0 = datetime(2026, 11, 16, 2, 0, tzinfo=UTC)
ADMIN = UserContext(1, "admin", True)
VIEWER = UserContext(2, "viewer", True)
MEMBER = UserContext(3, "member", True, member_id=5)


def ev(seconds: int, event_type: str, **kw: Any) -> SecurityEvent:
    raw: dict[str, Any] = {
        "event_type": event_type,
        "source_module": "test",
        "occurred_at": (T0 + timedelta(seconds=seconds)).isoformat(),
        "event_id": f"e{seconds}-{event_type}",
        "door_id": "main",
    }
    raw.update(kw)
    return normalise_event(raw, received_at=T0 + timedelta(hours=1))


def credential_attack() -> Incident:
    events = [
        ev(i, "auth.login_failed", outcome="failed", ip_address="203.0.113.7")
        for i in range(4)
    ]
    (incident,) = reconstruct(events)
    return incident


def intrusion_with_entry() -> Incident:
    events = [
        ev(0, "face.unknown_visitor", visitor_key="v-4", evidence_ref="snap/1.jpg"),
        ev(5, "access.denied", visitor_key="v-4", outcome="blocked"),
        ev(9, "face.uncertain_match", visitor_key="v-4"),
        ev(20, "access.allowed", visitor_key="v-4", outcome="succeeded"),
    ]
    (incident,) = reconstruct(events)
    return incident


# --- escalation ------------------------------------------------------------------


def test_entry_after_suspicious_activity_escalates_and_recommends_lockdown() -> None:
    rec = recommend(intrusion_with_entry())
    assert rec.level is Level.ESCALATE and rec.recommend_lockdown
    assert rec.recommend_notify_homeowner
    assert rec.requires_approval and not rec.executes_actions
    assert any("not executed" in r for r in rec.reasons)


def test_low_severity_credential_attack_is_monitored() -> None:
    incident = credential_attack()
    assert incident.severity == Severity.LOW
    rec = recommend(incident)
    assert rec.level is Level.MONITOR and not rec.recommend_lockdown
    assert not rec.recommend_notify_homeowner


@pytest.mark.parametrize(
    "high_risk",
    [
        "door.unlock_rejected",
        "face.liveness_failed",
        "auth.token_reuse",
        "ai.policy_violation",
    ],
)
def test_high_risk_signals_escalate(high_risk: str) -> None:
    events = [
        ev(0, "auth.login_failed", outcome="failed", ip_address="203.0.113.7"),
        ev(3, high_risk, outcome="blocked", ip_address="203.0.113.7"),
    ]
    (incident,) = reconstruct(events)
    rec = recommend(incident)
    assert rec.level is Level.ESCALATE and high_risk in " ".join(rec.reasons)


def test_existing_lockdown_is_not_recommended_again() -> None:
    incident = intrusion_with_entry()
    steps = list(incident.timeline)
    steps.append(
        dataclasses.replace(
            steps[-1], event_id="lock", event_type="door.lockdown_entered"
        )
    )
    rec = recommend(dataclasses.replace(incident, timeline=tuple(steps)))
    assert rec.level is Level.ESCALATE and not rec.recommend_lockdown


@pytest.mark.parametrize(
    "severity,level",
    [
        (Severity.CRITICAL, Level.ESCALATE),
        (Severity.HIGH, Level.ESCALATE),
        (Severity.MEDIUM, Level.MONITOR),
        (Severity.LOW, Level.MONITOR),
        (Severity.INFO, Level.NO_ACTION),
    ],
)
def test_severity_levels(severity: Severity, level: Level) -> None:
    incident = dataclasses.replace(credential_attack(), severity=severity, notify=False)
    assert recommend(incident).level is level


def test_critical_recommends_lockdown() -> None:
    incident = dataclasses.replace(credential_attack(), severity=Severity.CRITICAL)
    assert recommend(incident).recommend_lockdown


def test_recommendation_object_has_no_way_to_act() -> None:
    rec = recommend(intrusion_with_entry())
    public = {n for n in dir(rec) if not n.startswith("_")}
    assert not any(callable(getattr(rec, n)) for n in public)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.executes_actions = True  # type: ignore[misc]


def test_escalation_is_deterministic() -> None:
    assert recommend(intrusion_with_entry()) == recommend(intrusion_with_entry())


# --- incident reports -------------------------------------------------------------


def test_admin_report_has_full_detail() -> None:
    report = render_incident_report(intrusion_with_entry(), ADMIN)
    assert "event=e0-face.unknown_visitor" in report.text
    assert "evidence=snap/1.jpg" in report.text
    assert report.evidence_refs == ("snap/1.jpg",)
    assert "Why these events are linked" in report.text
    assert report.deterministic and not report.is_ai_generated
    assert "Not AI-generated" in report.text


def test_viewer_report_is_redacted() -> None:
    report = render_incident_report(intrusion_with_entry(), VIEWER)
    assert "event=" not in report.text and "snap/1.jpg" not in report.text
    assert "v-4" not in report.text and "Why these events are linked" not in report.text
    assert report.evidence_refs == ()


def test_members_get_no_incident_or_period_reports() -> None:
    with pytest.raises(ReportAccessDenied):
        render_incident_report(credential_attack(), MEMBER)
    summary = summarise_period(Period.DAILY, [], [], now=T0, timezone="UTC")
    with pytest.raises(ReportAccessDenied):
        render_period_report(summary, MEMBER)
    with pytest.raises(ReportAccessDenied):
        render_incident_report(credential_attack(), UserContext(1, "admin", False))


def test_reports_never_contain_ip_addresses() -> None:
    for ctx in (ADMIN, VIEWER):
        assert (
            "203.0.113.7" not in render_incident_report(credential_attack(), ctx).text
        )


def test_incident_report_is_byte_identical_across_runs() -> None:
    a = render_incident_report(intrusion_with_entry(), ADMIN).text
    b = render_incident_report(intrusion_with_entry(), ADMIN).text
    assert a == b


def test_categories() -> None:
    assert incident_category(credential_attack()) == "credential_attack"
    assert incident_category(intrusion_with_entry()) == "intrusion_attempt"


def test_recommendations_are_labelled_as_not_executed() -> None:
    text = render_incident_report(intrusion_with_entry(), ADMIN).text
    assert "nothing was executed" in text


# --- period windows and summaries ---------------------------------------------


@pytest.mark.parametrize(
    "period,now,tz,start,end",
    [
        (
            Period.DAILY,
            datetime(2026, 11, 16, 10, tzinfo=UTC),
            "UTC",
            datetime(2026, 11, 15, tzinfo=UTC),
            datetime(2026, 11, 16, tzinfo=UTC),
        ),
        (
            Period.WEEKLY,
            datetime(2026, 11, 18, 10, tzinfo=UTC),  # Wednesday
            "UTC",
            datetime(2026, 11, 9, tzinfo=UTC),
            datetime(2026, 11, 16, tzinfo=UTC),
        ),
        (
            Period.MONTHLY,
            datetime(2026, 1, 5, tzinfo=UTC),
            "UTC",
            datetime(2025, 12, 1, tzinfo=UTC),
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
        (
            Period.DAILY,
            datetime(2026, 11, 16, 3, tzinfo=UTC),  # 08:30 in Kolkata
            "Asia/Kolkata",
            datetime(2026, 11, 14, 18, 30, tzinfo=UTC),
            datetime(2026, 11, 15, 18, 30, tzinfo=UTC),
        ),
    ],
)
def test_report_windows(
    period: Period, now: datetime, tz: str, start: datetime, end: datetime
) -> None:
    assert report_window(period, now, tz) == (start, end)


def test_dst_day_is_23_hours() -> None:
    """Europe/London springs forward on 2026-03-29."""
    start, end = report_window(
        Period.DAILY, datetime(2026, 3, 30, 12, tzinfo=UTC), "Europe/London"
    )
    assert end - start == timedelta(hours=23)


def test_naive_now_rejected() -> None:
    with pytest.raises(ValueError):
        report_window(Period.DAILY, datetime(2026, 11, 16), "UTC")


def test_period_summary_counts_are_exact() -> None:
    day = datetime(2026, 11, 15, tzinfo=UTC)
    events = [
        normalise_event(
            {
                "event_type": t,
                "source_module": "test",
                "occurred_at": (day + timedelta(hours=h)).isoformat(),
                "outcome": o,
                "door_id": "main",
            },
            received_at=day + timedelta(days=1),
        )
        for t, o, h in [
            ("auth.login_failed", "failed", 1),
            ("auth.login_failed", "failed", 2),
            ("auth.login_throttled", "blocked", 3),
            ("face.unknown_visitor", "observed", 4),
            ("access.denied", "blocked", 5),
            ("access.allowed", "succeeded", 6),
            ("access.allowed", "succeeded", 30),  # next day: outside the window
        ]
    ]
    summary = summarise_period(
        Period.DAILY,
        events,
        [],
        now=datetime(2026, 11, 16, 9, tzinfo=UTC),
        timezone="UTC",
    )
    assert summary.total_events == 6
    assert (summary.failed_logins, summary.throttled_logins) == (2, 1)
    assert (summary.access_allowed, summary.access_denied) == (1, 1)
    assert summary.unknown_visitor_sightings == 1 and summary.blocked == 2
    text = render_period_report(summary, VIEWER)
    assert "Failed logins: 2 (throttled: 1)" in text and "Not AI-generated" in text
    assert render_period_report(summary, ADMIN) == text
