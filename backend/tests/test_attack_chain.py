"""Cross-Modal Attack Chain Reconstruction scenarios (Day 8). Stdlib only."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.domain.attack_chain import (
    CorrelationConfig,
    Stage,
    reconstruct,
)
from app.domain.events import Modality, SecurityEvent, Severity, normalise_event

T0 = datetime(2026, 11, 16, 2, 0, tzinfo=UTC)


def ev(seconds: int, event_type: str, **fields: Any) -> SecurityEvent:
    raw = {
        "event_type": event_type,
        "source_module": "test",
        "occurred_at": T0 + timedelta(seconds=seconds),
        "outcome": fields.pop("outcome", "observed"),
        **fields,
    }
    return normalise_event(raw, received_at=T0 + timedelta(hours=1))


def test_single_suspicious_event_is_not_an_incident() -> None:
    assert reconstruct([ev(0, "auth.login_failed", ip_address="203.0.113.9")]) == []


def test_unrelated_events_far_apart_are_not_grouped() -> None:
    events = [
        ev(0, "auth.login_failed", ip_address="203.0.113.9"),
        ev(3600, "auth.login_failed", ip_address="198.51.100.4"),
    ]
    assert reconstruct(events) == []


def test_credential_attack_from_one_ip_grouped_and_blocked() -> None:
    events = [
        ev(i * 10, "auth.login_failed", ip_address="203.0.113.9", outcome="blocked")
        for i in range(5)
    ] + [ev(60, "auth.login_throttled", ip_address="203.0.113.9", outcome="blocked")]
    (incident,) = reconstruct(events)
    assert incident.blocked_count == 6
    assert incident.allowed_after_suspicious == ()
    assert {s.stage for s in incident.timeline} == {Stage.PROBE, Stage.ESCALATION}
    assert all(link.kind == "shared_key" for link in incident.links)
    assert "No allowed action" in incident.summary


def test_cross_modal_chain_raises_severity_and_explains_temporal_links() -> None:
    events = [
        ev(0, "face.unknown_visitor", visitor_key="v-1", door_id="main"),
        ev(5, "access.denied", visitor_key="v-1", door_id="main", outcome="blocked"),
        ev(40, "auth.login_failed", ip_address="203.0.113.9", outcome="blocked"),
        ev(
            70,
            "admin.permission_change_denied",
            ip_address="203.0.113.9",
            outcome="blocked",
        ),
    ]
    (incident,) = reconstruct(events)
    assert {Modality.BIOMETRIC, Modality.ACCESS, Modality.AUTH, Modality.ADMIN} <= (
        incident.modalities
    )
    # Highest event is HIGH (permission change denied) + one cross-modal bump.
    assert incident.severity is Severity.CRITICAL
    temporal = [link for link in incident.links if link.kind == "temporal"]
    assert temporal, "biometric and auth events share no key, only timing"
    assert all("timing only" in link.explanation for link in temporal)
    assert "may be coincidental" in incident.summary
    assert incident.notify


def test_allowed_action_after_suspicious_activity_is_highlighted_not_judged() -> None:
    events = [
        ev(0, "auth.login_failed", ip_address="203.0.113.9", outcome="blocked"),
        ev(20, "auth.login_failed", ip_address="203.0.113.9", outcome="blocked"),
        ev(
            40,
            "auth.login_succeeded",
            ip_address="203.0.113.9",
            user_id=1,
            outcome="succeeded",
        ),
    ]
    (incident,) = reconstruct(events)
    assert len(incident.allowed_after_suspicious) == 1
    assert incident.timeline[-1].stage is Stage.ALLOWED_ACTION
    assert "does not establish" in incident.summary
    assert any("Review the allowed action" in r for r in incident.recommendations)


def test_context_event_joins_through_specific_identifier() -> None:
    """A door unlock linked by decision_id to an access event in the chain."""
    events = [
        ev(0, "face.uncertain_match", visitor_key="v-2", door_id="main"),
        ev(10, "access.denied", visitor_key="v-2", outcome="blocked"),
        ev(
            60,
            "access.hold_approved",
            visitor_key="v-2",
            decision_id="d-9",
            outcome="succeeded",
        ),
        ev(61, "door.unlocked", decision_id="d-9", door_id="main", outcome="succeeded"),
    ]
    (incident,) = reconstruct(events)
    assert {s.event_type for s in incident.timeline} >= {"door.unlocked"}
    assert len(incident.allowed_after_suspicious) == 2


def test_household_ip_alone_does_not_merge_normal_activity() -> None:
    events = [
        ev(i * 30, "auth.login_succeeded", ip_address="192.168.1.10") for i in range(10)
    ]
    assert reconstruct(events) == []


def test_rejected_unlock_and_ai_violation_recommendations() -> None:
    events = [
        ev(0, "ai.policy_violation", session_id="s-1", outcome="blocked"),
        ev(
            1,
            "door.unlock_rejected",
            session_id="s-1",
            door_id="main",
            outcome="blocked",
        ),
    ]
    (incident,) = reconstruct(events)
    recs = " ".join(incident.recommendations)
    assert "AI agent execution log" in recs
    assert "rejected unlock" in recs
    assert "Consider enabling lockdown" in recs


def test_gaps_are_reported_not_filled() -> None:
    events = [
        ev(0, "auth.login_failed", session_id="s-3"),
        ev(600, "auth.token_reuse", session_id="s-3"),
    ]
    (incident,) = reconstruct(events, CorrelationConfig(window=timedelta(minutes=15)))
    assert len(incident.gaps) == 1 and len(incident.timeline) == 2


def test_deterministic_ids_and_order() -> None:
    events = [
        ev(0, "auth.login_failed", ip_address="203.0.113.9"),
        ev(5, "auth.login_failed", ip_address="203.0.113.9"),
    ]
    a = reconstruct(events)
    b = reconstruct(list(reversed(events)))
    assert [i.incident_id for i in a] == [i.incident_id for i in b]
    assert a[0].event_ids == b[0].event_ids


def test_evidence_refs_preserved() -> None:
    events = [
        ev(0, "face.unknown_visitor", visitor_key="v-4", evidence_ref="snap/1.jpg"),
        ev(3, "access.denied", visitor_key="v-4", outcome="blocked"),
    ]
    (incident,) = reconstruct(events)
    assert incident.evidence_refs == ("snap/1.jpg",)


def test_module_cannot_reach_door_or_engine() -> None:
    """Reconstruction is read-only: no import path to the access core."""
    path = Path(__file__).resolve().parent.parent / "app" / "domain" / "attack_chain.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {
        n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
    }
    assert "app.domain.access_engine" not in imported
    assert "app.domain.virtual_door" not in imported
