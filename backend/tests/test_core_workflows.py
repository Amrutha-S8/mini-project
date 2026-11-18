"""Workflows A, B and C through the pure core, end to end. Stdlib only.

Face gallery -> AccessEngine -> VirtualDoor -> EventPipeline -> attack-chain
reconstruction, wired by a small adapter written here in the test. This
proves the core components work together; it does not exercise the camera,
the database, the API or notifications, which need the blocked stack.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from app.domain.access_engine import (
    AccessDecision,
    AccessEngine,
    AccessRequest,
    DecisionSigner,
    MemberSnapshot,
    Outcome,
    PermissionSnapshot,
    Policy,
    Source,
)
from app.domain.attack_chain import reconstruct
from app.domain.face_matching import FaceGallery, FaceObservation
from app.domain.pipeline import EventPipeline, MemorySink, Status
from app.domain.virtual_door import (
    DoorEvent,
    DoorState,
    InvalidUnlockError,
    VirtualDoor,
)

T0 = datetime(2026, 11, 16, 18, 0, tzinfo=UTC)
DIM = 8


def vec(*head: float) -> list[float]:
    return list(head) + [0.0] * (DIM - len(head))


class Home:
    """Minimal adapter: the role the FastAPI service layer will play."""

    def __init__(self) -> None:
        self.now = T0
        self.signer = DecisionSigner(b"h" * 32)
        self.engine = AccessEngine(self.signer)
        self.sink = MemorySink()
        self.pipeline = EventPipeline(self.sink, clock=lambda: self.now)
        self.door = VirtualDoor("main", self.signer, listener=self._door_event)
        self.gallery = FaceGallery.from_vectors([(1, 7, vec(1, 0, 0))], dim=DIM)
        self.members = {7: MemberSnapshot(7, "active")}
        self.permissions = (PermissionSnapshot(11, 7, "main"),)
        self.policy = Policy(match_threshold=0.6, min_margin=0.1, hold_band=0.05)

    def _emit(self, **raw: Any) -> None:
        raw.setdefault("occurred_at", self.now)
        result = self.pipeline.ingest(raw)
        assert result.status is Status.ACCEPTED, result

    def _door_event(self, event: DoorEvent) -> None:
        kinds = {
            "unlocked": ("door.unlocked", "succeeded"),
            "relocked_automatically": ("door.relocked", "observed"),
            "unlock_rejected": ("door.unlock_rejected", "blocked"),
        }
        if event.kind in kinds:
            etype, outcome = kinds[event.kind]
            self._emit(
                event_type=etype,
                source_module="virtual_door",
                occurred_at=event.at,
                outcome=outcome,
                door_id=event.door_id,
                decision_id=event.decision_id,
            )

    def camera(self, faces: list[FaceObservation], visitor_key: str) -> AccessDecision:
        match = self.gallery.match(
            faces,
            threshold=self.policy.match_threshold,
            min_margin=self.policy.min_margin,
        )
        member = self.members.get(match.member_id) if match.member_id else None
        decision = self.engine.decide(
            AccessRequest(
                request_id=f"cam-{self.now.timestamp()}",
                door_id="main",
                source=Source.CAMERA,
                now=self.now,
                match=match,
                member=member,
                permissions=self.permissions,
            ),
            self.policy,
        )
        etype = {
            Outcome.ALLOW: "access.allowed",
            Outcome.DENY: "access.denied",
            Outcome.HOLD: "access.hold",
        }[decision.outcome]
        if decision.member_id is None:
            self._emit(
                event_type="face.unknown_visitor",
                source_module="face",
                visitor_key=visitor_key,
                door_id="main",
            )
        self._emit(
            event_type=etype,
            source_module="access_engine",
            outcome="succeeded" if decision.outcome is Outcome.ALLOW else "blocked",
            decision_id=decision.decision_id,
            member_id=decision.member_id,
            visitor_key=None if decision.member_id else visitor_key,
            door_id="main",
            details={"rule": decision.rule_name, "reason": decision.reason},
        )
        self.door.apply(decision, self.now)
        return decision


def test_workflow_a_authorised_member() -> None:
    home = Home()
    d = home.camera([FaceObservation(vec(1, 0.02, 0))], "v-a")
    assert d.outcome is Outcome.ALLOW and d.member_id == 7
    assert home.door.state_at(home.now) is DoorState.UNLOCKED
    home.now += timedelta(seconds=5)
    assert home.door.state_at(home.now) is DoorState.LOCKED
    types = [e.event_type for e in home.sink.events]
    assert types == ["access.allowed", "door.unlocked", "door.relocked"]
    assert reconstruct(home.sink.events) == [], "normal entry is not an incident"


def test_workflow_b_unknown_visitor_stays_anonymous_and_locked() -> None:
    home = Home()
    d = home.camera([FaceObservation(vec(0, 0, 1))], "v-b")
    assert d.outcome is Outcome.DENY and d.member_id is None
    assert home.door.state_at(home.now) is DoorState.LOCKED
    assert len(home.gallery) == 1, "unknown visitor was not enrolled"
    unknown = [e for e in home.sink.events if e.event_type == "face.unknown_visitor"]
    assert unknown[0].member_id is None and unknown[0].visitor_key == "v-b"


def test_workflow_c_suspicious_activity_reconstructed() -> None:
    home = Home()
    for _ in range(3):
        home.camera([FaceObservation(vec(0, 0, 1))], "v-c")
        home.now += timedelta(seconds=10)
    home._emit(
        event_type="auth.login_failed",
        source_module="auth",
        outcome="blocked",
        ip_address="203.0.113.9",
    )
    home.now += timedelta(seconds=5)
    home._emit(
        event_type="admin.permission_change_denied",
        source_module="api",
        outcome="blocked",
        ip_address="203.0.113.9",
    )
    # A forged ALLOW reaches the door and is refused.
    forged = home.engine.decide(
        AccessRequest(
            request_id="x", door_id="main", source=Source.CAMERA, now=home.now
        ),
        home.policy,
    )
    try:
        home.door.apply(replace(forged, outcome=Outcome.ALLOW), home.now)
        raise AssertionError("door accepted a forged decision")
    except InvalidUnlockError as exc:
        assert exc.reason == "invalid_signature"
    assert home.door.state_at(home.now) is DoorState.LOCKED

    incidents = reconstruct(home.sink.events)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.notify and incident.allowed_after_suspicious == ()
    assert {"face.unknown_visitor", "door.unlock_rejected"} <= {
        s.event_type for s in incident.timeline
    }
    assert any("lockdown" in r for r in incident.recommendations)
    # Defensive response, deny-side only. An ALLOW issued just before the
    # lockdown reaches the door afterwards: the door refuses it (layer 2).
    late_allow = home.engine.decide(
        AccessRequest(
            request_id="late",
            door_id="main",
            source=Source.MANUAL_OVERRIDE,
            now=home.now,
            approver_user_id=1,
            approver_is_active_admin=True,
        ),
        home.policy,
    )
    assert late_allow.outcome is Outcome.ALLOW
    home.door.enter_lockdown(home.now, actor_user_id=None, reason=incident.incident_id)
    try:
        home.door.apply(late_allow, home.now)
        raise AssertionError("door accepted an ALLOW during lockdown")
    except InvalidUnlockError as exc:
        assert exc.reason == "lockdown_active"

    # Layer 1: with lockdown in the policy, the engine itself denies, even a
    # recognised family member with a valid permission.
    home.policy = replace(home.policy, lockdown=True)
    member = home.camera([FaceObservation(vec(1, 0.02, 0))], "v-ok")
    assert (member.outcome, member.reason) == (Outcome.DENY, "lockdown_active")
    assert home.door.state_at(home.now) is DoorState.LOCKDOWN
