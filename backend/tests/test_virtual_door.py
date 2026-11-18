"""Virtual door simulation (M09, SR-AUTHZ-15/16). Stdlib only."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

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
from app.domain.face_matching import MatchResult, MatchStatus
from app.domain.virtual_door import (
    SIMULATION_NOTICE,
    DoorEvent,
    DoorState,
    InvalidUnlockError,
    VirtualDoor,
)

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
SIGNER = DecisionSigner(b"d" * 32)
ENGINE = AccessEngine(SIGNER)


def allow(now: datetime = NOW, door: str = "main") -> AccessDecision:
    req = AccessRequest(
        request_id="r",
        door_id=door,
        source=Source.CAMERA,
        now=now,
        match=MatchResult(
            MatchStatus.MATCHED,
            threshold=0.45,
            min_margin=0.05,
            member_id=7,
            embedding_id=1,
            score=0.9,
        ),
        member=MemberSnapshot(7, "active"),
        permissions=(PermissionSnapshot(1, 7, door),),
    )
    d = ENGINE.decide(req, Policy())
    assert d.outcome is Outcome.ALLOW
    return d


def deny(now: datetime = NOW) -> AccessDecision:
    req = AccessRequest(request_id="r", door_id="main", source=Source.CAMERA, now=now)
    return ENGINE.decide(req, Policy())


@pytest.fixture
def events() -> list[DoorEvent]:
    return []


@pytest.fixture
def door(events: list[DoorEvent]) -> VirtualDoor:
    return VirtualDoor("main", SIGNER, unlock_seconds=5, listener=events.append)


def test_starts_locked_and_states_it_is_a_simulation(door: VirtualDoor) -> None:
    assert door.state_at(NOW) is DoorState.LOCKED
    assert "simulation" in SIMULATION_NOTICE.lower()


def test_allow_unlocks_then_relocks_automatically(door: VirtualDoor) -> None:
    assert door.apply(allow(), NOW) is DoorState.UNLOCKED
    assert door.state_at(NOW + timedelta(seconds=4.9)) is DoorState.UNLOCKED
    assert door.state_at(NOW + timedelta(seconds=5)) is DoorState.LOCKED
    kinds = [e.kind for e in door.history]
    assert kinds == ["unlocked", "relocked_automatically"]
    assert door.history[-1].at == NOW + timedelta(seconds=5)


@pytest.mark.parametrize("outcome", [Outcome.DENY, Outcome.HOLD])
def test_deny_and_hold_keep_it_locked(door: VirtualDoor, outcome: Outcome) -> None:
    decision = deny()
    if outcome is Outcome.HOLD:
        decision = ENGINE.decide(
            AccessRequest(
                request_id="r",
                door_id="main",
                source=Source.CAMERA,
                now=NOW,
                match=MatchResult(
                    MatchStatus.MULTIPLE_FACES, threshold=0.45, min_margin=0.05
                ),
            ),
            Policy(),
        )
    assert decision.outcome is outcome
    assert door.apply(decision, NOW) is DoorState.LOCKED
    assert door.history[-1].kind == f"kept_locked_{outcome.value}"


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda d: replace(d, outcome=Outcome.ALLOW, reason="forged"),
            "invalid_signature",
        ),
        (lambda d: replace(d, signature=""), "invalid_signature"),
    ],
)
def test_forged_decisions_rejected(door: VirtualDoor, mutate, reason: str) -> None:
    with pytest.raises(InvalidUnlockError) as exc:
        door.apply(mutate(deny()), NOW)
    assert exc.value.reason == reason
    assert door.state_at(NOW) is DoorState.LOCKED
    assert door.history[-1].kind == "unlock_rejected"


def test_decision_from_another_signer_rejected(door: VirtualDoor) -> None:
    other = AccessEngine(DecisionSigner(b"o" * 32))
    foreign = other.decide(
        AccessRequest(
            request_id="r",
            door_id="main",
            source=Source.MANUAL_OVERRIDE,
            now=NOW,
            approver_user_id=1,
            approver_is_active_admin=True,
        ),
        Policy(),
    )
    with pytest.raises(InvalidUnlockError, match="invalid_signature"):
        door.apply(foreign, NOW)


def test_wrong_door_rejected(door: VirtualDoor) -> None:
    with pytest.raises(InvalidUnlockError, match="wrong_door"):
        door.apply(allow(door="garage"), NOW)


def test_replay_rejected(door: VirtualDoor) -> None:
    d = allow()
    door.apply(d, NOW)
    with pytest.raises(InvalidUnlockError, match="replayed_decision"):
        door.apply(d, NOW + timedelta(seconds=6))


def test_stale_decision_rejected(door: VirtualDoor) -> None:
    with pytest.raises(InvalidUnlockError, match="stale_decision"):
        door.apply(allow(), NOW + timedelta(seconds=11))


def test_future_decision_rejected(door: VirtualDoor) -> None:
    with pytest.raises(InvalidUnlockError, match="decision_from_future"):
        door.apply(allow(NOW + timedelta(seconds=1)), NOW)


def test_lockdown_refuses_allow(door: VirtualDoor) -> None:
    door.enter_lockdown(NOW, actor_user_id=None, reason="incident")
    with pytest.raises(InvalidUnlockError, match="lockdown_active"):
        door.apply(allow(), NOW)
    assert door.state_at(NOW) is DoorState.LOCKDOWN


def test_lockdown_relocks_an_open_door(door: VirtualDoor) -> None:
    door.apply(allow(), NOW)
    door.enter_lockdown(NOW + timedelta(seconds=1), actor_user_id=1, reason="manual")
    assert door.state_at(NOW + timedelta(seconds=1)) is DoorState.LOCKDOWN
    assert door.unlocked_until(NOW + timedelta(seconds=1)) is None


def test_release_lockdown_returns_to_locked(door: VirtualDoor) -> None:
    door.enter_lockdown(NOW, actor_user_id=None, reason="incident")
    assert door.release_lockdown(NOW, actor_user_id=1) is DoorState.LOCKED


def test_manual_lock(door: VirtualDoor) -> None:
    door.apply(allow(), NOW)
    assert door.lock(NOW + timedelta(seconds=1), actor_user_id=1) is DoorState.LOCKED
    assert door.history[-1].actor_user_id == 1


@pytest.mark.parametrize("seconds", [0, 61, -1])
def test_unlock_duration_bounded(seconds: int) -> None:
    with pytest.raises(ValueError):
        VirtualDoor("main", SIGNER, unlock_seconds=seconds)


def test_unlock_duration_change_is_recorded(door: VirtualDoor) -> None:
    door.set_unlock_seconds(10, now=NOW, actor_user_id=1)
    door.apply(allow(), NOW)
    assert door.state_at(NOW + timedelta(seconds=9)) is DoorState.UNLOCKED
    assert door.state_at(NOW + timedelta(seconds=10)) is DoorState.LOCKED


def test_restart_is_locked() -> None:
    """A new instance (e.g. after a crash) never inherits an unlocked state."""
    VirtualDoor("main", SIGNER).apply(allow(), NOW)
    assert VirtualDoor("main", SIGNER).state_at(NOW) is DoorState.LOCKED


def test_failing_listener_never_affects_the_lock() -> None:
    def broken(_event: DoorEvent) -> None:
        raise RuntimeError("pipeline down")

    door = VirtualDoor("main", SIGNER, listener=broken)
    assert door.apply(allow(), NOW) is DoorState.UNLOCKED
    assert door.state_at(NOW + timedelta(seconds=5)) is DoorState.LOCKED
    assert door.listener_failures == 2
    assert len(door.history) == 2, "history kept even though the listener failed"


def test_listener_receives_every_event(door: VirtualDoor, events: list) -> None:
    door.apply(allow(), NOW)
    door.state_at(NOW + timedelta(seconds=5))
    assert [e.kind for e in events] == ["unlocked", "relocked_automatically"]
