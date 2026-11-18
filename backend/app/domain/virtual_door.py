"""Virtual door state machine (module M09). A software SIMULATION only.

This does not secure a real door. It models a lock so the access workflow can
be demonstrated and tested without hardware.

Rules:
* The resting state is LOCKED. A new or restarted door is LOCKED.
* Only an ALLOW decision that the AccessEngine signed, for this door, issued
  recently and never used before can unlock it, and only for a bounded time.
* DENY and HOLD decisions keep it locked.
* LOCKDOWN refuses every unlock until an admin releases it.
* Every transition and every rejected unlock is recorded as a DoorEvent.

Time is passed in; relocking is evaluated lazily at each call, so there is no
background thread that could fail and leave the door open.
"""

from __future__ import annotations

import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from app.domain.access_engine import AccessDecision, DecisionSigner, Outcome

SIMULATION_NOTICE = (
    "Virtual door simulation: this software does not physically secure a door."
)
MIN_UNLOCK_SECONDS = 1
MAX_UNLOCK_SECONDS = 60


class DoorState(StrEnum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    LOCKDOWN = "lockdown"


class InvalidUnlockError(Exception):
    """An unlock was refused. ``reason`` is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DoorEvent:
    event_id: str
    door_id: str
    at: datetime
    kind: str
    state_before: DoorState
    state_after: DoorState
    decision_id: str | None = None
    actor_user_id: int | None = None
    detail: str | None = None


Listener = Callable[[DoorEvent], None]


class VirtualDoor:
    def __init__(
        self,
        door_id: str,
        signer: DecisionSigner,
        *,
        unlock_seconds: int = 5,
        max_decision_age_seconds: int = 10,
        listener: Listener | None = None,
        replay_memory: int = 10_000,
    ) -> None:
        self.door_id = door_id
        self._signer = signer
        self._unlock_seconds = _validate_duration(unlock_seconds)
        self._max_age = timedelta(seconds=max_decision_age_seconds)
        self._listener = listener
        self._state = DoorState.LOCKED
        self._unlocked_until: datetime | None = None
        self._used_ids: set[str] = set()
        self._used_order: deque[str] = deque()
        self._replay_memory = replay_memory
        self._history: list[DoorEvent] = []
        self.listener_failures = 0

    # --- queries ------------------------------------------------------------

    @property
    def unlock_seconds(self) -> int:
        return self._unlock_seconds

    @property
    def history(self) -> tuple[DoorEvent, ...]:
        return tuple(self._history)

    def state_at(self, now: datetime) -> DoorState:
        """Current state, relocking first if the unlock period has ended."""
        self._relock_if_due(now)
        return self._state

    def unlocked_until(self, now: datetime) -> datetime | None:
        self._relock_if_due(now)
        return self._unlocked_until

    # --- configuration --------------------------------------------------------

    def set_unlock_seconds(
        self, seconds: int, *, now: datetime, actor_user_id: int
    ) -> None:
        self._unlock_seconds = _validate_duration(seconds)
        self._record(
            now,
            "unlock_duration_changed",
            self._state,
            self._state,
            actor_user_id=actor_user_id,
            detail=f"{seconds}s",
        )

    # --- decisions ------------------------------------------------------------

    def apply(self, decision: AccessDecision, now: datetime) -> DoorState:
        """Act on an AccessEngine decision.

        Raises InvalidUnlockError, after recording it, for anything that is
        not a genuine, fresh, unused decision for this door.
        """
        self._relock_if_due(now)
        before = self._state
        reason = self._rejection_reason(decision, now)
        if reason is not None:
            self._record(
                now,
                "unlock_rejected",
                before,
                before,
                decision_id=decision.decision_id,
                detail=reason,
            )
            raise InvalidUnlockError(reason)
        self._remember(decision.decision_id)

        if decision.outcome is not Outcome.ALLOW:
            self._record(
                now,
                f"kept_locked_{decision.outcome.value}",
                before,
                before,
                decision_id=decision.decision_id,
                detail=decision.reason,
            )
            return self._state
        if self._state is DoorState.LOCKDOWN:
            self._record(
                now,
                "unlock_rejected",
                before,
                before,
                decision_id=decision.decision_id,
                detail="lockdown_active",
            )
            raise InvalidUnlockError("lockdown_active")

        self._state = DoorState.UNLOCKED
        self._unlocked_until = now + timedelta(seconds=self._unlock_seconds)
        self._record(
            now,
            "unlocked",
            before,
            self._state,
            decision_id=decision.decision_id,
            detail=decision.reason,
        )
        return self._state

    # --- manual controls (caller must have authenticated an admin) ---------------

    def lock(self, now: datetime, *, actor_user_id: int) -> DoorState:
        self._relock_if_due(now)
        before = self._state
        if before is DoorState.UNLOCKED:
            self._state = DoorState.LOCKED
            self._unlocked_until = None
            self._record(
                now, "locked_manually", before, self._state, actor_user_id=actor_user_id
            )
        return self._state

    def enter_lockdown(
        self, now: datetime, *, actor_user_id: int | None, reason: str
    ) -> DoorState:
        """Deny-side action: always safe. ``actor_user_id`` None means system."""
        self._relock_if_due(now)
        before = self._state
        self._state = DoorState.LOCKDOWN
        self._unlocked_until = None
        self._record(
            now,
            "lockdown_entered",
            before,
            self._state,
            actor_user_id=actor_user_id,
            detail=reason,
        )
        return self._state

    def release_lockdown(self, now: datetime, *, actor_user_id: int) -> DoorState:
        before = self._state
        if before is DoorState.LOCKDOWN:
            self._state = DoorState.LOCKED
            self._record(
                now,
                "lockdown_released",
                before,
                self._state,
                actor_user_id=actor_user_id,
            )
        return self._state

    # --- internals ------------------------------------------------------------

    def _rejection_reason(self, decision: AccessDecision, now: datetime) -> str | None:
        if not isinstance(decision, AccessDecision):
            return "not_a_decision"
        if not self._signer.verify(decision):
            return "invalid_signature"
        if decision.door_id != self.door_id:
            return "wrong_door"
        if decision.decision_id in self._used_ids:
            return "replayed_decision"
        age = now - decision.decided_at
        if age < timedelta(0):
            return "decision_from_future"
        if age > self._max_age:
            return "stale_decision"
        return None

    def _remember(self, decision_id: str) -> None:
        self._used_ids.add(decision_id)
        self._used_order.append(decision_id)
        while len(self._used_order) > self._replay_memory:
            self._used_ids.discard(self._used_order.popleft())

    def _relock_if_due(self, now: datetime) -> None:
        if (
            self._state is DoorState.UNLOCKED
            and self._unlocked_until is not None
            and now >= self._unlocked_until
        ):
            at = self._unlocked_until
            self._state = DoorState.LOCKED
            self._unlocked_until = None
            self._record(
                at, "relocked_automatically", DoorState.UNLOCKED, DoorState.LOCKED
            )

    def _record(
        self,
        at: datetime,
        kind: str,
        before: DoorState,
        after: DoorState,
        *,
        decision_id: str | None = None,
        actor_user_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        event = DoorEvent(
            uuid.uuid4().hex,
            self.door_id,
            at,
            kind,
            before,
            after,
            decision_id,
            actor_user_id,
            detail,
        )
        self._history.append(event)
        if self._listener is not None:
            try:
                self._listener(event)
            except Exception:  # noqa: BLE001 - a listener must never affect the lock
                # Counted, not raised: the lock state is already committed and
                # the history above still holds the event.
                self.listener_failures += 1


def _validate_duration(seconds: int) -> int:
    if not MIN_UNLOCK_SECONDS <= int(seconds) <= MAX_UNLOCK_SECONDS:
        raise ValueError(
            f"unlock duration must be {MIN_UNLOCK_SECONDS}-{MAX_UNLOCK_SECONDS} seconds"
        )
    return int(seconds)
