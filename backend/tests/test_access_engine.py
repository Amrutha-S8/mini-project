"""AccessEngine rule matrix (M08, SR-AUTHZ-06..16, DD-01). Stdlib only."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, time, timedelta

import pytest

from app.domain.access_engine import (
    AccessEngine,
    AccessRequest,
    DecisionSigner,
    MemberSnapshot,
    Outcome,
    PendingHold,
    PermissionSnapshot,
    Policy,
    Rule,
    Source,
    in_time_window,
)
from app.domain.face_matching import MatchResult, MatchStatus

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)  # a Monday
DOOR = "main"


@pytest.fixture
def signer() -> DecisionSigner:
    return DecisionSigner(b"k" * 32)


@pytest.fixture
def engine(signer: DecisionSigner) -> AccessEngine:
    return AccessEngine(signer)


def matched(member_id: int = 7, score: float = 0.80) -> MatchResult:
    return MatchResult(
        MatchStatus.MATCHED,
        threshold=0.45,
        min_margin=0.05,
        member_id=member_id,
        embedding_id=1,
        score=score,
        second_score=0.1,
    )


def permission(**overrides: object) -> PermissionSnapshot:
    base = PermissionSnapshot(permission_id=11, member_id=7, door_id=DOOR)
    return replace(base, **overrides)  # type: ignore[arg-type]


def camera(**overrides: object) -> AccessRequest:
    base = AccessRequest(
        request_id="r1",
        door_id=DOOR,
        source=Source.CAMERA,
        now=NOW,
        match=matched(),
        member=MemberSnapshot(7, "active"),
        permissions=(permission(),),
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def decide(engine: AccessEngine, request: AccessRequest, **policy: object):
    return engine.decide(request, Policy(**policy))  # type: ignore[arg-type]


# --- camera rule matrix --------------------------------------------------------


def test_grant_when_everything_checks_out(engine: AccessEngine) -> None:
    d = decide(engine, camera())
    assert (d.outcome, d.rule, d.reason) == (
        Outcome.ALLOW,
        Rule.GRANT,
        "permission_satisfied",
    )
    assert d.member_id == 7 and d.permission_id == 11


def test_lockdown_beats_everything(engine: AccessEngine) -> None:
    d = decide(engine, camera(), lockdown=True)
    assert (d.outcome, d.reason) == (Outcome.DENY, "lockdown_active")


@pytest.mark.parametrize(
    "status,outcome,reason",
    [
        (MatchStatus.NO_FACE, Outcome.DENY, "no_face"),
        (MatchStatus.MULTIPLE_FACES, Outcome.HOLD, "multiple_faces"),
        (MatchStatus.POOR_QUALITY, Outcome.HOLD, "poor_quality"),
        (MatchStatus.AMBIGUOUS, Outcome.HOLD, "ambiguous_match"),
    ],
)
def test_unusable_or_ambiguous_input(
    engine: AccessEngine, status: MatchStatus, outcome: Outcome, reason: str
) -> None:
    match = MatchResult(status, threshold=0.45, min_margin=0.05, score=0.9)
    d = decide(engine, camera(match=match))
    assert (d.outcome, d.reason) == (outcome, reason)


def test_missing_match_is_denied(engine: AccessEngine) -> None:
    assert decide(engine, camera(match=None)).outcome is Outcome.DENY


def test_unknown_visitor_denied_by_default(engine: AccessEngine) -> None:
    match = MatchResult(MatchStatus.UNKNOWN, threshold=0.45, min_margin=0.05, score=0.1)
    d = decide(engine, camera(match=match, member=None))
    assert (d.outcome, d.reason, d.member_id) == (
        Outcome.DENY,
        "unknown_identity",
        None,
    )


def test_unknown_visitor_hold_when_configured(engine: AccessEngine) -> None:
    match = MatchResult(MatchStatus.UNKNOWN, threshold=0.45, min_margin=0.05, score=0.1)
    d = decide(
        engine, camera(match=match, member=None), unknown_visitor_outcome=Outcome.HOLD
    )
    assert d.outcome is Outcome.HOLD


def test_score_just_below_threshold_is_hold(engine: AccessEngine) -> None:
    match = MatchResult(
        MatchStatus.UNKNOWN, threshold=0.45, min_margin=0.05, score=0.42
    )
    assert decide(engine, camera(match=match)).reason == "uncertain_match"


def test_engine_rechecks_threshold_independently(engine: AccessEngine) -> None:
    """A matcher claiming MATCHED below the engine's threshold is not trusted."""
    d = decide(engine, camera(match=matched(score=0.30)))
    assert d.outcome is Outcome.DENY and d.reason == "unknown_identity"


def test_score_exactly_at_threshold_is_allowed(engine: AccessEngine) -> None:
    d = decide(engine, camera(match=matched(score=0.45)))
    assert d.outcome is Outcome.ALLOW


@pytest.mark.parametrize("status", ["inactive", "revoked"])
def test_inactive_or_revoked_member_denied(engine: AccessEngine, status: str) -> None:
    d = decide(engine, camera(member=MemberSnapshot(7, status)))
    assert (d.outcome, d.reason) == (Outcome.DENY, "member_inactive")


def test_member_record_must_match_identity(engine: AccessEngine) -> None:
    d = decide(engine, camera(member=MemberSnapshot(8, "active")))
    assert d.reason == "member_not_found"


@pytest.mark.parametrize(
    "perms",
    [
        (),
        (permission(is_active=False),),
        (permission(door_id="garage"),),
        (permission(member_id=99),),
    ],
)
def test_no_usable_permission_denied(engine: AccessEngine, perms: tuple) -> None:
    d = decide(engine, camera(permissions=perms))
    assert (d.outcome, d.reason) == (Outcome.DENY, "no_permission")


def test_expired_permission_denied(engine: AccessEngine) -> None:
    d = decide(engine, camera(permissions=(permission(valid_to=NOW),)))
    assert d.reason == "permission_expired"


def test_not_yet_valid_permission_denied(engine: AccessEngine) -> None:
    perm = permission(valid_from=NOW + timedelta(seconds=1))
    assert decide(engine, camera(permissions=(perm,))).reason == "permission_expired"


def test_outside_window_is_hold(engine: AccessEngine) -> None:
    perm = permission(start_local=time(18), end_local=time(22))
    d = decide(engine, camera(permissions=(perm,)))
    assert (d.outcome, d.reason) == (Outcome.HOLD, "outside_time_window")


def test_outside_window_deny_when_configured(engine: AccessEngine) -> None:
    perm = permission(start_local=time(18), end_local=time(22))
    d = decide(engine, camera(permissions=(perm,)), outside_window_outcome=Outcome.DENY)
    assert d.outcome is Outcome.DENY


def test_any_matching_window_is_enough(engine: AccessEngine) -> None:
    perms = (
        permission(start_local=time(18), end_local=time(22)),
        permission(permission_id=12, start_local=time(9), end_local=time(11)),
    )
    d = decide(engine, camera(permissions=perms))
    assert d.outcome is Outcome.ALLOW and d.permission_id == 12


def test_rate_limit(engine: AccessEngine) -> None:
    d = decide(engine, camera(recent_attempts=5))
    assert (d.outcome, d.reason) == (Outcome.DENY, "rate_limited")


def test_naive_time_fails_secure(engine: AccessEngine) -> None:
    d = decide(engine, camera(now=datetime(2026, 11, 16, 10, 0)))
    assert (d.outcome, d.rule) == (Outcome.DENY, Rule.ENGINE_ERROR)


def test_internal_error_fails_secure(engine: AccessEngine) -> None:
    broken = permission(timezone="Not/AZone")
    d = decide(engine, camera(permissions=(broken,)))
    assert (d.outcome, d.reason) == (Outcome.DENY, "engine_error")


def test_garbage_input_fails_secure(engine: AccessEngine) -> None:
    d = decide(engine, camera(match="MATCHED"))  # type: ignore[arg-type]
    assert d.outcome is Outcome.DENY


# --- policy can never allow by configuration ----------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"unknown_visitor_outcome": Outcome.ALLOW},
        {"outside_window_outcome": Outcome.ALLOW},
        {"match_threshold": 0.0},
        {"hold_band": 0.5},
        {"attempt_limit": 0},
    ],
)
def test_unsafe_policy_rejected(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        Policy(**kwargs)


# --- signatures and determinism ------------------------------------------------


def test_decisions_are_signed_and_verifiable(
    engine: AccessEngine, signer: DecisionSigner
) -> None:
    d = decide(engine, camera())
    assert signer.verify(d)
    assert not signer.verify(replace(d, outcome=Outcome.ALLOW, door_id="garage"))
    assert not DecisionSigner(b"x" * 32).verify(d)


def test_tampered_outcome_fails_verification(
    engine: AccessEngine, signer: DecisionSigner
) -> None:
    denied = decide(engine, camera(member=MemberSnapshot(7, "revoked")))
    assert not signer.verify(replace(denied, outcome=Outcome.ALLOW))


def test_same_inputs_same_decision(engine: AccessEngine) -> None:
    a, b = decide(engine, camera()), decide(engine, camera())
    fields = ("outcome", "rule", "reason", "member_id", "permission_id")
    assert [getattr(a, f) for f in fields] == [getattr(b, f) for f in fields]


def test_short_signing_key_rejected() -> None:
    with pytest.raises(ValueError):
        DecisionSigner(b"short")


# --- admin review of a HOLD ----------------------------------------------------


def _hold(engine: AccessEngine, **camera_overrides: object) -> PendingHold:
    perm = permission(start_local=time(18), end_local=time(22))
    overrides = {"permissions": (perm,), **camera_overrides}
    d = decide(engine, camera(**overrides))
    assert d.outcome is Outcome.HOLD
    return PendingHold(decision=d, expires_at=NOW + timedelta(minutes=5))


def review(hold: PendingHold, **overrides: object) -> AccessRequest:
    base = AccessRequest(
        request_id="r2",
        door_id=DOOR,
        source=Source.ADMIN_REVIEW,
        now=NOW + timedelta(seconds=30),
        member=MemberSnapshot(7, "active"),
        permissions=(permission(start_local=time(18), end_local=time(22)),),
        approver_user_id=1,
        approver_is_active_admin=True,
        approved=True,
        hold=hold,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def test_admin_approval_allows_and_waives_only_the_window(
    engine: AccessEngine,
) -> None:
    d = decide(engine, review(_hold(engine)))
    assert (d.outcome, d.reason) == (Outcome.ALLOW, "admin_approved")
    assert d.review_of is not None and d.approver_user_id == 1


def test_admin_approval_cannot_bypass_lockdown(engine: AccessEngine) -> None:
    d = decide(engine, review(_hold(engine)), lockdown=True)
    assert d.reason == "lockdown_active"


def test_admin_approval_cannot_bypass_revocation(engine: AccessEngine) -> None:
    d = decide(engine, review(_hold(engine), member=MemberSnapshot(7, "revoked")))
    assert d.reason == "member_inactive"


def test_admin_approval_cannot_bypass_expired_permission(
    engine: AccessEngine,
) -> None:
    expired = permission(valid_to=NOW)
    d = decide(engine, review(_hold(engine), permissions=(expired,)))
    assert d.reason == "permission_expired"


def test_admin_approval_cannot_bypass_removed_permission(
    engine: AccessEngine,
) -> None:
    d = decide(engine, review(_hold(engine), permissions=()))
    assert d.reason == "no_permission"


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"approver_is_active_admin": False}, "approver_not_authorised"),
        ({"approver_user_id": None}, "approver_not_authorised"),
        ({"approved": False}, "admin_rejected"),
        ({"approved": None}, "admin_rejected"),
        ({"now": NOW + timedelta(minutes=6)}, "hold_expired"),
        ({"door_id": "garage"}, "no_valid_hold"),
    ],
)
def test_review_failures_deny(
    engine: AccessEngine, overrides: dict, reason: str
) -> None:
    d = decide(engine, review(_hold(engine), **overrides))
    assert (d.outcome, d.reason) == (Outcome.DENY, reason)


def test_resolved_hold_cannot_be_approved_twice(engine: AccessEngine) -> None:
    hold = replace(_hold(engine), resolved=True)
    assert decide(engine, review(hold)).reason == "hold_already_resolved"


def test_forged_hold_rejected(engine: AccessEngine) -> None:
    real = _hold(engine)
    forged = PendingHold(
        decision=replace(real.decision, decision_id="forged"),
        expires_at=real.expires_at,
    )
    assert decide(engine, review(forged)).reason == "no_valid_hold"


def test_cannot_review_a_non_hold_decision(engine: AccessEngine) -> None:
    deny = decide(engine, camera(member=MemberSnapshot(7, "revoked")))
    hold = PendingHold(decision=deny, expires_at=NOW + timedelta(minutes=5))
    assert decide(engine, review(hold)).reason == "no_valid_hold"


def test_unknown_visitor_hold_approval_is_single_guest_entry(
    engine: AccessEngine,
) -> None:
    unknown = MatchResult(
        MatchStatus.UNKNOWN, threshold=0.45, min_margin=0.05, score=0.1
    )
    d = decide(
        engine,
        camera(match=unknown, member=None),
        unknown_visitor_outcome=Outcome.HOLD,
    )
    hold = PendingHold(decision=d, expires_at=NOW + timedelta(minutes=5))
    approved = decide(engine, review(hold, member=None))
    assert (approved.outcome, approved.reason, approved.member_id) == (
        Outcome.ALLOW,
        "guest_entry_approved",
        None,
    )


# --- manual override -------------------------------------------------------------


def manual(**overrides: object) -> AccessRequest:
    base = AccessRequest(
        request_id="r3",
        door_id=DOOR,
        source=Source.MANUAL_OVERRIDE,
        now=NOW,
        approver_user_id=1,
        approver_is_active_admin=True,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def test_manual_override_by_admin_allows(engine: AccessEngine) -> None:
    assert decide(engine, manual()).reason == "manual_override"


def test_manual_override_blocked_by_lockdown(engine: AccessEngine) -> None:
    assert decide(engine, manual(), lockdown=True).outcome is Outcome.DENY


def test_manual_override_requires_active_admin(engine: AccessEngine) -> None:
    d = decide(engine, manual(approver_is_active_admin=False))
    assert d.reason == "approver_not_authorised"


# --- time windows ----------------------------------------------------------------


@pytest.mark.parametrize(
    "now,expected",
    [
        (datetime(2026, 11, 16, 9, 0, tzinfo=UTC), True),  # start, inclusive
        (datetime(2026, 11, 16, 17, 0, tzinfo=UTC), False),  # end, exclusive
        (datetime(2026, 11, 16, 8, 59, tzinfo=UTC), False),
    ],
)
def test_window_edges(now: datetime, expected: bool) -> None:
    perm = permission(start_local=time(9), end_local=time(17))
    assert in_time_window(perm, now) is expected


def test_weekday_restriction() -> None:
    perm = permission(days_of_week=frozenset({5, 6}))  # weekend only
    assert not in_time_window(perm, NOW)  # Monday


def test_overnight_window_belongs_to_start_day() -> None:
    perm = permission(
        start_local=time(22), end_local=time(6), days_of_week=frozenset({4})
    )  # Friday 22:00 - Saturday 06:00
    friday_late = datetime(2026, 11, 20, 23, 0, tzinfo=UTC)
    saturday_early = datetime(2026, 11, 21, 5, 0, tzinfo=UTC)
    saturday_late = datetime(2026, 11, 21, 23, 0, tzinfo=UTC)
    assert in_time_window(perm, friday_late)
    assert in_time_window(perm, saturday_early)
    assert not in_time_window(perm, saturday_late)


def test_window_uses_household_timezone() -> None:
    perm = permission(start_local=time(9), end_local=time(17), timezone="Asia/Kolkata")
    # 10:00 UTC is 15:30 in India: inside. 12:00 UTC is 17:30: outside.
    assert in_time_window(perm, datetime(2026, 11, 16, 10, 0, tzinfo=UTC))
    assert not in_time_window(perm, datetime(2026, 11, 16, 12, 0, tzinfo=UTC))


def test_window_across_dst_change_is_exact() -> None:
    perm = permission(start_local=time(9), end_local=time(17), timezone="Europe/London")
    # 2026-03-29: London moves to BST (UTC+1). 08:30 UTC = 09:30 local.
    assert in_time_window(perm, datetime(2026, 3, 29, 8, 30, tzinfo=UTC))
    assert not in_time_window(perm, datetime(2026, 3, 29, 7, 30, tzinfo=UTC))


def test_empty_window_never_matches() -> None:
    perm = permission(start_local=time(9), end_local=time(9))
    assert not in_time_window(perm, datetime(2026, 11, 16, 9, 0, tzinfo=UTC))
