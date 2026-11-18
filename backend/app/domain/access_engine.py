"""AccessEngine (module M08): the sole access decision authority.

Pure, synchronous, deterministic Python. No network, no database, no AI
imports (enforced by tests/test_import_boundary.py). The caller gathers the
facts (match result, member, permissions, policy, time) and the engine applies
ordered rules; the first rule that fires decides.

Outcomes (DD-01):
    ALLOW  the virtual door may unlock for its time-bounded TTL
    DENY   the door stays locked
    HOLD   the door stays locked and an admin is asked to review

Every decision is HMAC-signed so the virtual door can reject anything the
engine did not issue. Any unexpected error resolves to DENY (fail secure).
An admin approval is a new request that goes through these same rules, so it
cannot bypass a lockdown, a revoked member or an expired permission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, time, timedelta
from enum import IntEnum, StrEnum
from typing import Any
from zoneinfo import ZoneInfo

from app.domain.face_matching import MatchResult, MatchStatus

ENGINE_VERSION = "1.0.0"


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"


class Source(StrEnum):
    CAMERA = "camera"
    ADMIN_REVIEW = "admin_review"
    MANUAL_OVERRIDE = "manual_override"


class Rule(IntEnum):
    ENGINE_ERROR = 0
    LOCKDOWN = 1
    UNUSABLE_INPUT = 2
    IDENTITY = 3
    MEMBER_STATUS = 4
    NO_PERMISSION = 5
    PERMISSION_VALIDITY = 6
    TIME_WINDOW = 7
    RATE_LIMIT = 8
    GRANT = 9
    APPROVER = 10
    HOLD_STATE = 11


ACTIVE = "active"


# --- inputs ------------------------------------------------------------------


@dataclass(frozen=True)
class MemberSnapshot:
    member_id: int
    status: str  # "active" | "inactive" | "revoked"


@dataclass(frozen=True)
class PermissionSnapshot:
    permission_id: int
    member_id: int
    door_id: str
    is_active: bool = True
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    #: 0 = Monday ... 6 = Sunday. None means every day.
    days_of_week: frozenset[int] | None = None
    start_local: time | None = None
    end_local: time | None = None  # exclusive; None = end of day
    timezone: str = "UTC"


@dataclass(frozen=True)
class Policy:
    lockdown: bool = False
    match_threshold: float = 0.45
    min_margin: float = 0.05
    #: Scores within this distance below the threshold are HOLD, not DENY.
    hold_band: float = 0.05
    unknown_visitor_outcome: Outcome = Outcome.DENY
    outside_window_outcome: Outcome = Outcome.HOLD
    attempt_limit: int = 5

    def __post_init__(self) -> None:
        if not 0.0 < self.match_threshold <= 1.0:
            raise ValueError("match_threshold must be in (0, 1]")
        if not 0.0 <= self.hold_band < self.match_threshold:
            raise ValueError("hold_band must be >= 0 and below the threshold")
        if not 0.0 <= self.min_margin < 1.0:
            raise ValueError("min_margin must be in [0, 1)")
        if self.unknown_visitor_outcome is Outcome.ALLOW:
            raise ValueError("unknown visitors can never be allowed by policy")
        if self.outside_window_outcome is Outcome.ALLOW:
            raise ValueError("outside-window attempts can never be allowed by policy")
        if self.attempt_limit < 1:
            raise ValueError("attempt_limit must be positive")


@dataclass(frozen=True)
class AccessRequest:
    request_id: str
    door_id: str
    source: Source
    now: datetime
    match: MatchResult | None = None
    member: MemberSnapshot | None = None
    permissions: tuple[PermissionSnapshot, ...] = ()
    recent_attempts: int = 0
    approver_user_id: int | None = None
    approver_is_active_admin: bool = False
    approved: bool | None = None
    hold: PendingHold | None = None


# --- output ------------------------------------------------------------------


@dataclass(frozen=True)
class AccessDecision:
    decision_id: str
    request_id: str
    door_id: str
    source: Source
    outcome: Outcome
    rule: Rule
    reason: str
    decided_at: datetime
    engine_version: str
    member_id: int | None = None
    permission_id: int | None = None
    match_score: float | None = None
    threshold: float | None = None
    review_of: str | None = None
    approver_user_id: int | None = None
    signature: str = field(default="", compare=False)

    @property
    def rule_name(self) -> str:
        return self.rule.name.lower()

    def canonical(self) -> bytes:
        """Deterministic bytes covering every field except the signature."""
        data: dict[str, Any] = asdict(self)
        data.pop("signature")
        data["rule"] = int(self.rule)
        data["decided_at"] = self.decided_at.isoformat()
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class PendingHold:
    """A HOLD awaiting admin review.

    ``decision`` must be the signed HOLD exactly as the engine issued it; the
    engine verifies the signature, so a caller cannot fabricate a HOLD to
    approve. ``resolved`` is tracked by the caller (persisted state) so one
    HOLD can be approved at most once.
    """

    decision: AccessDecision
    expires_at: datetime
    resolved: bool = False


class DecisionSigner:
    """HMAC-SHA256 over a decision. Shared by the engine and the door only."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else secrets.token_bytes(32)
        if len(self._key) < 32:
            raise ValueError("signing key must be at least 32 bytes")

    def sign(self, decision: AccessDecision) -> AccessDecision:
        mac = hmac.new(self._key, decision.canonical(), hashlib.sha256).hexdigest()
        return replace(decision, signature=mac)

    def verify(self, decision: AccessDecision) -> bool:
        expected = hmac.new(self._key, decision.canonical(), hashlib.sha256)
        return hmac.compare_digest(expected.hexdigest(), decision.signature)


# --- engine ------------------------------------------------------------------


class AccessEngine:
    def __init__(self, signer: DecisionSigner) -> None:
        self._signer = signer

    def decide(self, request: AccessRequest, policy: Policy) -> AccessDecision:
        """Apply the rules. Never raises: any error becomes DENY engine_error."""
        try:
            _require_aware(request.now)
            if request.source is Source.CAMERA:
                verdict = self._camera(request, policy)
            elif request.source is Source.ADMIN_REVIEW:
                verdict = self._review(request, policy)
            elif request.source is Source.MANUAL_OVERRIDE:
                verdict = self._manual(request, policy)
            else:  # pragma: no cover - exhaustive over Source
                raise ValueError("unknown source")
        except Exception:
            verdict = _Verdict(Outcome.DENY, Rule.ENGINE_ERROR, "engine_error")
        return self._issue(request, verdict, policy)

    # --- camera attempts ----------------------------------------------------

    def _camera(self, req: AccessRequest, policy: Policy) -> _Verdict:
        if policy.lockdown:
            return _Verdict(Outcome.DENY, Rule.LOCKDOWN, "lockdown_active")
        match = req.match
        if match is None or match.status is MatchStatus.NO_FACE:
            return _Verdict(Outcome.DENY, Rule.UNUSABLE_INPUT, "no_face")
        if match.status is MatchStatus.MULTIPLE_FACES:
            return _Verdict(Outcome.HOLD, Rule.UNUSABLE_INPUT, "multiple_faces")
        if match.status is MatchStatus.POOR_QUALITY:
            return _Verdict(Outcome.HOLD, Rule.UNUSABLE_INPUT, "poor_quality")
        if match.status is MatchStatus.AMBIGUOUS:
            return _Verdict(Outcome.HOLD, Rule.IDENTITY, "ambiguous_match")

        # Independent re-check: the engine's own threshold, not the matcher's.
        score = match.score
        matched = (
            match.status is MatchStatus.MATCHED
            and match.member_id is not None
            and score is not None
            and score >= policy.match_threshold
        )
        if not matched:
            if score is not None and score >= policy.match_threshold - policy.hold_band:
                return _Verdict(Outcome.HOLD, Rule.IDENTITY, "uncertain_match")
            return _Verdict(
                policy.unknown_visitor_outcome, Rule.IDENTITY, "unknown_identity"
            )

        member = req.member
        if member is None or member.member_id != match.member_id:
            return _Verdict(Outcome.DENY, Rule.MEMBER_STATUS, "member_not_found")
        if member.status != ACTIVE:
            return _Verdict(Outcome.DENY, Rule.MEMBER_STATUS, "member_inactive")

        permission, verdict = _check_permissions(req, member, check_window=True)
        if verdict is not None:
            if verdict.reason == "outside_time_window":
                return replace(verdict, outcome=policy.outside_window_outcome)
            return verdict
        if req.recent_attempts >= policy.attempt_limit:
            return _Verdict(Outcome.DENY, Rule.RATE_LIMIT, "rate_limited")
        assert permission is not None
        return _Verdict(
            Outcome.ALLOW,
            Rule.GRANT,
            "permission_satisfied",
            permission_id=permission.permission_id,
        )

    # --- admin review of a HOLD ---------------------------------------------

    def _review(self, req: AccessRequest, policy: Policy) -> _Verdict:
        if policy.lockdown:
            return _Verdict(Outcome.DENY, Rule.LOCKDOWN, "lockdown_active")
        if req.approver_user_id is None or not req.approver_is_active_admin:
            return _Verdict(Outcome.DENY, Rule.APPROVER, "approver_not_authorised")
        hold = req.hold
        if (
            hold is None
            or not self._signer.verify(hold.decision)
            or hold.decision.outcome is not Outcome.HOLD
            or hold.decision.door_id != req.door_id
        ):
            return _Verdict(Outcome.DENY, Rule.HOLD_STATE, "no_valid_hold")
        if hold.resolved:
            return _Verdict(Outcome.DENY, Rule.HOLD_STATE, "hold_already_resolved")
        _require_aware(hold.expires_at)
        if req.now >= hold.expires_at:
            return _Verdict(Outcome.DENY, Rule.HOLD_STATE, "hold_expired")
        if req.approved is not True:
            return _Verdict(Outcome.DENY, Rule.HOLD_STATE, "admin_rejected")
        hold_member = hold.decision.member_id
        if hold_member is None:
            # Unknown or unconfirmed face: one admin-approved entry only.
            # Nothing is enrolled; the visitor stays anonymous.
            return _Verdict(Outcome.ALLOW, Rule.GRANT, "guest_entry_approved")
        member = req.member
        if member is None or member.member_id != hold_member:
            return _Verdict(Outcome.DENY, Rule.MEMBER_STATUS, "member_not_found")
        if member.status != ACTIVE:
            return _Verdict(Outcome.DENY, Rule.MEMBER_STATUS, "member_inactive")
        # The admin's approval waives the time window, nothing else.
        permission, verdict = _check_permissions(req, member, check_window=False)
        if verdict is not None:
            return verdict
        assert permission is not None
        return _Verdict(
            Outcome.ALLOW,
            Rule.GRANT,
            "admin_approved",
            permission_id=permission.permission_id,
        )

    # --- authenticated manual control ---------------------------------------

    def _manual(self, req: AccessRequest, policy: Policy) -> _Verdict:
        if policy.lockdown:
            return _Verdict(Outcome.DENY, Rule.LOCKDOWN, "lockdown_active")
        if req.approver_user_id is None or not req.approver_is_active_admin:
            return _Verdict(Outcome.DENY, Rule.APPROVER, "approver_not_authorised")
        return _Verdict(Outcome.ALLOW, Rule.GRANT, "manual_override")

    # --- issue ----------------------------------------------------------------

    def _issue(
        self, req: AccessRequest, verdict: _Verdict, policy: Policy
    ) -> AccessDecision:
        match = req.match if isinstance(req.match, MatchResult) else None
        member_id: int | None = None
        if req.source is Source.CAMERA and match is not None:
            member_id = match.member_id
        elif req.source is Source.ADMIN_REVIEW and isinstance(req.hold, PendingHold):
            member_id = req.hold.decision.member_id
        decided_at = req.now if _is_aware(req.now) else _EPOCH
        decision = AccessDecision(
            decision_id=uuid.uuid4().hex,
            request_id=str(req.request_id),
            door_id=str(req.door_id),
            source=req.source if isinstance(req.source, Source) else Source.CAMERA,
            outcome=verdict.outcome,
            rule=verdict.rule,
            reason=verdict.reason,
            decided_at=decided_at,
            engine_version=ENGINE_VERSION,
            member_id=member_id,
            permission_id=verdict.permission_id,
            match_score=match.score if match is not None else None,
            threshold=policy.match_threshold,
            review_of=(
                req.hold.decision.decision_id
                if isinstance(req.hold, PendingHold)
                else None
            ),
            approver_user_id=req.approver_user_id,
        )
        return self._signer.sign(decision)


# --- helpers -------------------------------------------------------------------


@dataclass(frozen=True)
class _Verdict:
    outcome: Outcome
    rule: Rule
    reason: str
    permission_id: int | None = None


_EPOCH = datetime(1970, 1, 1).astimezone(ZoneInfo("UTC"))


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _require_aware(value: datetime) -> None:
    if not _is_aware(value):
        raise ValueError("decision time must be timezone-aware")


def _check_permissions(
    req: AccessRequest, member: MemberSnapshot, *, check_window: bool
) -> tuple[PermissionSnapshot | None, _Verdict | None]:
    """First permission satisfying every check, or the most specific failure."""
    candidates = [
        p
        for p in req.permissions
        if p.is_active and p.member_id == member.member_id and p.door_id == req.door_id
    ]
    if not candidates:
        return None, _Verdict(Outcome.DENY, Rule.NO_PERMISSION, "no_permission")
    valid = [p for p in candidates if _within_validity(p, req.now)]
    if not valid:
        return None, _Verdict(
            Outcome.DENY, Rule.PERMISSION_VALIDITY, "permission_expired"
        )
    if not check_window:
        return valid[0], None
    for permission in valid:
        if in_time_window(permission, req.now):
            return permission, None
    return None, _Verdict(Outcome.HOLD, Rule.TIME_WINDOW, "outside_time_window")


def _within_validity(p: PermissionSnapshot, now: datetime) -> bool:
    if p.valid_from is not None:
        _require_aware(p.valid_from)
        if now < p.valid_from:
            return False
    if p.valid_to is not None:
        _require_aware(p.valid_to)
        if now >= p.valid_to:
            return False
    return True


def in_time_window(p: PermissionSnapshot, now: datetime) -> bool:
    """Is ``now`` inside the permission's local weekly window?

    Converting from an aware UTC instant to local time is unambiguous, so DST
    transitions cannot widen a window. Overnight windows (start > end) belong
    to the day on which they start.
    """
    local = now.astimezone(ZoneInfo(p.timezone))
    t = local.time().replace(tzinfo=None)
    start = p.start_local or time.min
    days = p.days_of_week

    def day_ok(weekday: int) -> bool:
        return days is None or weekday in days

    if p.end_local is None or start < p.end_local:
        before_end = p.end_local is None or t < p.end_local
        return day_ok(local.weekday()) and start <= t and before_end
    if start == p.end_local:
        return False  # empty window
    # Overnight: [start, 24:00) today or [00:00, end) belonging to yesterday.
    if t >= start:
        return day_ok(local.weekday())
    if t < p.end_local:
        return day_ok((local - timedelta(days=1)).weekday())
    return False


def evaluate_all(
    engine: AccessEngine, requests: Sequence[AccessRequest], policy: Policy
) -> list[AccessDecision]:
    """Convenience for batch replay and tests."""
    return [engine.decide(r, policy) for r in requests]
