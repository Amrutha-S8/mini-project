"""Cross-Modal Attack Chain Reconstruction (Day 8 core, stdlib only).

Groups suspicious security events from different layers (face recognition,
access decisions, door, authentication, API, admin changes, AI agents) into
explainable incidents with an ordered timeline and the evidence for every
link.

Defensive and read-only. It never decides access and has no reference to the
door or the AccessEngine; its strongest output is a *recommendation* (for
example "consider lockdown") and a notify flag, which a human or the
deterministic core acts on.

Wording is deliberately cautious: the module reports correlation and what was
blocked or allowed. It never states intent, and it never states that an
attack succeeded; when an allowed action follows suspicious activity, it says
exactly that and nothing more.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum

from app.domain.events import Modality, SecurityEvent, Severity

#: Identifiers specific to one interaction: equal values link any two events.
SPECIFIC_KEYS = (
    "correlation_id",
    "request_id",
    "decision_id",
    "session_id",
    "visitor_key",
)
#: Broad identifiers (one household IP serves every family device): they only
#: link events when at least one of the two is suspicious.
BROAD_KEYS = ("ip_address", "user_id")

#: Allowed / successful actions worth highlighting after suspicious activity.
SUCCESS_TYPES = frozenset(
    {
        "access.allowed",
        "access.hold_approved",
        "door.unlocked",
        "auth.login_succeeded",
        "admin.permission_changed",
        "admin.enrollment_changed",
    }
)


class Stage(StrEnum):
    PROBE = "probe"
    ESCALATION = "escalation"
    ALLOWED_ACTION = "allowed_action"
    DEFENSIVE_RESPONSE = "defensive_response"
    CONTEXT = "context"


_STAGE_BY_TYPE = {
    "face.unknown_visitor": Stage.PROBE,
    "face.uncertain_match": Stage.PROBE,
    "access.denied": Stage.PROBE,
    "auth.login_failed": Stage.PROBE,
    "api.unauthorized": Stage.PROBE,
    "auth.login_throttled": Stage.ESCALATION,
    "auth.token_reuse": Stage.ESCALATION,
    "api.forbidden": Stage.ESCALATION,
    "admin.permission_change_denied": Stage.ESCALATION,
    "ai.policy_violation": Stage.ESCALATION,
    "ai.tool_denied": Stage.ESCALATION,
    "door.unlock_rejected": Stage.ESCALATION,
    "face.liveness_failed": Stage.ESCALATION,
    "door.lockdown_entered": Stage.DEFENSIVE_RESPONSE,
}


@dataclass(frozen=True)
class Link:
    a: str
    b: str
    kind: str  # "shared_key" | "temporal"
    key: str | None
    explanation: str


@dataclass(frozen=True)
class TimelineStep:
    at: datetime
    event_id: str
    event_type: str
    modality: Modality
    stage: Stage
    outcome: str
    severity: Severity
    evidence_ref: str | None


@dataclass(frozen=True)
class Gap:
    start: datetime
    end: datetime


@dataclass(frozen=True)
class Incident:
    incident_id: str
    started_at: datetime
    ended_at: datetime
    severity: Severity
    modalities: frozenset[Modality]
    timeline: tuple[TimelineStep, ...]
    links: tuple[Link, ...]
    blocked_count: int
    allowed_after_suspicious: tuple[str, ...]
    gaps: tuple[Gap, ...]
    summary: str
    recommendations: tuple[str, ...]
    notify: bool
    evidence_refs: tuple[str, ...] = field(default=())

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(s.event_id for s in self.timeline)


@dataclass(frozen=True)
class CorrelationConfig:
    window: timedelta = timedelta(minutes=15)
    temporal_window: timedelta = timedelta(minutes=2)
    min_suspicious: int = 2
    gap: timedelta = timedelta(minutes=5)
    notify_at: Severity = Severity.HIGH


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def reconstruct(
    events: Sequence[SecurityEvent], config: CorrelationConfig | None = None
) -> list[Incident]:
    """Correlate events into incidents. Deterministic for the same input."""
    cfg = config or CorrelationConfig()
    ordered = sorted(events, key=lambda e: (e.occurred_at, e.event_id))
    n = len(ordered)
    uf = _UnionFind(n)
    links: list[tuple[int, int, Link]] = []

    for i in range(n):
        ei = ordered[i]
        for j in range(i + 1, n):
            ej = ordered[j]
            if ej.occurred_at - ei.occurred_at > cfg.window:
                break
            shared = _shared_key(ei, ej, allow_broad=ei.suspicious or ej.suspicious)
            if shared is not None:
                uf.union(i, j)
                links.append(
                    (
                        i,
                        j,
                        Link(
                            ei.event_id,
                            ej.event_id,
                            "shared_key",
                            shared,
                            f"both events carry the same {shared}",
                        ),
                    )
                )
            elif (
                ei.suspicious
                and ej.suspicious
                and ei.modality != ej.modality
                and ej.occurred_at - ei.occurred_at <= cfg.temporal_window
            ):
                uf.union(i, j)
                gap = int((ej.occurred_at - ei.occurred_at).total_seconds())
                links.append(
                    (
                        i,
                        j,
                        Link(
                            ei.event_id,
                            ej.event_id,
                            "temporal",
                            None,
                            f"suspicious {ei.modality.value} and {ej.modality.value} "
                            f"events {gap}s apart with no shared identifier; "
                            "timing only, lower confidence",
                        ),
                    )
                )

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    incidents = []
    for members in groups.values():
        group = [ordered[i] for i in members]
        if sum(1 for e in group if e.suspicious) < cfg.min_suspicious:
            continue
        member_set = set(members)
        group_links = tuple(
            link for a, b, link in links if a in member_set and b in member_set
        )
        incidents.append(_build(group, group_links, cfg))
    incidents.sort(key=lambda inc: (inc.started_at, inc.incident_id))
    return incidents


def _shared_key(a: SecurityEvent, b: SecurityEvent, *, allow_broad: bool) -> str | None:
    keys = SPECIFIC_KEYS + BROAD_KEYS if allow_broad else SPECIFIC_KEYS
    for key in keys:
        va, vb = getattr(a, key), getattr(b, key)
        if va is not None and va == vb:
            return key
    return None


def _build(
    group: list[SecurityEvent], links: tuple[Link, ...], cfg: CorrelationConfig
) -> Incident:
    timeline = tuple(
        TimelineStep(
            at=e.occurred_at,
            event_id=e.event_id,
            event_type=e.event_type,
            modality=e.modality,
            stage=_stage(e),
            outcome=e.outcome,
            severity=e.severity,
            evidence_ref=e.evidence_ref,
        )
        for e in group
    )
    first_suspicious = next(e.occurred_at for e in group if e.suspicious)
    allowed_after = tuple(
        e.event_id
        for e in group
        if e.event_type in SUCCESS_TYPES
        and e.outcome != "blocked"
        and e.occurred_at > first_suspicious
    )
    timeline = tuple(
        replace(s, stage=Stage.ALLOWED_ACTION) if s.event_id in allowed_after else s
        for s in timeline
    )
    modalities = frozenset(e.modality for e in group)
    suspicious_modalities = frozenset(e.modality for e in group if e.suspicious)
    blocked = sum(1 for e in group if e.outcome == "blocked")

    severity = max(e.severity for e in group)
    if len(suspicious_modalities) >= 2:
        severity = Severity(min(Severity.CRITICAL, severity + 1))
    if allowed_after:
        severity = Severity(min(Severity.CRITICAL, severity + 1))

    gaps = tuple(
        Gap(a.occurred_at, b.occurred_at)
        for a, b in zip(group, group[1:], strict=False)
        if b.occurred_at - a.occurred_at > cfg.gap
    )
    digest = hashlib.sha256(
        "|".join(sorted(e.event_id for e in group)).encode()
    ).hexdigest()[:16]

    return Incident(
        incident_id=f"inc-{digest}",
        started_at=group[0].occurred_at,
        ended_at=group[-1].occurred_at,
        severity=severity,
        modalities=modalities,
        timeline=timeline,
        links=links,
        blocked_count=blocked,
        allowed_after_suspicious=allowed_after,
        gaps=gaps,
        summary=_summary(group, suspicious_modalities, blocked, allowed_after, links),
        recommendations=_recommendations(group, allowed_after, severity),
        notify=severity >= cfg.notify_at,
        evidence_refs=tuple(e.evidence_ref for e in group if e.evidence_ref),
    )


def _stage(event: SecurityEvent) -> Stage:
    return _STAGE_BY_TYPE.get(event.event_type, Stage.CONTEXT)


def _summary(
    group: list[SecurityEvent],
    suspicious_modalities: frozenset[Modality],
    blocked: int,
    allowed_after: tuple[str, ...],
    links: tuple[Link, ...],
) -> str:
    span = int((group[-1].occurred_at - group[0].occurred_at).total_seconds())
    layers = ", ".join(sorted(m.value for m in suspicious_modalities))
    temporal = sum(1 for link in links if link.kind == "temporal")
    parts = [
        f"{len(group)} related events over {span}s involving suspicious activity "
        f"in: {layers}.",
        f"{blocked} action(s) were blocked.",
    ]
    if allowed_after:
        parts.append(
            f"{len(allowed_after)} allowed action(s) occurred after the first "
            "suspicious event. This is a correlation for review; it does not "
            "establish that the allowed action was malicious."
        )
    else:
        parts.append("No allowed action followed the suspicious activity.")
    if temporal:
        parts.append(
            f"{temporal} link(s) are based on timing alone and may be coincidental."
        )
    return " ".join(parts)


def _recommendations(
    group: list[SecurityEvent], allowed_after: tuple[str, ...], severity: Severity
) -> tuple[str, ...]:
    types = {e.event_type for e in group}
    recs: list[str] = []
    if allowed_after:
        recs.append(
            "Review the allowed action(s) and the decision records they reference."
        )
    if types & {"auth.login_failed", "auth.login_throttled", "auth.token_reuse"}:
        recs.append(
            "Review operator sessions; revoke any you do not recognise and "
            "rotate passwords if in doubt."
        )
    if "admin.permission_change_denied" in types or "api.forbidden" in types:
        recs.append(
            "Review recent permission changes and which account attempted them."
        )
    if types & {"ai.policy_violation", "ai.tool_denied"}:
        recs.append("Review the AI agent execution log for the blocked tool calls.")
    if types & {"face.unknown_visitor", "face.uncertain_match", "face.liveness_failed"}:
        recs.append("Review the visitor evidence captured at the door.")
    if "door.unlock_rejected" in types:
        recs.append(
            "Investigate the rejected unlock: it indicates a forged, replayed "
            "or stale decision."
        )
    if severity >= Severity.HIGH and "door.lockdown_entered" not in types:
        recs.append(
            "Consider enabling lockdown until the incident is reviewed "
            "(deny-side, safe)."
        )
    return tuple(recs)
