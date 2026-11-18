"""Deterministic escalation recommendations (Notification Recommendation Agent).

Given an incident reconstructed by the deterministic M15 core, decide whether
to *recommend* escalating it to the homeowner, and whether to *recommend*
lockdown. The result is advisory data only:

* ``requires_approval`` is always True and ``executes_actions`` always False;
* nothing here sends a message, changes a setting or touches the door;
* the LLM is never asked to make this call. A future agent may explain the
  result in words, but cannot change it.

Rules, first match sets the level, and each rule adds its reason:

| Condition                                                    | Level     |
|--------------------------------------------------------------|-----------|
| an allowed action followed suspicious activity               | escalate  |
| a high-risk signal (rejected unlock, liveness failure, token |           |
| reuse, AI policy violation)                                  | escalate  |
| severity HIGH or CRITICAL, or M15 set ``notify``             | escalate  |
| severity MEDIUM with suspicious activity in 2+ layers        | escalate  |
| severity MEDIUM or LOW                                       | monitor   |
| severity INFO                                                | no_action |

Lockdown is recommended when the level is ``escalate`` and either severity is
CRITICAL or an allowed door/access action followed suspicious activity, and
the incident does not already include lockdown.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.domain.attack_chain import Incident, Stage
from app.domain.events import Severity

HIGH_RISK_TYPES = frozenset(
    {
        "door.unlock_rejected",
        "face.liveness_failed",
        "auth.token_reuse",
        "ai.policy_violation",
    }
)
_ENTRY_TYPES = frozenset({"access.allowed", "access.hold_approved", "door.unlocked"})


class Level(StrEnum):
    ESCALATE = "escalate"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


@dataclass(frozen=True)
class EscalationRecommendation:
    incident_id: str
    level: Level
    recommend_notify_homeowner: bool
    recommend_lockdown: bool
    reasons: tuple[str, ...]
    requires_approval: bool = True
    executes_actions: bool = False


def recommend(incident: Incident) -> EscalationRecommendation:
    reasons: list[str] = []
    types = {step.event_type for step in incident.timeline}
    suspicious_layers = {
        step.modality
        for step in incident.timeline
        if step.stage in (Stage.PROBE, Stage.ESCALATION)
    }
    level: Level | None = None

    if incident.allowed_after_suspicious:
        level = Level.ESCALATE
        reasons.append(
            f"{len(incident.allowed_after_suspicious)} allowed action(s) followed "
            "suspicious activity"
        )
    risky = sorted(types & HIGH_RISK_TYPES)
    if risky:
        level = Level.ESCALATE
        reasons.append("high-risk signal(s): " + ", ".join(risky))
    if incident.severity >= Severity.HIGH:
        level = Level.ESCALATE
        reasons.append(f"severity {incident.severity.name.lower()}")
    if incident.notify:
        level = Level.ESCALATE
        reasons.append("the deterministic reconstruction set the notify flag")
    if level is None and incident.severity == Severity.MEDIUM:
        if len(suspicious_layers) >= 2:
            level = Level.ESCALATE
            layers = ", ".join(sorted(m.value for m in suspicious_layers))
            reasons.append(f"medium severity across layers: {layers}")
        else:
            level = Level.MONITOR
            reasons.append("medium severity in one layer")
    if level is None:
        if incident.severity >= Severity.LOW:
            level = Level.MONITOR
            reasons.append("low severity")
        else:
            level = Level.NO_ACTION
            reasons.append("informational only")

    already_locked = "door.lockdown_entered" in types
    entry_after = any(
        step.event_id in incident.allowed_after_suspicious
        and step.event_type in _ENTRY_TYPES
        for step in incident.timeline
    )
    lockdown = (
        level is Level.ESCALATE
        and not already_locked
        and (incident.severity == Severity.CRITICAL or entry_after)
    )
    if lockdown:
        reasons.append(
            "lockdown recommended for human review (deny-side); not executed"
        )
    elif already_locked:
        reasons.append("lockdown is already recorded in this incident")

    return EscalationRecommendation(
        incident_id=incident.incident_id,
        level=level,
        recommend_notify_homeowner=level is Level.ESCALATE,
        recommend_lockdown=lockdown,
        reasons=tuple(reasons),
    )
