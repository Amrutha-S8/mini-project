"""Supervisor routing: which specialised agent handles a question (deterministic).

Routing is rules, not a model, so it cannot be talked into a different
route. In order:

1. **Validate** the question (non-empty, bounded length).
2. **Refuse actions.** A request to unlock, open, start or stop lockdown,
   change permissions, approve or enrol visitors, or delete records is
   refused with a fixed message. The AI can only recommend.
3. **Refuse decisions.** "Should I let them in?" is refused: the
   AccessEngine alone decides ALLOW, DENY or HOLD.
4. **Score intents** by keywords; up to two agents may be combined.
5. **Apply the role allowlist.** A route the caller may not use is denied
   with a reason and is never run.

Only ``general_knowledge`` may ever use Gemini, and only with content the
privacy policy approves (documentation and public policies). Every other
route works on household data and is answered locally.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from app.ai.core.sensitive import normalise
from app.ai.core.types import Role, UserContext

MAX_QUESTION_CHARS = 2_000
MAX_ROUTES = 2


class Route(StrEnum):
    SECURITY_MONITORING = "security_monitoring"
    INCIDENT_ANALYSIS = "incident_analysis"
    VISITOR_HISTORY = "visitor_history"
    SECURITY_REPORT = "security_report"
    NOTIFICATION_RECOMMENDATION = "notification_recommendation"
    GENERAL_KNOWLEDGE = "general_knowledge"


class Refusal(StrEnum):
    INVALID_QUESTION = "invalid_question"
    SECURITY_ACTION = "security_action"
    ACCESS_DECISION = "access_decision"
    NOT_AUTHORISED = "not_authorised"


ROUTE_ROLES: Mapping[Route, frozenset[Role]] = {
    Route.SECURITY_MONITORING: frozenset({Role.ADMIN}),
    Route.INCIDENT_ANALYSIS: frozenset({Role.ADMIN, Role.VIEWER}),
    Route.VISITOR_HISTORY: frozenset({Role.ADMIN}),
    Route.SECURITY_REPORT: frozenset({Role.ADMIN, Role.VIEWER}),
    Route.NOTIFICATION_RECOMMENDATION: frozenset({Role.ADMIN}),
    Route.GENERAL_KNOWLEDGE: frozenset({Role.ADMIN, Role.VIEWER, Role.MEMBER}),
}
#: The only route that may call Gemini (owner privacy policy, Phase 1).
GEMINI_ELIGIBLE_ROUTES = frozenset({Route.GENERAL_KNOWLEDGE})

REFUSAL_MESSAGES: Mapping[Refusal, str] = {
    Refusal.INVALID_QUESTION: "Please ask a question of up to 2,000 characters.",
    Refusal.SECURITY_ACTION: (
        "I can't do that. The assistant is advisory only: it cannot unlock "
        "doors, change lockdown, change permissions, or approve or enrol "
        "visitors. An admin can do these from the authenticated controls, and "
        "every access decision still goes through the AccessEngine."
    ),
    Refusal.ACCESS_DECISION: (
        "I can't make access decisions. The AccessEngine alone decides ALLOW, "
        "DENY or HOLD, and an admin reviews any HOLD. I can explain past "
        "decisions or summarise the evidence instead."
    ),
    Refusal.NOT_AUTHORISED: ("Your account does not have access to that information."),
}

_POLITE = (
    r"(?:please\s+|kindly\s+|now\s+|immediately\s+|just\s+|"
    r"(?:can|could|would|will)\s+you\s+(?:please\s+)?|"
    r"i\s+(?:want|need)\s+you\s+to\s+|go\s+ahead\s+and\s+|"
    r"you\s+(?:must|should|need\s+to)\s+)"
)
#: An imperative: start of a sentence or clause, optionally after politeness.
#: "How do I unlock the door?" is a question, not an imperative, and is
#: answered as documentation.
_IMPERATIVE = rf"(?:^|[.!?;,]\s*|\band\s+)(?:hey\s+|ok\s+|assistant\s+)?{_POLITE}*"
_ACTION_SHAPES: tuple[tuple[str, str], ...] = (
    (r"(?:unlock|open|close|lock)", r"(?:door|gate|lock|garage|entrance)"),
    (
        r"(?:start|begin|enable|activate|trigger|initiate|enter|put|end|stop|"
        r"cancel|lift|release|disable|override|bypass|exit|turn\s+(?:on|off))",
        r"lockdown",
    ),
    (
        r"(?:grant|give|revoke|remove|change|modify|edit|extend|reset|update|set|"
        r"add|raise|lower)",
        r"(?:permissions?|access|roles?|admin|rights|schedule|threshold|polic(?:y|ies)|"
        r"retention)",
    ),
    (
        r"(?:approve|accept|enrol+|register|whitelist|add|trust|admit|allow)",
        r"(?:visitors?|guests?|faces?|person|people|strangers?|them|him|her|"
        r"members?|users?)",
    ),
    (
        r"(?:delete|erase|purge|wipe|remove|edit|alter|clear|rewrite)",
        r"(?:records?|logs?|events?|evidence|history|incidents?|footage|snapshots?)",
    ),
    (
        r"(?:disable|deactivate|stop|pause|turn\s+off|switch\s+off|mute)",
        r"(?:cameras?|alarms?|monitoring|recording|sensors?|notifications?)",
    ),
)
_ACTION_REQUEST = re.compile(
    "|".join(
        rf"{_IMPERATIVE}{verb}\b[^.?!]{{0,40}}?\b{obj}\b"
        for verb, obj in _ACTION_SHAPES
    )
    + rf"|{_IMPERATIVE}(?:let|admit)\s+(?:\w+\s+){{1,3}}in\b"
)
_DECISION_REQUEST = re.compile(
    r"\bshould\s+(?:i|we|you)\s+(?:let|allow|admit|deny|open|unlock|grant|hold)\b"
    r"|\b(?:allow|deny|hold)\s+(?:or\s+(?:allow|deny|hold)\s+)?"
    r"(?:this|that|the)\s+(?:visitor|person|attempt|request|entry|guest)\b"
    r"|\b(?:decide|determine)\b[^.?!]{0,40}\b(?:access|entry|allowed|let\s+in)\b"
    r"|\b(?:is|are)\s+(?:they|he|she|this\s+person|this\s+visitor|the\s+visitor)\s+"
    r"(?:allowed|authori[sz]ed|safe|ok|okay)\s+to\s+(?:enter|come\s+in|be\s+let\s+in)\b"
    r"|\b(?:would|will)\s+(?:the\s+)?(?:engine|system|door)\s+(?:allow|deny|let)\b"
)

_DOCUMENTATION_QUESTION = re.compile(
    r"\b(?:polic(?:y|ies)|documentation|docs|design\s+decisions?|architecture)\b"
    r"[^.?!]{0,40}\b(?:say|says|said|mean|means|require|requires|allow|state|states)\b"
    r"|\bwhat\s+(?:does|do)\s+the\s+[\w\s-]{0,30}?(?:polic(?:y|ies)|documentation|docs)\b"
    r"|\bhow\s+(?:does|do)\s+(?:the\s+)?(?:system|accessengine|engine|ai|assistant|"
    r"pipeline|privacy\s+policy)\b"
)

_INTENTS: Mapping[Route, tuple[tuple[re.Pattern[str], int], ...]] = {
    Route.VISITOR_HISTORY: (
        (
            re.compile(
                r"\b(?:visitors?|guests?|strangers?|unknown\s+(?:faces?|people|person))\b"
            ),
            3,
        ),
        (
            re.compile(
                r"\b(?:who\s+(?:came|visited|was\s+at|rang)|delivery|loiter\w*)\b"
            ),
            2,
        ),
        (re.compile(r"\b(?:visit(?:ed|s)?|sightings?)\b"), 1),
    ),
    Route.INCIDENT_ANALYSIS: (
        (re.compile(r"\bincidents?\b"), 3),
        (
            re.compile(
                r"\b(?:attack\s+chain|timeline|evidence|what\s+happened|investigat\w*)\b"
            ),
            2,
        ),
        (re.compile(r"\binc-[0-9a-f]{4,}\b"), 3),
    ),
    Route.SECURITY_REPORT: (
        (re.compile(r"\b(?:report|summary|summari[sz]e|digest|overview)\b"), 2),
        (re.compile(r"\b(?:daily|weekly|monthly)\b"), 1),
        # Time words alone do not make a question a report request.
        (
            re.compile(
                r"\b(?:today|yesterday|this\s+week|last\s+week|this\s+month|last\s+month)\b"
            ),
            1,
        ),
    ),
    Route.NOTIFICATION_RECOMMENDATION: (
        (
            re.compile(
                r"\b(?:escalat\w*|notify|notification|alert\s+(?:me|the\s+homeowner|the\s+owner))\b"
            ),
            3,
        ),
        (
            re.compile(
                r"\b(?:should\s+(?:i|we)\s+be\s+(?:worried|concerned)|tell\s+the\s+homeowner)\b"
            ),
            2,
        ),
    ),
    Route.SECURITY_MONITORING: (
        (
            re.compile(
                r"\b(?:suspicious|anomal\w*|threats?|brute[\s-]?force|failed\s+logins?|attacks?|intrusion|monitor\w*)\b"
            ),
            3,
        ),
        (
            re.compile(
                r"\b(?:security\s+events?|alerts?|denied|denials?|throttl\w*)\b"
            ),
            2,
        ),
    ),
    Route.GENERAL_KNOWLEDGE: (
        (
            re.compile(
                r"\b(?:how\s+does|how\s+do\s+i|what\s+is|explain|documentation|docs|policy|policies|configure|setting)\b"
            ),
            1,
        ),
    ),
}


@dataclass(frozen=True)
class RoutePlan:
    routes: tuple[Route, ...]
    refusal: Refusal | None
    denied: tuple[Route, ...]
    message: str | None

    @property
    def uses_gemini_possible(self) -> bool:
        return bool(self.routes) and set(self.routes) <= GEMINI_ELIGIBLE_ROUTES


def _clean(question: str) -> str:
    return re.sub(r"\s+", " ", normalise(question)).strip().lower()


def _refuse(kind: Refusal, denied: tuple[Route, ...] = ()) -> RoutePlan:
    return RoutePlan((), kind, denied, REFUSAL_MESSAGES[kind])


def route(question: str, ctx: UserContext) -> RoutePlan:
    if not isinstance(question, str):
        return _refuse(Refusal.INVALID_QUESTION)
    text = _clean(question)
    if not text or len(question) > MAX_QUESTION_CHARS:
        return _refuse(Refusal.INVALID_QUESTION)
    role = ctx.parsed_role if ctx.is_active else None
    if role is None:
        return _refuse(Refusal.NOT_AUTHORISED)
    if _DECISION_REQUEST.search(text):
        return _refuse(Refusal.ACCESS_DECISION)
    if _ACTION_REQUEST.search(text):
        return _refuse(Refusal.SECURITY_ACTION)
    if _DOCUMENTATION_QUESTION.search(text):
        # "What does the privacy policy say about visitors?" asks about the
        # rules, not about household records.
        return _plan([Route.GENERAL_KNOWLEDGE], role)

    scores: dict[Route, int] = {}
    for candidate, patterns in _INTENTS.items():
        score = sum(weight for pattern, weight in patterns if pattern.search(text))
        if score:
            scores[candidate] = score
    specialised = {r: s for r, s in scores.items() if r is not Route.GENERAL_KNOWLEDGE}
    if specialised:
        ranked = sorted(
            specialised, key=lambda r: (-specialised[r], list(Route).index(r))
        )
        top = specialised[ranked[0]]
        # Combine a second agent only when it is nearly as strong.
        chosen: list[Route] = [
            r for r in ranked[:MAX_ROUTES] if specialised[r] >= top - 1
        ]
    else:
        chosen = [Route.GENERAL_KNOWLEDGE]

    return _plan(chosen, role)


def _plan(chosen: list[Route], role: Role) -> RoutePlan:
    allowed = tuple(r for r in chosen if role in ROUTE_ROLES[r])
    denied = tuple(r for r in chosen if role not in ROUTE_ROLES[r])
    if not allowed:
        return _refuse(Refusal.NOT_AUTHORISED, denied)
    return RoutePlan(allowed, None, denied, None)
