"""Strict validation of model output (SR-AI-08). Invalid output is discarded.

The model must return one JSON object with exactly these keys:

    answer                string, at most MAX_ANSWER_CHARS
    citations             list of source ids such as "S1"
    confidence            "low" | "medium" | "high"
    insufficient_context  boolean
    recommendations       at most 5 objects {"action", "rationale"}

Rules beyond the shape:

* ``action`` must come from ``RECOMMENDATION_ACTIONS``. Every action is a
  suggestion for a human; nothing here can execute one, and
  ``requires_approval`` is always True.
* Text that presents an access decision (``ALLOW``/``DENY``/``HOLD``), claims
  the AI performed a security action, or contains tool-call syntax is
  rejected (SR-AI-01/02/08).
* Duplicate keys, unknown keys, NaN/Infinity, wrong types and oversize output
  are rejected. One surrounding Markdown code fence is tolerated.

Rejection raises ``OutputRejected`` with a short code for logging. The raw
text is never passed on.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from app.ai.core.sensitive import normalise

MAX_RAW_CHARS = 20_000
MAX_ANSWER_CHARS = 4_000
MAX_RATIONALE_CHARS = 500
MAX_RECOMMENDATIONS = 5
MAX_CITATIONS = 20

RECOMMENDATION_ACTIONS = frozenset(
    {
        "review_incident",
        "review_visitor_evidence",
        "review_sessions",
        "rotate_credentials",
        "notify_homeowner",
        "consider_lockdown",
        "monitor",
        "no_action",
    }
)
CONFIDENCE = frozenset({"low", "medium", "high"})
KEYS = frozenset(
    {"answer", "citations", "confidence", "insufficient_context", "recommendations"}
)
SOURCE_ID = re.compile(r"S[1-9]\d{0,2}")

_FENCE = re.compile(r"^\s*```(?:json)?\s*\n(.*)\n\s*```\s*$", re.DOTALL)

_DECISION_LANGUAGE: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Explaining what HOLD means is fine; issuing one is not.
    (
        "bare_decision",
        re.compile(
            r"^\W*(?:ALLOW|DENY|HOLD)\W*(?:\[S\d+\]\W*)*$|(?:=>|->|→)\s*(?:ALLOW|DENY|HOLD)\b"
        ),
    ),
    (
        "ai_decides",
        re.compile(
            r"(?i)\b(?:i|we)\s+(?:would\s+|recommend\s+|suggest\s+|choose\s+|decide\s+(?:to\s+)?)"
            r"{1,2}(?:allow(?:ing)?|deny(?:ing)?|hold(?:ing)?|admit(?:ting)?|"
            r"let(?:ting)?)\b|"
            r"\byou\s+should\s+(?:allow|deny|admit|let)\b|"
            r"\b(?:access|entry|result|answer)\s*[:=]\s*(?:allow|deny|hold|granted|denied)\b"
        ),
    ),
    (
        "decision_statement",
        re.compile(
            r"(?i)\b(?:decision|verdict|outcome)\s*(?:is|:|=)\s*"
            r"(?:allow(?:ed)?|den(?:y|ied)|hold|grant(?:ed)?)\b"
        ),
    ),
    (
        "ai_performed_action",
        re.compile(
            r"(?i)\b(?:i|we)(?:'ve|'ll| have| will| am going to| shall)?\s+"
            r"(?:now\s+|just\s+|already\s+)?"
            r"(?:unlock(?:ed)?|open(?:ed)?|grant(?:ed)?|approv(?:e|ed)|"
            r"enrol(?:l|led)?|disabl(?:e|ed)|releas(?:e|ed)|lift(?:ed)?|"
            r"overrid(?:e|den)|revok(?:e|ed)|(?:re)?activat(?:e|ed)|"
            r"(?:enabl|trigger|start)(?:e|ed)?\s+(?:the\s+)?lockdown)\b"
        ),
    ),
    (
        "state_change_claim",
        re.compile(
            r"(?i)\b(?:door|lock)\s+(?:is|has)\s+now\s+(?:been\s+)?(?:unlocked|open)|"
            r"\blockdown\s+(?:is|has)\s+now\s+(?:been\s+)?"
            r"(?:disabled|released|lifted|off|over)|"
            r"\b(?:access|entry)\s+(?:is|has)\s+now\s+(?:been\s+)?(?:granted|allowed)|"
            r"\bpermissions?\s+(?:has|have)\s+(?:now\s+)?been\s+"
            r"(?:granted|updated|changed)\s+by\s+(?:me|the\s+ai)"
        ),
    ),
    (
        "tool_call_syntax",
        re.compile(
            r"(?i)\b(?:unlock|open_door|grant_access|release_lockdown|"
            r"enter_lockdown|approve_visitor|enrol+_?\w*|set_permission)\s*\(|"
            r"\"(?:tool|function)(?:_call|_name)?\"\s*:"
        ),
    ),
)


class OutputRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Recommendation:
    action: str
    rationale: str
    requires_approval: bool = True


@dataclass(frozen=True)
class ValidatedAnswer:
    answer: str
    citations: tuple[str, ...]
    confidence: str
    insufficient_context: bool
    recommendations: tuple[Recommendation, ...]
    is_ai_generated: bool = True
    advisory: bool = True


def decision_language(text: str) -> tuple[str, ...]:
    clean = normalise(text)
    return tuple(name for name, p in _DECISION_LANGUAGE if p.search(clean))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise OutputRejected("duplicate_key")
        seen[key] = value
    return seen


def _reject_constant(_name: str) -> None:
    raise OutputRejected("non_finite_number")


def _parse(raw: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise OutputRejected("not_text")
    if len(raw) > MAX_RAW_CHARS:
        raise OutputRejected("too_long")
    fenced = _FENCE.match(raw)
    body = fenced.group(1) if fenced else raw.strip()
    try:
        data = json.loads(
            body, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except OutputRejected:
        raise
    except ValueError:
        raise OutputRejected("not_json") from None
    if not isinstance(data, dict):
        raise OutputRejected("not_an_object")
    return data


def parse_model_output(raw: str) -> ValidatedAnswer:
    data = _parse(raw)
    if set(data) != KEYS:
        raise OutputRejected("wrong_keys")

    answer = data["answer"]
    if not isinstance(answer, str) or not answer.strip():
        raise OutputRejected("answer_not_text")
    if len(answer) > MAX_ANSWER_CHARS:
        raise OutputRejected("answer_too_long")

    citations = data["citations"]
    if not isinstance(citations, list) or len(citations) > MAX_CITATIONS:
        raise OutputRejected("citations_invalid")
    if not all(isinstance(c, str) and SOURCE_ID.fullmatch(c) for c in citations):
        raise OutputRejected("citation_format")
    if len(set(citations)) != len(citations):
        raise OutputRejected("citation_duplicate")

    confidence = data["confidence"]
    if confidence not in CONFIDENCE:
        raise OutputRejected("confidence_invalid")
    insufficient = data["insufficient_context"]
    if not isinstance(insufficient, bool):
        raise OutputRejected("insufficient_context_not_bool")

    recs_raw = data["recommendations"]
    if not isinstance(recs_raw, list) or len(recs_raw) > MAX_RECOMMENDATIONS:
        raise OutputRejected("recommendations_invalid")
    recs = []
    for item in recs_raw:
        if not isinstance(item, dict) or set(item) != {"action", "rationale"}:
            raise OutputRejected("recommendation_shape")
        action, rationale = item["action"], item["rationale"]
        if action not in RECOMMENDATION_ACTIONS:
            raise OutputRejected("recommendation_action_not_allowed")
        if not isinstance(rationale, str) or len(rationale) > MAX_RATIONALE_CHARS:
            raise OutputRejected("recommendation_rationale_invalid")
        if decision_language(rationale):
            raise OutputRejected("decision_language")
        recs.append(Recommendation(action, rationale.strip()))

    if decision_language(answer):
        raise OutputRejected("decision_language")
    if not insufficient and not citations:
        raise OutputRejected("uncited_answer")

    return ValidatedAnswer(
        answer.strip(),
        tuple(citations),
        confidence,
        insufficient,
        tuple(recs),
    )
