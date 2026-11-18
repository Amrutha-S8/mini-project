"""Gemini data-sharing policy (owner-approved, Phase 1). See docs/AI_PRIVACY_POLICY.md.

Default: **household data never leaves the house.** Only general
documentation, public technical information and non-sensitive security
policies may be sent to Gemini.

How a request is reviewed, in order:

1. **Source class decides first.** Every item declares what it is
   (``RecordKind``) and its sensitivity. Only ``documentation`` and
   ``security_policy`` marked ``public`` are shareable. Visitor history,
   access records, security events, attack chains and member records are
   never shareable, sanitised or not. Security summaries and incident reports
   are household data too: they can be sent only under an explicit,
   owner-approved, unexpired exception from the documented allowlist, and
   only as minimised fields.
2. **Content is scanned second.** Credentials, biometric payloads and
   evidence references are refused outright in any item and in the question.
   Personal data in a public document is replaced. In an excepted household
   item any finding at all is a refusal.
3. **Household terms.** A locally held list of household names and
   identifiers (members, doors, cameras) is matched; any hit is a refusal,
   because names cannot be detected by pattern.

Redaction is never treated as proof of anonymity: a sanitised household
record is still household data and is still refused.

Only ``GeminiPrivacyPolicy.approve`` can create an ``ApprovedGeminiPayload``:
the payload carries an HMAC seal over its exact content with a per-process
key, so a hand-built or edited payload (including ``dataclasses.replace``)
fails ``verify_approved``. The future Gemini adapter must accept nothing else
and call ``verify_approved`` before sending.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from app.ai.core.sensitive import Category, normalise, sanitise
from app.ai.core.types import RecordKind


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    HOUSEHOLD = "household"


#: May be sent when marked public and free of credentials or biometrics.
SHAREABLE_KINDS = frozenset({RecordKind.DOCUMENTATION, RecordKind.SECURITY_POLICY})
#: Household-derived; only under an approved exception, as minimised fields.
EXCEPTION_ELIGIBLE_KINDS = frozenset(
    {RecordKind.SECURITY_SUMMARY, RecordKind.INCIDENT_REPORT}
)
#: Never sent, under any exception.
NEVER_SHAREABLE_KINDS = (
    frozenset(RecordKind) - SHAREABLE_KINDS - EXCEPTION_ELIGIBLE_KINDS
)

#: Content categories refused in every item and in the question.
ALWAYS_REFUSED = frozenset(
    {Category.CREDENTIAL, Category.BIOMETRIC, Category.EVIDENCE_REF}
)

#: Field names that identify people, places or evidence; never allowlisted.
IDENTIFYING_FIELD = re.compile(
    r"(?i)(name|member|user|visitor|person|email|phone|ip|address|location|"
    r"camera|door|evidence|snapshot|image|face|embedding|session|token|key|"
    r"_id$|^id$)"
)

MAX_ITEMS = 20
MAX_TOTAL_CHARS = 30_000
MAX_QUESTION_CHARS = 2_000
MIN_JUSTIFICATION = 20


class PrivacyViolation(ValueError):
    """The request must not reach the Gemini adapter."""

    def __init__(self, violations: Sequence[Violation]) -> None:
        super().__init__("; ".join(f"{v.where}: {v.code}" for v in violations))
        self.violations = tuple(violations)


@dataclass(frozen=True)
class Violation:
    where: str  # "question", "item[3]", "request"
    code: str


@dataclass(frozen=True)
class EgressItem:
    """One piece of context proposed for a Gemini prompt."""

    kind: str
    source_id: str
    sensitivity: str
    text: str = ""
    #: Structured, minimised fields. Required for excepted household items.
    fields: Mapping[str, str] | None = None
    exception_id: str | None = None


@dataclass(frozen=True)
class EgressException:
    """A documented, owner-approved exception to the default. None exist."""

    exception_id: str
    kind: RecordKind
    allowed_fields: frozenset[str]
    approved_by_user_id: int
    approved_at: datetime
    expires_at: datetime
    justification: str

    def problems(self) -> list[str]:
        found = []
        if self.kind not in EXCEPTION_ELIGIBLE_KINDS:
            found.append("kind_not_eligible")
        if not self.allowed_fields:
            found.append("no_fields")
        if any(IDENTIFYING_FIELD.search(f) for f in self.allowed_fields):
            found.append("identifying_field_allowlisted")
        if isinstance(self.approved_by_user_id, bool) or self.approved_by_user_id < 1:
            found.append("no_approver")
        if len(self.justification.strip()) < MIN_JUSTIFICATION:
            found.append("justification_too_short")
        if self.approved_at.tzinfo is None or self.expires_at.tzinfo is None:
            found.append("naive_datetime")
        elif self.expires_at <= self.approved_at:
            found.append("expires_before_approval")
        return found


POLICY_VERSION = "gemini-privacy-1"

#: Per-process key binding a payload to the exact content the policy approved.
#: ``dataclasses.replace`` or direct construction cannot produce a valid seal.
_SEAL_KEY = secrets.token_bytes(32)


def _seal(question: str, items: tuple[EgressItem, ...], version: str) -> str:
    body = json.dumps(
        {
            "q": question,
            "v": version,
            "items": [
                [
                    i.kind,
                    i.source_id,
                    i.sensitivity,
                    i.text,
                    sorted((i.fields or {}).items()),
                    i.exception_id,
                ]
                for i in items
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hmac.new(_SEAL_KEY, body.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ApprovedGeminiPayload:
    """The only object the Gemini adapter may send. Built only by the policy."""

    question: str
    items: tuple[EgressItem, ...]
    policy_version: str
    seal: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        verify_approved(self)


class GeminiPrivacyPolicy:
    def __init__(
        self,
        *,
        exceptions: Iterable[EgressException] = (),
        household_terms: Iterable[str] = (),
    ) -> None:
        self._exceptions = {e.exception_id: e for e in exceptions}
        terms = sorted({normalise(t).strip().lower() for t in household_terms})
        terms = [t for t in terms if len(t) >= 3]
        self._terms = (
            re.compile(r"(?i)(?<!\w)(?:" + "|".join(map(re.escape, terms)) + r")(?!\w)")
            if terms
            else None
        )

    # --- review ----------------------------------------------------------------

    def review(
        self, question: str, items: Sequence[EgressItem], *, now: datetime
    ) -> tuple[list[Violation], str, tuple[EgressItem, ...]]:
        """(violations, cleaned question, cleaned items). Empty list = allowed."""
        violations: list[Violation] = []
        if not isinstance(question, str):
            return [Violation("question", "not_text")], "", ()
        if len(question) > MAX_QUESTION_CHARS:
            violations.append(Violation("question", "too_long"))
        if len(items) > MAX_ITEMS:
            violations.append(Violation("request", "too_many_items"))
        if now.tzinfo is None:
            violations.append(Violation("request", "naive_now"))

        q = sanitise(question)
        if q.categories & ALWAYS_REFUSED:
            violations.append(Violation("question", "prohibited_content"))
        if q.categories - ALWAYS_REFUSED:
            violations.append(Violation("question", "personal_or_internal_data"))
        if self._household_hit(question):
            violations.append(Violation("question", "household_term"))

        cleaned: list[EgressItem] = []
        total = len(q.text)
        for i, item in enumerate(items):
            where = f"item[{i}]"
            result = self._review_item(item, now)
            if isinstance(result, str):
                violations.append(Violation(where, result))
                continue
            total += len(result.text) + sum(
                len(v) for v in (result.fields or {}).values()
            )
            cleaned.append(result)
        if total > MAX_TOTAL_CHARS:
            violations.append(Violation("request", "too_much_context"))
        return violations, q.text, tuple(cleaned)

    def approve(
        self, question: str, items: Sequence[EgressItem], *, now: datetime
    ) -> ApprovedGeminiPayload:
        """Raise PrivacyViolation, or return the payload the adapter may send."""
        violations, clean_q, clean_items = self.review(question, items, now=now)
        if violations:
            raise PrivacyViolation(violations)
        seal = _seal(clean_q, clean_items, POLICY_VERSION)
        return ApprovedGeminiPayload(clean_q, clean_items, POLICY_VERSION, seal)

    # --- internals -------------------------------------------------------------

    def _household_hit(self, text: str) -> bool:
        return bool(self._terms and self._terms.search(normalise(text)))

    def _review_item(self, item: EgressItem, now: datetime) -> EgressItem | str:
        if not isinstance(item.text, str):
            return "binary_content"
        try:
            kind = RecordKind(item.kind)
        except ValueError:
            return "unknown_kind"
        if kind in NEVER_SHAREABLE_KINDS:
            return "household_record_never_shared"
        if kind in SHAREABLE_KINDS:
            return self._review_public(item)
        return self._review_excepted(item, kind, now)

    def _review_public(self, item: EgressItem) -> EgressItem | str:
        if item.sensitivity != Sensitivity.PUBLIC:
            return "not_marked_public"
        if item.fields:
            return "fields_not_allowed_for_documents"
        result = sanitise(item.text)
        if result.categories & ALWAYS_REFUSED:
            return "prohibited_content"
        if self._household_hit(item.text):
            return "household_term"
        return EgressItem(item.kind, item.source_id, item.sensitivity, result.text)

    def _review_excepted(
        self, item: EgressItem, kind: RecordKind, now: datetime
    ) -> EgressItem | str:
        exception = self._exceptions.get(item.exception_id or "")
        if exception is None:
            return "household_data_requires_approved_exception"
        if exception.problems():
            return "exception_invalid"
        if exception.kind is not kind:
            return "exception_kind_mismatch"
        if not exception.approved_at <= now < exception.expires_at:
            return "exception_not_in_force"
        if item.text:
            return "free_text_not_allowed_under_exception"
        if not item.fields:
            return "no_fields"
        if set(item.fields) - exception.allowed_fields:
            return "field_not_allowlisted"
        for value in item.fields.values():
            if not isinstance(value, str):
                return "binary_content"
            # Under an exception, *any* finding is a refusal: redaction is not
            # treated as making household data anonymous.
            if sanitise(value).findings or self._household_hit(value):
                return "sensitive_value_in_household_field"
        return EgressItem(
            item.kind,
            item.source_id,
            item.sensitivity,
            "",
            dict(item.fields),
            item.exception_id,
        )


def verify_approved(payload: object) -> ApprovedGeminiPayload:
    """The adapter's entry check: refuse anything the policy did not build."""
    if not isinstance(payload, ApprovedGeminiPayload):
        raise PrivacyViolation([Violation("request", "not_policy_approved")])
    expected = _seal(payload.question, payload.items, payload.policy_version)
    if payload.policy_version != POLICY_VERSION or not hmac.compare_digest(
        expected, payload.seal
    ):
        raise PrivacyViolation([Violation("request", "not_policy_approved")])
    return payload
