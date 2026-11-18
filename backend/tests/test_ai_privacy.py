"""Sensitive-data detection and the Gemini privacy policy: leak tests.

Every prohibited class from the owner's policy is tried: face images,
biometric data, visitor identities and history, raw access logs, raw
security events, incident evidence, credentials, tokens and household
personal information. Each must be refused before reaching an adapter.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.ai.core.privacy import (
    NEVER_SHAREABLE_KINDS,
    POLICY_VERSION,
    ApprovedGeminiPayload,
    EgressException,
    EgressItem,
    GeminiPrivacyPolicy,
    PrivacyViolation,
    verify_approved,
)
from app.ai.core.sensitive import Category, normalise, sanitise, sanitise_mapping, scan
from app.ai.core.types import RecordKind

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
DOC = "The AccessEngine is the only component that decides access."
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlLXZhbHVl"
GOOGLE_KEY = "AIza" + "B" * 35
VECTOR = "[" + ", ".join(f"0.{i:03d}" for i in range(32)) + "]"


def doc(text: str = DOC, **kw: Any) -> EgressItem:
    return EgressItem(
        kw.pop("kind", "documentation"),
        "doc-1",
        kw.pop("sensitivity", "public"),
        text,
        **kw,
    )


def violations(
    policy: GeminiPrivacyPolicy, question: str, items: list[EgressItem]
) -> list[str]:
    found, _q, _i = policy.review(question, items, now=NOW)
    return [f"{v.where}:{v.code}" for v in found]


# --- detection ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,category",
    [
        (FAKE_JWT, Category.CREDENTIAL),
        ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", Category.CREDENTIAL),
        (GOOGLE_KEY, Category.CREDENTIAL),
        ("sk-" + "a" * 32, Category.CREDENTIAL),
        ("ghp_" + "a" * 36, Category.CREDENTIAL),
        ("AKIA" + "A" * 16, Category.CREDENTIAL),
        ("password = hunter22", Category.CREDENTIAL),
        ("SECRET_KEY: Zx9-very-long-value", Category.CREDENTIAL),
        ("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", Category.CREDENTIAL),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
            Category.CREDENTIAL,
        ),
        ("data:image/jpeg;base64,/9j/4AAQSkZJRg==", Category.BIOMETRIC),
        (VECTOR, Category.BIOMETRIC),
        ("A" * 240, Category.BIOMETRIC),
        ("mail me at alex.smith@example.org", Category.PERSONAL),
        ("from 192.168.1.20", Category.PERSONAL),
        ("from 2001:db8::1", Category.PERSONAL),
        ("device aa:bb:cc:dd:ee:ff", Category.PERSONAL),
        ("call +44 7700 900123", Category.PERSONAL),
        ("see snap/2026-11-16/cam1-0001.jpg", Category.EVIDENCE_REF),
        ("id " + "ab" * 16, Category.INTERNAL_ID),
    ],
)
def test_detectors(text: str, category: Category) -> None:
    assert category in sanitise(text).categories


@pytest.mark.parametrize(
    "text",
    [
        "Throttling allows 20 attempts per 5 minutes.",
        "Released on 2026-11-16 at 10:00:00 UTC.",
        "Version 1.2.3 of the engine.",
        "Rule 7 returns HOLD outside the time window.",
    ],
)
def test_ordinary_text_is_not_flagged(text: str) -> None:
    assert scan(text) == ()


def test_sanitise_replaces_and_reports() -> None:
    result = sanitise(f"user alex@example.com token={FAKE_JWT} from 10.0.0.7")
    assert "alex@example.com" not in result.text and FAKE_JWT not in result.text
    assert "10.0.0.7" not in result.text
    assert (
        "[REDACTED:personal]" in result.text and "[REDACTED:credential]" in result.text
    )


@pytest.mark.parametrize(
    "hidden",
    [
        "alex\u200b@example.com",  # zero-width space
        "ａｌｅｘ@ｅｘａｍｐｌｅ.ｃｏｍ",  # fullwidth
        "pass\u202eword = hunter22",  # bidi override inside the key
    ],
)
def test_obfuscated_values_are_normalised_then_caught(hidden: str) -> None:
    assert sanitise(hidden).findings, normalise(hidden)


def test_mapping_sanitiser_drops_sensitive_fields() -> None:
    out = sanitise_mapping(
        {
            "face_embedding": [0.1] * 512,
            "snapshot": b"\xff\xd8",
            "password": "x",
            "note": "seen at 192.168.0.4",
            "nested": {"api_key": "k", "count": 3},
        }
    )
    assert (
        out["face_embedding"]
        == out["snapshot"]
        == out["password"]
        == ("[REDACTED:sensitive_field]")
    )
    assert out["note"] == "seen at [REDACTED:personal]"
    assert out["nested"] == {"api_key": "[REDACTED:sensitive_field]", "count": 3}


# --- policy: what may be sent ---------------------------------------------------


def test_public_documentation_is_allowed() -> None:
    policy = GeminiPrivacyPolicy()
    payload = policy.approve("How does HOLD work?", [doc()], now=NOW)
    assert payload.items[0].text == DOC
    assert verify_approved(payload) is payload


def test_personal_data_in_public_documentation_is_replaced() -> None:
    payload = GeminiPrivacyPolicy().approve(
        "Who maintains it?", [doc("Contact admin@example.com for help.")], now=NOW
    )
    assert "admin@example.com" not in payload.items[0].text


# --- policy: household records are never sent ---------------------------------


@pytest.mark.parametrize("kind", sorted(k.value for k in NEVER_SHAREABLE_KINDS))
def test_household_record_kinds_are_never_sent(kind: str) -> None:
    item = EgressItem(kind, "r1", "public", "Front door, 10:02, denied.")
    assert violations(GeminiPrivacyPolicy(), "What happened?", [item]) == [
        "item[0]:household_record_never_shared"
    ]


def test_never_shareable_covers_every_household_kind() -> None:
    assert {
        RecordKind.VISITOR_HISTORY,
        RecordKind.ACCESS_RECORD,
        RecordKind.SECURITY_EVENT,
        RecordKind.ATTACK_CHAIN,
        RecordKind.MEMBER_RECORD,
    } <= NEVER_SHAREABLE_KINDS


def test_sanitised_household_data_is_still_refused() -> None:
    """Redaction is not proof of anonymity."""
    clean = sanitise("Visitor v-4 at 192.168.1.9 denied twice").text
    item = EgressItem("visitor_history", "v4", "public", clean)
    assert violations(GeminiPrivacyPolicy(), "Summarise", [item]) == [
        "item[0]:household_record_never_shared"
    ]


@pytest.mark.parametrize("kind", ["security_summary", "incident_report"])
def test_household_summaries_need_an_approved_exception(kind: str) -> None:
    item = EgressItem(kind, "r1", "household", "3 failed logins yesterday")
    assert violations(GeminiPrivacyPolicy(), "Explain", [item]) == [
        "item[0]:household_data_requires_approved_exception"
    ]


@pytest.mark.parametrize("sensitivity", ["internal", "household", "PUBLIC", ""])
def test_documents_not_marked_public_are_refused(sensitivity: str) -> None:
    assert violations(GeminiPrivacyPolicy(), "q", [doc(sensitivity=sensitivity)]) == [
        "item[0]:not_marked_public"
    ]


@pytest.mark.parametrize(
    "text",
    [
        f"Example token: {FAKE_JWT}",
        f"Set GEMINI_API_KEY={GOOGLE_KEY}",
        f"Embedding sample {VECTOR}",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
        "Snapshot stored at evidence/2026/11/16/front.jpg",
        "password: CorrectHorse9",
    ],
)
def test_prohibited_content_in_a_document_is_refused(text: str) -> None:
    assert violations(GeminiPrivacyPolicy(), "q", [doc(text)]) == [
        "item[0]:prohibited_content"
    ]


@pytest.mark.parametrize(
    "question,code",
    [
        (f"Is this token valid? {FAKE_JWT}", "question:prohibited_content"),
        ("Why was 192.168.1.20 throttled?", "question:personal_or_internal_data"),
        ("Who is alex@example.com?", "question:personal_or_internal_data"),
        ("What is in snap/1.jpg?", "question:prohibited_content"),
    ],
)
def test_prohibited_content_in_the_question_is_refused(
    question: str, code: str
) -> None:
    assert code in violations(GeminiPrivacyPolicy(), question, [doc()])


def test_household_terms_are_refused_anywhere() -> None:
    policy = GeminiPrivacyPolicy(household_terms=["Alex Smith", "back-garden-cam"])
    assert "question:household_term" in violations(
        policy, "When did alex smith visit?", []
    )
    assert violations(policy, "q", [doc("Alex Smith configured the camera.")]) == [
        "item[0]:household_term"
    ]
    assert violations(policy, "q", [doc("back-garden-cam settings")]) == [
        "item[0]:household_term"
    ]


@pytest.mark.parametrize(
    "item,code",
    [
        (EgressItem("documentation", "d", "public", b"\x89PNG"), "binary_content"),  # type: ignore[arg-type]
        (EgressItem("face_image", "d", "public", "x"), "unknown_kind"),
        (EgressItem("biometric", "d", "public", "x"), "unknown_kind"),
        (
            EgressItem("documentation", "d", "public", "x", fields={"a": "b"}),
            "fields_not_allowed_for_documents",
        ),
    ],
)
def test_malformed_items_refused(item: EgressItem, code: str) -> None:
    assert violations(GeminiPrivacyPolicy(), "q", [item]) == [f"item[0]:{code}"]


def test_size_limits() -> None:
    policy = GeminiPrivacyPolicy()
    assert "request:too_many_items" in violations(policy, "q", [doc()] * 21)
    assert "request:too_much_context" in violations(policy, "q", [doc("word " * 7000)])
    assert "question:too_long" in violations(policy, "x" * 2001, [])


def test_approve_raises_with_every_violation() -> None:
    items = [doc(), EgressItem("visitor_history", "v", "public", "x")]
    with pytest.raises(PrivacyViolation) as info:
        GeminiPrivacyPolicy().approve("192.168.1.1?", items, now=NOW)
    codes = {v.code for v in info.value.violations}
    assert codes == {"personal_or_internal_data", "household_record_never_shared"}


# --- the approved payload cannot be forged or edited ---------------------------


def test_payload_cannot_be_constructed_directly() -> None:
    with pytest.raises(PrivacyViolation):
        ApprovedGeminiPayload("q", (), POLICY_VERSION)
    with pytest.raises(PrivacyViolation):
        ApprovedGeminiPayload("q", (), POLICY_VERSION, seal="0" * 64)


def test_payload_cannot_be_edited_with_replace() -> None:
    payload = GeminiPrivacyPolicy().approve("q", [doc()], now=NOW)
    smuggled = EgressItem("visitor_history", "v", "public", "visitor v-4")
    with pytest.raises(PrivacyViolation):
        dataclasses.replace(payload, items=(smuggled,))
    with pytest.raises(PrivacyViolation):
        dataclasses.replace(payload, question="new question")


def test_mutating_payload_fields_breaks_the_seal() -> None:
    policy = GeminiPrivacyPolicy(
        exceptions=[_exception()],
    )
    item = EgressItem(
        "security_summary",
        "s",
        "household",
        fields={"total_events": "12"},
        exception_id="ex-1",
    )
    payload = policy.approve("q", [item], now=NOW)
    assert payload.items[0].fields is not None
    payload.items[0].fields["total_events"] = "Alex visited at 10:00"  # type: ignore[index]
    with pytest.raises(PrivacyViolation):
        verify_approved(payload)


@pytest.mark.parametrize("obj", [None, "q", {"question": "q"}, object()])
def test_verify_rejects_non_payloads(obj: object) -> None:
    with pytest.raises(PrivacyViolation):
        verify_approved(obj)


# --- exceptions (none exist today) ----------------------------------------------


def _exception(**overrides: Any) -> EgressException:
    values: dict[str, Any] = {
        "exception_id": "ex-1",
        "kind": RecordKind.SECURITY_SUMMARY,
        "allowed_fields": frozenset({"total_events", "blocked"}),
        "approved_by_user_id": 1,
        "approved_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=30),
        "justification": "Owner approved aggregate counts for wording help.",
    }
    values.update(overrides)
    return EgressException(**values)


def _summary_item(**overrides: Any) -> EgressItem:
    values: dict[str, Any] = {
        "kind": "security_summary",
        "source_id": "s",
        "sensitivity": "household",
        "fields": {"total_events": "12", "blocked": "3"},
        "exception_id": "ex-1",
    }
    values.update(overrides)
    return EgressItem(**values)


def test_valid_exception_allows_only_minimised_fields() -> None:
    policy = GeminiPrivacyPolicy(exceptions=[_exception()])
    payload = policy.approve("q", [_summary_item()], now=NOW)
    assert payload.items[0].fields == {"total_events": "12", "blocked": "3"}


@pytest.mark.parametrize(
    "exception",
    [
        _exception(kind=RecordKind.VISITOR_HISTORY),
        _exception(allowed_fields=frozenset({"visitor_name"})),
        _exception(allowed_fields=frozenset({"ip_address"})),
        _exception(allowed_fields=frozenset()),
        _exception(approved_by_user_id=0),
        _exception(justification="ok"),
        _exception(expires_at=NOW - timedelta(days=2)),
        _exception(approved_at=datetime(2026, 11, 15)),
    ],
)
def test_invalid_exceptions_are_ignored(exception: EgressException) -> None:
    assert exception.problems()
    policy = GeminiPrivacyPolicy(exceptions=[exception])
    assert violations(policy, "q", [_summary_item()])


@pytest.mark.parametrize(
    "item,code",
    [
        (
            _summary_item(exception_id="ex-2"),
            "household_data_requires_approved_exception",
        ),
        (_summary_item(kind="incident_report"), "exception_kind_mismatch"),
        (
            _summary_item(fields={"total_events": "12", "who": "x"}),
            "field_not_allowlisted",
        ),
        (
            _summary_item(fields={"total_events": "from 10.0.0.9"}),
            "sensitive_value_in_household_field",
        ),
        (_summary_item(fields={"total_events": "[REDACTED:personal]"}), None),
        (_summary_item(text="free text"), "free_text_not_allowed_under_exception"),
        (_summary_item(fields={}), "no_fields"),
    ],
)
def test_exception_misuse(item: EgressItem, code: str | None) -> None:
    policy = GeminiPrivacyPolicy(exceptions=[_exception()])
    found = violations(policy, "q", [item])
    if code is None:
        assert found == []  # a placeholder token is not itself sensitive
    else:
        assert found == [f"item[0]:{code}"]


def test_expired_exception_not_in_force() -> None:
    policy = GeminiPrivacyPolicy(exceptions=[_exception()])
    found, _q, _i = policy.review("q", [_summary_item()], now=NOW + timedelta(days=31))
    assert [v.code for v in found] == ["exception_not_in_force"]


def test_household_term_inside_excepted_field_refused() -> None:
    policy = GeminiPrivacyPolicy(exceptions=[_exception()], household_terms=["Alex"])
    item = _summary_item(fields={"total_events": "Alex 3"})
    assert violations(policy, "q", [item]) == [
        "item[0]:sensitive_value_in_household_field"
    ]


def test_no_exceptions_are_configured_in_code() -> None:
    import app.ai.core.privacy as module

    assert GeminiPrivacyPolicy()._exceptions == {}
    for value in vars(module).values():
        assert not isinstance(value, EgressException)
        if isinstance(value, (tuple, list, frozenset, set)):
            assert not any(isinstance(v, EgressException) for v in value)
