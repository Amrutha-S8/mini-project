"""Retrieval permissions: before retrieval, after retrieval, and against SQLite.

Includes permission-bypass attempts: forged metadata, re-owned or purged
sources, stale indexes, inactive users, unknown roles and malformed ids.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.ai.core.access_policy import (
    authorise_metadata,
    enforce,
    retrieval_filter,
)
from app.ai.core.types import RecordKind, RetrievedChunk, SourceState, UserContext

ADMIN = UserContext(1, "admin", True)
VIEWER = UserContext(2, "viewer", True)
MEMBER = UserContext(3, "member", True, member_id=5)
MEMBER_UNLINKED = UserContext(4, "member", True, member_id=None)
K = RecordKind


def chunk(
    kind: str, source_id: str = "s1", owner: Any = None, sha: str = "h"
) -> RetrievedChunk:
    meta: dict[str, Any] = {"kind": kind, "source_id": source_id, "content_sha256": sha}
    if owner is not None:
        meta["owner_member_id"] = owner
    return RetrievedChunk(f"{kind}:{source_id}", "text", 0.9, meta)


class Verifier:
    """Stands in for the read-only SQLite lookup; holds the 'current' rows."""

    def __init__(self, rows: dict[tuple[str, str], SourceState]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str]] = []

    def current(self, kind: str, source_id: str) -> SourceState | None:
        self.calls.append((kind, source_id))
        return self.rows.get((kind, source_id))


def verifier_for(*chunks: RetrievedChunk) -> Verifier:
    return Verifier(
        {
            (c.metadata["kind"], c.metadata["source_id"]): SourceState(
                c.metadata["kind"],
                c.metadata.get("owner_member_id"),
                c.metadata["content_sha256"],
            )
            for c in chunks
        }
    )


# --- the role matrix -------------------------------------------------------------

MATRIX = {
    "admin": set(K),
    "viewer": {
        K.DOCUMENTATION,
        K.SECURITY_POLICY,
        K.SECURITY_SUMMARY,
        K.INCIDENT_REPORT,
    },
    "member": {K.DOCUMENTATION, K.SECURITY_POLICY},
}


@pytest.mark.parametrize("ctx", [ADMIN, VIEWER, MEMBER])
@pytest.mark.parametrize("kind", list(K))
def test_matrix_for_unowned_records(ctx: UserContext, kind: RecordKind) -> None:
    expected = kind in MATRIX[ctx.role]
    c = chunk(kind.value)
    allowed = enforce(ctx, [c], verifier_for(c)).allowed
    assert bool(allowed) is expected, (ctx.role, kind)


def test_viewer_never_sees_visitor_or_member_records() -> None:
    for kind in (K.VISITOR_HISTORY, K.MEMBER_RECORD, K.ACCESS_RECORD, K.SECURITY_EVENT):
        assert (
            authorise_metadata(VIEWER, chunk(kind.value).metadata)
            == "kind_not_permitted"
        )


def test_member_sees_only_own_access_records() -> None:
    own, other = (
        chunk("access_record", "a1", owner=5),
        chunk("access_record", "a2", owner=6),
    )
    result = enforce(MEMBER, [own, other], verifier_for(own, other))
    assert [c.chunk_id for c in result.allowed] == [own.chunk_id]
    assert result.denied[0].reason == "not_owner"


def test_member_without_linked_member_gets_no_access_records() -> None:
    c = chunk("access_record", owner=5)
    assert authorise_metadata(MEMBER_UNLINKED, c.metadata) == "no_linked_member"


@pytest.mark.parametrize("owner", [None, "5", 5.0, True])
def test_member_owner_must_be_an_exact_integer(owner: Any) -> None:
    meta = {"kind": "access_record", "source_id": "a1", "owner_member_id": owner}
    assert authorise_metadata(MEMBER, meta) is not None


# --- before retrieval -------------------------------------------------------------


def test_filters_per_role() -> None:
    assert retrieval_filter(ADMIN) == {"kind": {"$in": sorted(k.value for k in K)}}
    assert retrieval_filter(VIEWER) == {
        "kind": {
            "$in": [
                "documentation",
                "incident_report",
                "security_policy",
                "security_summary",
            ]
        }
    }
    assert retrieval_filter(MEMBER) == {
        "$or": [
            {"kind": {"$in": ["documentation", "security_policy"]}},
            {"$and": [{"kind": "access_record"}, {"owner_member_id": 5}]},
        ]
    }
    assert retrieval_filter(MEMBER_UNLINKED) == {
        "kind": {"$in": ["documentation", "security_policy"]}
    }


@pytest.mark.parametrize(
    "ctx",
    [
        UserContext(1, "admin", False),
        UserContext(1, "superuser", True),
        UserContext(1, "Admin", True),
        UserContext(1, "", True),
        UserContext(0, "admin", True),
        UserContext(True, "admin", True),  # type: ignore[arg-type]
    ],
)
def test_fail_closed_callers_retrieve_nothing(ctx: UserContext) -> None:
    assert retrieval_filter(ctx) is None
    c = chunk("documentation")
    assert enforce(ctx, [c], verifier_for(c)).allowed == ()


# --- after retrieval: forged or malformed metadata ----------------------------


@pytest.mark.parametrize(
    "meta,reason",
    [
        ({"source_id": "s"}, "unknown_kind"),
        ({"kind": "biometric", "source_id": "s"}, "unknown_kind"),
        ({"kind": "face_embedding", "source_id": "s"}, "unknown_kind"),
        ({"kind": ["documentation"], "source_id": "s"}, "unknown_kind"),
        ({"kind": "documentation"}, "source_id_missing"),
        ({"kind": "documentation", "source_id": ""}, "source_id_missing"),
    ],
)
def test_malformed_metadata_denied(meta: dict[str, Any], reason: str) -> None:
    assert authorise_metadata(ADMIN, meta) == reason


def test_store_returning_forbidden_chunk_is_still_denied() -> None:
    """If the vector-store filter fails, the second check catches it."""
    leaked = chunk("visitor_history")
    result = enforce(VIEWER, [leaked], verifier_for(leaked))
    assert result.allowed == () and result.denied[0].reason == "kind_not_permitted"


# --- against SQLite ----------------------------------------------------------------


def test_metadata_relabelled_as_documentation_is_caught_by_source_check() -> None:
    """A chunk whose index metadata claims 'documentation' but whose SQLite
    source is visitor history is denied."""
    forged = chunk("documentation", "v9")
    verifier = Verifier(
        {("documentation", "v9"): SourceState("visitor_history", None, "h")}
    )
    result = enforce(MEMBER, [forged], verifier)
    assert result.denied[0].reason == "source_kind_changed"


def test_reowned_record_is_denied() -> None:
    c = chunk("access_record", "a1", owner=5)
    verifier = Verifier({("access_record", "a1"): SourceState("access_record", 6, "h")})
    assert enforce(MEMBER, [c], verifier).denied[0].reason == "source_owner_changed"


@pytest.mark.parametrize(
    "state,reason",
    [
        (None, "source_missing"),
        (SourceState("documentation", None, "h", purged=True), "source_purged"),
        (SourceState("documentation", None, "other"), "stale_index"),
    ],
)
def test_source_state_checks(state: SourceState | None, reason: str) -> None:
    c = chunk("documentation", "d1")
    verifier = Verifier({("documentation", "d1"): state} if state else {})
    result = enforce(ADMIN, [c], verifier)
    assert result.allowed == () and result.denied[0].reason == reason


def test_every_allowed_chunk_was_checked_against_sqlite() -> None:
    chunks = [chunk("documentation", f"d{i}") for i in range(5)]
    verifier = verifier_for(*chunks)
    result = enforce(ADMIN, chunks, verifier)
    assert len(result.allowed) == 5
    assert verifier.calls == [("documentation", f"d{i}") for i in range(5)]


def test_unauthorised_chunks_never_reach_the_verifier() -> None:
    c = chunk("visitor_history")
    verifier = verifier_for(c)
    enforce(VIEWER, [c], verifier)
    assert verifier.calls == []
