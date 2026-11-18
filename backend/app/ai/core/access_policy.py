"""Role-based retrieval permissions (DD-08 decision 5), enforced three times.

| Role     | May retrieve                                                    |
|----------|-----------------------------------------------------------------|
| admin    | every record kind                                               |
| viewer   | documentation, security policies, security summaries, incident  |
|          | reports; no visitor history, no individual member records       |
| member   | documentation, security policies, and only their own access     |
|          | records                                                         |

1. **Before retrieval:** ``retrieval_filter`` builds the vector-store
   metadata filter, so unauthorised chunks are never even returned.
2. **After retrieval:** ``authorise_metadata`` re-checks every returned chunk,
   in case the store or the filter misbehaves.
3. **Against SQLite:** ``enforce`` asks a ``SourceVerifier`` (read-only
   SQLite) for the source record's *current* state and authorises against
   that. A record that was deleted, purged, re-owned or edited since it was
   indexed is excluded.

Everything fails closed: an inactive user, an unknown role, an unknown kind,
malformed metadata or a missing source yields no access.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from app.ai.core.types import RecordKind, RetrievedChunk, Role, SourceState, UserContext

_ALL = frozenset(RecordKind)
_SHARED = frozenset({RecordKind.DOCUMENTATION, RecordKind.SECURITY_POLICY})

#: Kinds a role may read regardless of ownership.
ROLE_KINDS: Mapping[Role, frozenset[RecordKind]] = {
    Role.ADMIN: _ALL,
    Role.VIEWER: _SHARED | {RecordKind.SECURITY_SUMMARY, RecordKind.INCIDENT_REPORT},
    Role.MEMBER: _SHARED,
}
#: Kinds a member may read only when they own the record.
MEMBER_OWNED_KINDS = frozenset({RecordKind.ACCESS_RECORD})


class SourceVerifier(Protocol):
    """Read-only lookup of a source record in SQLite (the source of truth)."""

    def current(self, kind: str, source_id: str) -> SourceState | None: ...


@dataclass(frozen=True)
class Denial:
    chunk_id: str
    reason: str


@dataclass(frozen=True)
class FilterResult:
    allowed: tuple[RetrievedChunk, ...]
    denied: tuple[Denial, ...]


def _active_role(ctx: UserContext) -> Role | None:
    if not ctx.is_active or isinstance(ctx.user_id, bool) or ctx.user_id < 1:
        return None
    return ctx.parsed_role


def _member_id(ctx: UserContext) -> int | None:
    mid = ctx.member_id
    if isinstance(mid, bool) or not isinstance(mid, int) or mid < 1:
        return None
    return mid


def allowed_kinds(ctx: UserContext) -> frozenset[RecordKind]:
    role = _active_role(ctx)
    return ROLE_KINDS.get(role, frozenset()) if role else frozenset()


def retrieval_filter(ctx: UserContext) -> dict[str, Any] | None:
    """Vector-store ``where`` filter for this caller, or None to skip retrieval.

    The shape follows ChromaDB's metadata filter syntax. None means the
    caller may retrieve nothing, and the caller must not query at all.
    """
    role = _active_role(ctx)
    if role is None:
        return None
    kinds = sorted(k.value for k in ROLE_KINDS[role])
    shared: dict[str, Any] = {"kind": {"$in": kinds}}
    member_id = _member_id(ctx)
    if role is Role.MEMBER and member_id is not None:
        own = [
            {"$and": [{"kind": kind.value}, {"owner_member_id": member_id}]}
            for kind in sorted(MEMBER_OWNED_KINDS)
        ]
        return {"$or": [shared, *own]}
    return shared


def _parse_kind(value: Any) -> RecordKind | None:
    if not isinstance(value, str):
        return None
    try:
        return RecordKind(value)
    except ValueError:
        return None


def _may_read(ctx: UserContext, kind: RecordKind, owner: Any) -> str | None:
    """None if allowed, else the denial reason."""
    role = _active_role(ctx)
    if role is None:
        return "caller_not_authorised"
    if kind in ROLE_KINDS[role]:
        return None
    if role is Role.MEMBER and kind in MEMBER_OWNED_KINDS:
        member_id = _member_id(ctx)
        if member_id is None:
            return "no_linked_member"
        if isinstance(owner, bool) or not isinstance(owner, int):
            return "owner_missing"
        return None if owner == member_id else "not_owner"
    return "kind_not_permitted"


def authorise_metadata(ctx: UserContext, metadata: Mapping[str, Any]) -> str | None:
    """Second check, on the chunk's own metadata. None means allowed."""
    kind = _parse_kind(metadata.get("kind"))
    if kind is None:
        return "unknown_kind"
    if not isinstance(metadata.get("source_id"), str) or not metadata["source_id"]:
        return "source_id_missing"
    return _may_read(ctx, kind, metadata.get("owner_member_id"))


def enforce(
    ctx: UserContext,
    chunks: Iterable[RetrievedChunk],
    verifier: SourceVerifier,
) -> FilterResult:
    """Second and third checks. Only chunks passing both are returned."""
    allowed: list[RetrievedChunk] = []
    denied: list[Denial] = []
    for chunk in chunks:
        meta = chunk.metadata
        reason = authorise_metadata(ctx, meta)
        if reason is None:
            source = verifier.current(str(meta["kind"]), str(meta["source_id"]))
            reason = _verify_source(ctx, meta, source)
        if reason is None:
            allowed.append(chunk)
        else:
            denied.append(Denial(chunk.chunk_id, reason))
    return FilterResult(tuple(allowed), tuple(denied))


def _verify_source(
    ctx: UserContext, meta: Mapping[str, Any], source: SourceState | None
) -> str | None:
    if source is None:
        return "source_missing"
    if source.purged:
        return "source_purged"
    if source.kind != meta.get("kind"):
        return "source_kind_changed"
    if source.owner_member_id != meta.get("owner_member_id"):
        return "source_owner_changed"
    indexed = meta.get("content_sha256")
    if not isinstance(indexed, str) or indexed != source.content_sha256:
        return "stale_index"
    kind = _parse_kind(source.kind)
    if kind is None:
        return "unknown_kind"
    # Authorise against SQLite's current values, not the indexed copy.
    return _may_read(ctx, kind, source.owner_member_id)
