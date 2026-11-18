"""Shared types for the AI core: who is asking, and what was retrieved."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    ADMIN = "admin"
    VIEWER = "viewer"
    MEMBER = "member"


class RecordKind(StrEnum):
    """Every kind of record the AI tier could ever retrieve.

    Incident evidence files, face images, embeddings and credentials are
    deliberately not kinds: they are never indexed or retrieved at all.
    """

    DOCUMENTATION = "documentation"
    SECURITY_POLICY = "security_policy"
    SECURITY_SUMMARY = "security_summary"
    INCIDENT_REPORT = "incident_report"
    ACCESS_RECORD = "access_record"
    VISITOR_HISTORY = "visitor_history"
    SECURITY_EVENT = "security_event"
    ATTACK_CHAIN = "attack_chain"
    MEMBER_RECORD = "member_record"


@dataclass(frozen=True)
class UserContext:
    """The authenticated caller, resolved server-side from SQLite.

    ``role`` is kept as the raw string so an unknown role fails closed
    instead of raising somewhere unexpected.
    """

    user_id: int
    role: str
    is_active: bool
    #: The family member linked to this operator account, if any.
    member_id: int | None = None

    @property
    def parsed_role(self) -> Role | None:
        try:
            return Role(self.role)
        except ValueError:
            return None


@dataclass(frozen=True)
class RetrievedChunk:
    """One chunk returned by the vector store, before any trust is given."""

    chunk_id: str
    text: str
    score: float
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceState:
    """The current state of a chunk's source record, read from SQLite."""

    kind: str
    owner_member_id: int | None
    content_sha256: str
    purged: bool = False
