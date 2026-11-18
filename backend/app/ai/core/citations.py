"""Citation and evidence-reference validation.

After ``output_validation`` accepts the shape, this checks that every
citation and every ``[S#]`` marker in the answer refers to a source that was
actually in the prompt, and that the answer does not mention evidence files
that were not provided. Any mismatch rejects the answer: an invented source
is treated as an invented fact.

Attributions returned to the caller are built from the sources, never from
model text. Evidence references are re-validated with the P1 validator and
are shown only to admins, matching the permission rules.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from app.ai.core.output_validation import OutputRejected, ValidatedAnswer
from app.ai.core.types import Role, UserContext
from app.domain.evidence import InvalidEvidenceRef, validate_evidence_ref

MARKER = re.compile(r"\[(S[1-9]\d{0,2})\]")
_PATH_LIKE = re.compile(
    r"(?i)\b[A-Za-z0-9][\w.-]*(?:/[\w.-]+)+\.(?:jpe?g|png|gif|webp|bmp|mp4|avi|mov|mkv)\b"
)


@dataclass(frozen=True)
class SourceRef:
    """What the prompt's source S# was. Built by the server, not the model."""

    chunk_id: str
    kind: str
    title: str
    evidence_ref: str | None = None


@dataclass(frozen=True)
class Attribution:
    source_id: str
    chunk_id: str
    kind: str
    title: str
    evidence_ref: str | None


def validate_citations(
    answer: ValidatedAnswer,
    sources: Mapping[str, SourceRef],
    ctx: UserContext,
) -> tuple[Attribution, ...]:
    """Raise OutputRejected, or return attributions for the cited sources."""
    markers = MARKER.findall(answer.answer)
    cited = set(answer.citations)
    for sid in [*markers, *answer.citations]:
        if sid not in sources:
            raise OutputRejected("citation_not_in_sources")
    if not set(markers) <= cited:
        raise OutputRejected("marker_not_listed_in_citations")
    if not answer.insufficient_context and not markers:
        raise OutputRejected("no_inline_citation")

    is_admin = ctx.is_active and ctx.parsed_role is Role.ADMIN
    provided_refs = {s.evidence_ref for s in sources.values() if s.evidence_ref}
    for mentioned in _PATH_LIKE.findall(answer.answer):
        if mentioned not in provided_refs:
            raise OutputRejected("unknown_evidence_reference")
        if not is_admin:
            raise OutputRejected("evidence_reference_not_permitted")

    out = []
    for sid in answer.citations:
        src = sources[sid]
        ref = None
        if src.evidence_ref is not None:
            try:
                ref = validate_evidence_ref(src.evidence_ref)
            except InvalidEvidenceRef:
                raise OutputRejected("source_evidence_ref_invalid") from None
        out.append(
            Attribution(
                sid, src.chunk_id, src.kind, src.title, ref if is_admin else None
            )
        )
    return tuple(out)


FALLBACK_TEXT = (
    "I could not find this in the information you are allowed to see, so I "
    "will not guess. Try rephrasing, or check the incident and event views "
    "directly."
)
