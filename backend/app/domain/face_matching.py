"""Face matching over precomputed embeddings (module M06, stdlib only).

Detection and embedding extraction (OpenCV + the approved recogniser) happen
in the vision layer. This module receives the resulting L2-normalisable
vectors and decides, with a threshold and a best-vs-second margin, whether a
face matches an enrolled family member.

It reports a *claim*. It never authorises: the AccessEngine re-checks the
score independently. Unknown faces are never added to the gallery here;
enrollment is a separate, admin-only operation.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

DEFAULT_DIM = 512


class FaceMatchError(ValueError):
    """An embedding cannot be used for matching."""


class MatchStatus(StrEnum):
    MATCHED = "matched"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    NO_FACE = "no_face"
    MULTIPLE_FACES = "multiple_faces"
    POOR_QUALITY = "poor_quality"


@dataclass(frozen=True)
class FaceObservation:
    """One detected face from one frame, as produced by the vision layer."""

    embedding: Sequence[float]
    quality_ok: bool = True
    quality_reason: str | None = None  # e.g. "too_dark", "blurred", "too_small"


@dataclass(frozen=True)
class GalleryEntry:
    embedding_id: int
    member_id: int
    vector: tuple[float, ...]  # L2-normalised


@dataclass(frozen=True)
class MatchResult:
    status: MatchStatus
    threshold: float
    min_margin: float
    member_id: int | None = None
    embedding_id: int | None = None
    score: float | None = None
    second_score: float | None = None
    detail: str | None = None

    @property
    def margin(self) -> float | None:
        if self.score is None:
            return None
        return self.score - (
            self.second_score if self.second_score is not None else -1.0
        )


def normalise(vector: Sequence[float], *, dim: int = DEFAULT_DIM) -> tuple[float, ...]:
    """Validate and L2-normalise an embedding."""
    if len(vector) != dim:
        raise FaceMatchError(f"embedding has {len(vector)} values, expected {dim}")
    values = tuple(float(v) for v in vector)
    if not all(math.isfinite(v) for v in values):
        raise FaceMatchError("embedding contains non-finite values")
    norm = math.sqrt(math.fsum(v * v for v in values))
    if norm == 0.0:
        raise FaceMatchError("embedding is a zero vector")
    return tuple(v / norm for v in values)


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two already-normalised vectors."""
    return math.fsum(x * y for x, y in zip(a, b, strict=True))


class FaceGallery:
    """Enrolled embeddings, held in memory and rebuilt on enrollment changes."""

    def __init__(
        self, entries: Iterable[GalleryEntry] = (), *, dim: int = DEFAULT_DIM
    ) -> None:
        self.dim = dim
        self._entries: list[GalleryEntry] = []
        for entry in entries:
            self._add(entry)

    @classmethod
    def from_vectors(
        cls,
        rows: Iterable[tuple[int, int, Sequence[float]]],
        *,
        dim: int = DEFAULT_DIM,
    ) -> FaceGallery:
        """Build from (embedding_id, member_id, raw_vector) rows."""
        return cls(
            (GalleryEntry(eid, mid, normalise(vec, dim=dim)) for eid, mid, vec in rows),
            dim=dim,
        )

    def _add(self, entry: GalleryEntry) -> None:
        if len(entry.vector) != self.dim:
            raise FaceMatchError("gallery entry has the wrong dimension")
        self._entries.append(entry)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def member_ids(self) -> frozenset[int]:
        return frozenset(e.member_id for e in self._entries)

    def match(
        self,
        observations: Sequence[FaceObservation],
        *,
        threshold: float,
        min_margin: float,
    ) -> MatchResult:
        """Classify the faces seen in one frame.

        Exactly one usable face is required. More than one face is reported
        as MULTIPLE_FACES rather than guessing who is at the door.
        """
        if not 0.0 < threshold <= 1.0 or not 0.0 <= min_margin < 1.0:
            raise FaceMatchError("threshold must be in (0, 1] and margin in [0, 1)")

        def result(status: MatchStatus, **extra: Any) -> MatchResult:
            return MatchResult(
                status, threshold=threshold, min_margin=min_margin, **extra
            )

        if not observations:
            return result(MatchStatus.NO_FACE)
        if len(observations) > 1:
            return result(
                MatchStatus.MULTIPLE_FACES, detail=f"{len(observations)} faces"
            )
        face = observations[0]
        if not face.quality_ok:
            return result(MatchStatus.POOR_QUALITY, detail=face.quality_reason)
        probe = normalise(face.embedding, dim=self.dim)
        if not self._entries:
            return result(MatchStatus.UNKNOWN, detail="empty gallery")

        # Best score per member, so several samples of one person never count
        # as competing candidates for the margin rule.
        best: dict[int, tuple[float, int]] = {}
        for entry in self._entries:
            score = cosine(probe, entry.vector)
            current = best.get(entry.member_id)
            if current is None or score > current[0]:
                best[entry.member_id] = (score, entry.embedding_id)
        ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)
        member_id, (score, embedding_id) = ranked[0]
        second = ranked[1][1][0] if len(ranked) > 1 else None

        if score < threshold:
            return result(MatchStatus.UNKNOWN, score=score, second_score=second)
        if second is not None and score - second < min_margin:
            return result(MatchStatus.AMBIGUOUS, score=score, second_score=second)
        return result(
            MatchStatus.MATCHED,
            member_id=member_id,
            embedding_id=embedding_id,
            score=score,
            second_score=second,
        )
