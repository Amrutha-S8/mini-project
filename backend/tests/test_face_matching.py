"""Face matching over precomputed embeddings (M06). Stdlib only.

Uses synthetic vectors, not real faces: this tests the matching logic, not
recognition accuracy. Real accuracy depends on the model and is measured once
the vision stack runs.
"""

from __future__ import annotations

import math

import pytest

from app.domain.face_matching import (
    FaceGallery,
    FaceMatchError,
    FaceObservation,
    MatchStatus,
    cosine,
    normalise,
)

DIM = 8


def vec(*head: float) -> list[float]:
    return list(head) + [0.0] * (DIM - len(head))


@pytest.fixture
def gallery() -> FaceGallery:
    return FaceGallery.from_vectors(
        [
            (1, 7, vec(1, 0, 0)),
            (2, 7, vec(0.9, 0.1, 0)),  # second sample of member 7
            (3, 8, vec(0, 1, 0)),
        ],
        dim=DIM,
    )


def observe(*head: float, quality_ok: bool = True) -> list[FaceObservation]:
    return [FaceObservation(vec(*head), quality_ok=quality_ok)]


def test_normalise_produces_unit_vector() -> None:
    v = normalise(vec(3, 4), dim=DIM)
    assert math.isclose(math.fsum(x * x for x in v), 1.0)
    assert math.isclose(cosine(v, v), 1.0)


@pytest.mark.parametrize(
    "bad",
    [vec(0), [1.0] * (DIM - 1), vec(float("nan")), vec(float("inf"))],
)
def test_invalid_embeddings_rejected(bad: list[float]) -> None:
    with pytest.raises(FaceMatchError):
        normalise(bad, dim=DIM)


def test_match_identifies_enrolled_member(gallery: FaceGallery) -> None:
    r = gallery.match(observe(1, 0.05, 0), threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.MATCHED and r.member_id == 7
    assert r.score is not None and r.score > 0.99


def test_multiple_samples_of_one_member_do_not_make_it_ambiguous(
    gallery: FaceGallery,
) -> None:
    r = gallery.match(observe(0.95, 0.05, 0), threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.MATCHED and r.member_id == 7


def test_below_threshold_is_unknown(gallery: FaceGallery) -> None:
    r = gallery.match(observe(0, 0, 1), threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.UNKNOWN and r.member_id is None


def test_close_scores_are_ambiguous(gallery: FaceGallery) -> None:
    r = gallery.match(observe(1, 1, 0), threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.AMBIGUOUS and r.member_id is None


def test_no_face(gallery: FaceGallery) -> None:
    assert (
        gallery.match([], threshold=0.6, min_margin=0.1).status is MatchStatus.NO_FACE
    )


def test_multiple_faces_not_guessed(gallery: FaceGallery) -> None:
    faces = observe(1, 0, 0) + observe(0, 1, 0)
    r = gallery.match(faces, threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.MULTIPLE_FACES and r.member_id is None


def test_poor_quality_not_matched(gallery: FaceGallery) -> None:
    faces = [FaceObservation(vec(1, 0, 0), quality_ok=False, quality_reason="too_dark")]
    r = gallery.match(faces, threshold=0.6, min_margin=0.1)
    assert (r.status, r.detail) == (MatchStatus.POOR_QUALITY, "too_dark")


def test_empty_gallery_is_unknown() -> None:
    r = FaceGallery(dim=DIM).match(observe(1, 0, 0), threshold=0.6, min_margin=0.1)
    assert r.status is MatchStatus.UNKNOWN


def test_matching_never_enrolls(gallery: FaceGallery) -> None:
    before = len(gallery)
    gallery.match(observe(0, 0, 1), threshold=0.6, min_margin=0.1)
    assert len(gallery) == before
    assert gallery.member_ids == frozenset({7, 8})


@pytest.mark.parametrize("threshold,margin", [(0.0, 0.1), (1.1, 0.1), (0.5, 1.0)])
def test_invalid_thresholds_rejected(
    gallery: FaceGallery, threshold: float, margin: float
) -> None:
    with pytest.raises(FaceMatchError):
        gallery.match(observe(1), threshold=threshold, min_margin=margin)


def test_wrong_dimension_probe_rejected(gallery: FaceGallery) -> None:
    with pytest.raises(FaceMatchError):
        gallery.match([FaceObservation([1.0, 0.0])], threshold=0.6, min_margin=0.1)
