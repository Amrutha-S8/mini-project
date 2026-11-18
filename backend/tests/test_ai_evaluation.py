"""Evaluation metrics, checked against hand-computed values."""

from __future__ import annotations

import math

import pytest

from app.ai.core.evaluation import (
    citation_precision,
    citation_recall,
    mean,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)

RETRIEVED = ["a", "x", "b", "y", "c"]
RELEVANT = {"a", "b", "z"}


def test_precision_and_recall_at_k() -> None:
    assert precision_at_k(RETRIEVED, RELEVANT, 1) == 1.0
    assert precision_at_k(RETRIEVED, RELEVANT, 3) == pytest.approx(2 / 3)
    assert recall_at_k(RETRIEVED, RELEVANT, 3) == pytest.approx(2 / 3)
    assert recall_at_k(RETRIEVED, RELEVANT, 1) == pytest.approx(1 / 3)
    assert recall_at_k(RETRIEVED, set(), 3) == 1.0


def test_reciprocal_rank() -> None:
    assert reciprocal_rank(RETRIEVED, {"b"}) == pytest.approx(1 / 3)
    assert reciprocal_rank(RETRIEVED, {"q"}) == 0.0


def test_ndcg() -> None:
    expected_dcg = 1 / math.log2(2) + 1 / math.log2(4)
    ideal = 1 / math.log2(2) + 1 / math.log2(3) + 1 / math.log2(4)
    assert ndcg_at_k(RETRIEVED, RELEVANT, 3) == pytest.approx(expected_dcg / ideal)
    assert ndcg_at_k(["a", "b"], {"a", "b"}, 2) == pytest.approx(1.0)


def test_citation_metrics() -> None:
    assert citation_precision(["S1", "S2"], {"S1"}) == 0.5
    assert citation_recall(["S1"], {"S1", "S3"}) == 0.5
    assert citation_precision([], set()) == 1.0
    assert citation_precision([], {"S1"}) == 0.0


@pytest.mark.parametrize("fn", [precision_at_k, recall_at_k, ndcg_at_k])
def test_k_must_be_positive(fn) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        fn(RETRIEVED, RELEVANT, 0)


def test_mean() -> None:
    assert mean([1.0, 0.0, 0.5]) == 0.5 and mean([]) == 0.0
