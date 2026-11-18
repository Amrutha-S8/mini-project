"""Evaluation metrics and test-dataset loading (RAG stage 17, routing, safety).

Metrics are plain functions over ids, so the same code scores a real
retrieval run later. Today only routing and the deterministic safety layers
can be evaluated for real; retrieval quality needs the real embedding model
and is not measured yet.

Metrics:

* ``precision_at_k``, ``recall_at_k``, ``reciprocal_rank``, ``ndcg_at_k``
  (binary relevance) for retrieval;
* ``citation_precision`` and ``citation_recall`` for answers;
* routing accuracy, refusal precision and recall, and per-case failures
  from ``evaluate_routing``.

Dataset format: JSON Lines, one case per line, validated on load.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from app.ai.core.routing import Refusal, Route, RoutePlan
from app.ai.core.types import Role, UserContext


def precision_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k < 1:
        raise ValueError("k must be positive")
    top = list(retrieved)[:k]
    return sum(1 for r in top if r in relevant) / k


def recall_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k < 1:
        raise ValueError("k must be positive")
    if not relevant:
        return 1.0
    top = set(list(retrieved)[:k])
    return len(top & relevant) / len(relevant)


def reciprocal_rank(retrieved: Sequence[str], relevant: set[str]) -> float:
    for rank, item in enumerate(retrieved, start=1):
        if item in relevant:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k < 1:
        raise ValueError("k must be positive")
    dcg = sum(
        1.0 / math.log2(i + 2)
        for i, item in enumerate(list(retrieved)[:k])
        if item in relevant
    )
    ideal = sum(1.0 / math.log2(i + 2) for i in range(min(k, len(relevant))))
    return dcg / ideal if ideal else 1.0


def citation_precision(cited: Iterable[str], relevant: set[str]) -> float:
    cited_set = set(cited)
    if not cited_set:
        return 1.0 if not relevant else 0.0
    return len(cited_set & relevant) / len(cited_set)


def citation_recall(cited: Iterable[str], relevant: set[str]) -> float:
    if not relevant:
        return 1.0
    return len(set(cited) & relevant) / len(relevant)


def mean(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0


class DatasetError(ValueError):
    pass


@dataclass(frozen=True)
class RoutingCase:
    case_id: str
    question: str
    role: Role
    expected_routes: frozenset[Route]
    expected_refusal: Refusal | None
    note: str = ""


def load_routing_cases(path: Path) -> list[RoutingCase]:
    cases: list[RoutingCase] = []
    seen: set[str] = set()
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            raw = json.loads(line)
            case = RoutingCase(
                case_id=str(raw["id"]),
                question=str(raw["question"]),
                role=Role(raw["role"]),
                expected_routes=frozenset(Route(r) for r in raw.get("routes", [])),
                expected_refusal=(
                    Refusal(raw["refusal"]) if raw.get("refusal") else None
                ),
                note=str(raw.get("note", "")),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise DatasetError(f"line {n}: {exc}") from None
        if case.case_id in seen:
            raise DatasetError(f"line {n}: duplicate id {case.case_id}")
        if bool(case.expected_routes) == bool(case.expected_refusal):
            raise DatasetError(f"line {n}: give either routes or a refusal")
        seen.add(case.case_id)
        cases.append(case)
    return cases


@dataclass
class RoutingReport:
    total: int = 0
    correct: int = 0
    refusals_expected: int = 0
    refusals_correct: int = 0
    false_refusals: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def refusal_recall(self) -> float:
        if not self.refusals_expected:
            return 1.0
        return self.refusals_correct / self.refusals_expected


def evaluate_routing(
    cases: Sequence[RoutingCase],
    router: Callable[[str, UserContext], RoutePlan],
) -> RoutingReport:
    report = RoutingReport()
    for case in cases:
        ctx = UserContext(user_id=1, role=case.role.value, is_active=True, member_id=1)
        plan = router(case.question, ctx)
        report.total += 1
        if case.expected_refusal is not None:
            report.refusals_expected += 1
            ok = plan.refusal is case.expected_refusal
            report.refusals_correct += ok
        else:
            ok = plan.refusal is None and set(plan.routes) == case.expected_routes
            if plan.refusal is not None:
                report.false_refusals += 1
        report.correct += ok
        if not ok:
            got = plan.refusal.value if plan.refusal else ",".join(plan.routes)
            report.failures.append(f"{case.case_id}: got {got}")
    return report
