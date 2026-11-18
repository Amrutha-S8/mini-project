"""Event normalisation and the central pipeline (M10/M11 core). Stdlib only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.domain.events import (
    EVENT_TYPES,
    EventValidationError,
    Modality,
    Severity,
    normalise_event,
    parse_timestamp,
)
from app.domain.pipeline import EventPipeline, MemorySink, Status

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)


def raw(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_type": "access.denied",
        "source_module": "access_engine",
        "occurred_at": "2026-11-16T09:59:58Z",
        "outcome": "blocked",
        "door_id": "main",
        "decision_id": "d1",
    }
    base.update(overrides)
    return base


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def pipeline(sink: MemorySink) -> EventPipeline:
    return EventPipeline(sink, clock=lambda: NOW)


# --- normalisation -----------------------------------------------------------


def test_normalises_type_modality_severity_and_utc() -> None:
    e = normalise_event(raw(), received_at=NOW)
    assert e.event_type == "access.denied" and e.modality is Modality.ACCESS
    assert e.severity is Severity.LOW and e.suspicious
    assert e.occurred_at == datetime(2026, 11, 16, 9, 59, 58, tzinfo=UTC)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-11-16T15:30:00+05:30", datetime(2026, 11, 16, 10, 0, tzinfo=UTC)),
        (1794823200, datetime(2026, 11, 16, 10, 0, tzinfo=UTC)),
        (
            datetime(2026, 11, 16, 10, 0, tzinfo=UTC),
            datetime(2026, 11, 16, 10, 0, tzinfo=UTC),
        ),
    ],
)
def test_timestamps_converted_to_utc(value: Any, expected: datetime) -> None:
    assert parse_timestamp(value)[0] == expected


def test_naive_timestamp_flagged() -> None:
    e = normalise_event(raw(occurred_at="2026-11-16T09:00:00"), received_at=NOW)
    assert e.timestamp_assumed_utc


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"event_type": "made.up"}, "unknown event_type"),
        ({"source_module": ""}, "source_module"),
        ({"source_module": "Bad Module"}, "source_module"),
        ({"occurred_at": None}, "timestamp"),
        ({"occurred_at": "yesterday"}, "unparseable"),
        ({"occurred_at": -5}, "out of range"),
        ({"occurred_at": True}, "timestamp"),
        ({"outcome": "maybe"}, "outcome"),
        ({"severity": "apocalyptic"}, "severity"),
        ({"details": ["not", "a", "mapping"]}, "details"),
        ({"member_id": -1}, "member_id"),
        ({"member_id": "7"}, "member_id"),
        ({"session_id": "x" * 200}, "session_id"),
        ({"ip_address": "1.2.3.4; DROP TABLE"}, "ip_address"),
    ],
)
def test_invalid_events_rejected(overrides: dict[str, Any], match: str) -> None:
    with pytest.raises(EventValidationError, match=match):
        normalise_event(raw(**overrides), received_at=NOW)


def test_details_redacted_and_bounded() -> None:
    e = normalise_event(
        raw(
            details={
                "password": "hunter2",
                "access_token": "eyJ...",
                "embedding": [0.1] * 512,
                "snapshot": b"\x00" * 1024,
                "note": "x" * 2000,
                "nested": {"api_key": "k", "ok": 1},
            }
        ),
        received_at=NOW,
    )
    d = e.details
    assert d["password"] == d["access_token"] == d["embedding"] == "***REDACTED***"
    assert d["snapshot"] == "<1024 bytes>"
    assert len(d["note"]) == 500
    assert d["nested"] == {"api_key": "***REDACTED***", "ok": 1}


def test_explicit_severity_overrides_default() -> None:
    e = normalise_event(raw(severity="critical"), received_at=NOW)
    assert e.severity is Severity.CRITICAL


def test_every_event_type_has_a_modality_and_severity() -> None:
    for name, etype in EVENT_TYPES.items():
        assert etype.name == name and etype.modality and etype.default_severity >= 0


# --- pipeline ----------------------------------------------------------------


def test_valid_event_persisted_then_dispatched(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    order: list[str] = []
    pipeline.subscribe(lambda e: order.append(f"listener saw {len(sink.events)}"))
    result = pipeline.ingest(raw())
    assert result.status is Status.ACCEPTED
    assert len(sink.events) == 1
    assert order == ["listener saw 1"], "persist must happen before dispatch"


def test_invalid_event_rejected_not_stored(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    result = pipeline.ingest(raw(event_type="nope"))
    assert result.status is Status.REJECTED and sink.events == []
    assert pipeline.stats.rejected == 1


def test_same_event_id_and_content_is_duplicate(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """An idempotent retry of one delivery is stored once."""
    pipeline.ingest(raw(event_id="abc"))
    assert pipeline.ingest(raw(event_id="abc")).status is Status.DUPLICATE
    assert len(sink.events) == 1 and pipeline.stats.duplicates == 1


def test_reused_event_id_with_different_content_is_stored_rekeyed(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """P2: an id reused for a different event must not hide that event."""
    pipeline.ingest(raw(event_id="abc"))
    second = pipeline.ingest(raw(event_id="abc", decision_id="d2"))
    assert second.status is Status.ACCEPTED
    assert "event_id_conflict_rekeyed" in second.warnings
    assert len(sink.events) == 2
    stored = sink.events[1]
    assert stored.event_id != "abc" and stored.decision_id == "d2"
    assert stored.details["event_id_conflict"] == "abc"
    assert pipeline.stats.id_conflicts == 1 and pipeline.stats.duplicates == 0


def test_same_facts_without_event_id_are_all_stored(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """P2 regression: identical facts are separate events, never merged."""
    pipeline.ingest(raw(occurred_at="2026-11-16T09:59:58.1Z"))
    second = pipeline.ingest(raw(occurred_at="2026-11-16T09:59:58.1Z"))
    assert second.status is Status.ACCEPTED and len(sink.events) == 2
    assert sink.events[0].event_id != sink.events[1].event_id
    assert pipeline.stats.duplicates == 0


def test_different_decisions_are_not_duplicates(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    pipeline.ingest(raw(decision_id="d1"))
    pipeline.ingest(raw(decision_id="d2"))
    assert len(sink.events) == 2


def test_far_future_timestamp_rejected(pipeline: EventPipeline) -> None:
    future = (NOW + timedelta(hours=1)).isoformat()
    assert pipeline.ingest(raw(occurred_at=future)).status is Status.REJECTED


def test_quality_warnings_recorded(pipeline: EventPipeline) -> None:
    result = pipeline.ingest(raw(door_id=None, occurred_at="2026-11-16T09:00:00"))
    assert set(result.warnings) == {"missing_door_id", "naive_timestamp_assumed_utc"}
    assert pipeline.stats.warnings["missing_door_id"] == 1


def test_sink_failure_reported_and_not_dispatched() -> None:
    class BrokenSink:
        def persist(self, event: Any) -> None:
            raise OSError("disk full")

    dispatched: list[Any] = []
    p = EventPipeline(BrokenSink(), clock=lambda: NOW)
    p.subscribe(dispatched.append)
    result = p.ingest(raw())
    assert result.status is Status.SINK_FAILED and result.error == "OSError"
    assert dispatched == []
    # Not remembered: a retry after recovery is accepted, not a "duplicate".
    good = MemorySink()
    p._sink = good  # type: ignore[attr-defined]
    assert p.ingest(raw()).status is Status.ACCEPTED


def test_listener_failure_isolated(pipeline: EventPipeline, sink: MemorySink) -> None:
    seen: list[Any] = []

    def broken(_e: Any) -> None:
        raise RuntimeError("notifier down")

    pipeline.subscribe(broken)
    pipeline.subscribe(seen.append)
    assert pipeline.ingest(raw()).status is Status.ACCEPTED
    assert len(seen) == 1 and pipeline.stats.listener_failures == 1


def test_stats_add_up(pipeline: EventPipeline) -> None:
    pipeline.ingest_many(
        [
            raw(event_id="a"),
            raw(event_id="a"),
            raw(event_type="bad"),
            raw(decision_id="z"),
        ]
    )
    s = pipeline.stats
    assert (s.received, s.accepted, s.duplicates, s.rejected) == (4, 2, 1, 1)
