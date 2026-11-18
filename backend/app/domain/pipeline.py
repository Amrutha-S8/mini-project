"""Central event pipeline (module M11 core, stdlib only).

validate/normalise -> quality checks -> de-duplicate -> persist -> dispatch

* Invalid events are rejected and counted, never stored.
* De-duplication uses only the producer's ``event_id`` (an idempotency key),
  so a retried delivery of the same event is stored once. Events are never
  merged because their facts look alike: five failed logins from one IP in
  the same second are five stored events (finding P2). An event without an
  ``event_id`` gets a fresh one and is always stored.
* Reusing an ``event_id`` for different content is not treated as a
  duplicate. The event is stored under a new id, the old id is kept in
  ``details["event_id_conflict"]``, and the conflict is counted, so a
  producer bug or a replayed id cannot hide an attempt.
* The pipeline records events and nothing else. Rate limiting lives in
  ``app.core.rate_limit`` and does not affect what is recorded.
* Persistence happens before dispatch, so a failing listener (notification,
  correlation) can never lose the record.
* A failing sink is reported to the caller and the event is not dispatched,
  so nothing downstream acts on an event that was not recorded.
* Listener failures are isolated and counted; they never stop the pipeline.

The operational sink will be SQLite through SQLAlchemy (the source of truth).
An in-memory sink is provided for tests and for running the core alone.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections import Counter, OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from app.domain.events import EventValidationError, SecurityEvent, normalise_event

Listener = Callable[[SecurityEvent], None]


class EventSink(Protocol):
    def persist(self, event: SecurityEvent) -> None: ...


class MemorySink:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def persist(self, event: SecurityEvent) -> None:
        self.events.append(event)


class Status(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    SINK_FAILED = "sink_failed"


@dataclass(frozen=True)
class IngestResult:
    status: Status
    event: SecurityEvent | None = None
    error: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass
class PipelineStats:
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    id_conflicts: int = 0
    rejected: int = 0
    sink_failures: int = 0
    listener_failures: int = 0
    warnings: Counter[str] = field(default_factory=Counter)
    rejection_reasons: Counter[str] = field(default_factory=Counter)


_NOT_CONTENT = frozenset({"event_id", "received_at"})


def content_digest(event: SecurityEvent) -> str:
    """Hash of everything the producer said, except the id and arrival time.

    Used only to tell an idempotent retry (same id, same content) from an id
    reused for a different event. It is never used to merge distinct ids.
    """
    facts = {f.name: getattr(event, f.name) for f in fields(event)}
    for name in _NOT_CONTENT:
        facts.pop(name)
    blob = json.dumps(facts, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class EventPipeline:
    def __init__(
        self,
        sink: EventSink,
        *,
        clock: Callable[[], datetime],
        dedupe_memory: int = 50_000,
        max_future_skew: timedelta = timedelta(minutes=5),
        max_age: timedelta = timedelta(days=7),
    ) -> None:
        """``dedupe_memory`` bounds how many recent event ids are remembered.

        A retry arriving after its id was evicted is stored a second time.
        That errs towards over-recording, never towards losing an event.
        """
        self._sink = sink
        self._clock = clock
        self._dedupe_memory = dedupe_memory
        self._max_future = max_future_skew
        self._max_age = max_age
        self._seen_ids: OrderedDict[str, str] = OrderedDict()
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()
        self.stats = PipelineStats()

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def ingest(self, raw: Mapping[str, Any]) -> IngestResult:
        received_at = self._clock()
        with self._lock:
            self.stats.received += 1
            try:
                event = normalise_event(raw, received_at=received_at)
            except EventValidationError as exc:
                self.stats.rejected += 1
                self.stats.rejection_reasons[str(exc).split(" ")[0]] += 1
                return IngestResult(Status.REJECTED, error=str(exc))

            warnings = self._quality(event)
            if warnings and "too_far_in_future" in warnings:
                self.stats.rejected += 1
                self.stats.rejection_reasons["too_far_in_future"] += 1
                return IngestResult(
                    Status.REJECTED, error="timestamp too far in the future"
                )
            seen_digest = self._seen_ids.get(event.event_id)
            if seen_digest is not None:
                if seen_digest == content_digest(event):
                    self.stats.duplicates += 1
                    return IngestResult(Status.DUPLICATE, event=event)
                event = self._rekey(event)
                warnings.append("event_id_conflict_rekeyed")
                self.stats.id_conflicts += 1

            for w in warnings:
                self.stats.warnings[w] += 1

            try:
                self._sink.persist(event)
            except Exception as exc:  # noqa: BLE001 - reported to the caller
                self.stats.sink_failures += 1
                return IngestResult(
                    Status.SINK_FAILED, event=event, error=type(exc).__name__
                )
            self._remember(event)
            self.stats.accepted += 1
            listeners = list(self._listeners)

        for listener in listeners:
            try:
                listener(event)
            except Exception:  # noqa: BLE001 - isolation is the point
                with self._lock:
                    self.stats.listener_failures += 1
        return IngestResult(Status.ACCEPTED, event=event, warnings=tuple(warnings))

    def ingest_many(self, raws: Sequence[Mapping[str, Any]]) -> list[IngestResult]:
        return [self.ingest(r) for r in raws]

    # --- internals ------------------------------------------------------------

    def _quality(self, event: SecurityEvent) -> list[str]:
        warnings: list[str] = []
        if event.timestamp_assumed_utc:
            warnings.append("naive_timestamp_assumed_utc")
        if event.occurred_at > event.received_at + self._max_future:
            warnings.append("too_far_in_future")
        if event.received_at - event.occurred_at > self._max_age:
            warnings.append("very_old_event")
        if event.modality.value in {"access", "door"} and event.door_id is None:
            warnings.append("missing_door_id")
        return warnings

    @staticmethod
    def _rekey(event: SecurityEvent) -> SecurityEvent:
        """Same content under a fresh id, keeping the reused id for audit."""
        details = dict(event.details)
        details["event_id_conflict"] = event.event_id
        return replace(event, event_id=uuid.uuid4().hex, details=details)

    def _remember(self, event: SecurityEvent) -> None:
        self._seen_ids[event.event_id] = content_digest(event)
        self._seen_ids.move_to_end(event.event_id)
        while len(self._seen_ids) > self._dedupe_memory:
            self._seen_ids.popitem(last=False)
