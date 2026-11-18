"""Finding P2: every failed login attempt is its own auditable event.

The pipeline used to merge events with the same facts inside a 2-second
bucket, so a burst of failed logins from one IP was stored as one event.
These tests pin the fix: only an explicit ``event_id`` (the producer's
idempotency key) de-duplicates, rate limiting is independent of recording,
and redaction still applies. Stdlib only.
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.rate_limit import LoginThrottle
from app.domain.pipeline import EventPipeline, MemorySink, Status

NOW = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
SAME_INSTANT = "2026-11-16T09:59:59.500Z"


def failed_login(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_type": "auth.login_failed",
        "source_module": "auth_service",
        "occurred_at": SAME_INSTANT,
        "outcome": "failed",
        "ip_address": "203.0.113.7",
        "details": {"email": "admin@example.com", "password": "guess"},
    }
    base.update(overrides)
    return base


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def pipeline(sink: MemorySink) -> EventPipeline:
    return EventPipeline(sink, clock=lambda: NOW)


def test_probe_from_finding_p2_now_stores_all_five(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """The exact probe that failed: 5 failures, one IP, within 2 s, no ids."""
    statuses = [
        pipeline.ingest(failed_login(occurred_at=f"2026-11-16T09:59:58.{i}Z")).status
        for i in range(5)
    ]
    assert statuses == [Status.ACCEPTED] * 5
    assert len(sink.events) == 5


def test_identical_rapid_attempts_all_stored(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """Same IP, same email, same instant, same request id: still 20 events."""
    for _ in range(20):
        result = pipeline.ingest(failed_login(request_id="req-1"))
        assert result.status is Status.ACCEPTED
    assert len(sink.events) == 20
    assert len({e.event_id for e in sink.events}) == 20
    s = pipeline.stats
    assert (s.received, s.accepted, s.duplicates, s.id_conflicts) == (20, 20, 0, 0)


def test_attempts_from_different_ips_counted_per_ip(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    plan = {"203.0.113.7": 4, "198.51.100.2": 3, "2001:db8::1": 6}
    for ip, n in plan.items():
        for _ in range(n):
            pipeline.ingest(failed_login(ip_address=ip))
    assert Counter(e.ip_address for e in sink.events) == plan
    assert len(sink.events) == sum(plan.values())


def test_concurrent_attempts_all_stored_exactly_once() -> None:
    sink = MemorySink()
    pipeline = EventPipeline(sink, clock=lambda: NOW)
    threads, per_thread = 10, 50
    barrier = threading.Barrier(threads)
    errors: list[BaseException] = []

    def attack() -> None:
        try:
            barrier.wait()
            for _ in range(per_thread):
                assert pipeline.ingest(failed_login()).status is Status.ACCEPTED
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    workers = [threading.Thread(target=attack) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)
    assert not errors
    total = threads * per_thread
    assert len(sink.events) == total
    assert len({e.event_id for e in sink.events}) == total
    s = pipeline.stats
    assert (s.received, s.accepted, s.duplicates) == (total, total, 0)


def test_concurrent_retries_with_ids_stored_once_each() -> None:
    """Idempotency still works: each attempt delivered twice, stored once."""
    sink = MemorySink()
    pipeline = EventPipeline(sink, clock=lambda: NOW)
    threads, per_thread = 8, 40
    barrier = threading.Barrier(threads)

    def deliver(t: int) -> None:
        barrier.wait()
        for i in range(per_thread):
            for _ in range(2):  # original delivery plus one retry
                pipeline.ingest(failed_login(event_id=f"att-{t}-{i}"))

    workers = [threading.Thread(target=deliver, args=(t,)) for t in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)
    total = threads * per_thread
    assert len(sink.events) == total
    assert pipeline.stats.duplicates == total
    assert pipeline.stats.id_conflicts == 0


def test_reused_id_for_a_different_attempt_is_not_lost(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    pipeline.ingest(failed_login(event_id="att-1"))
    second = pipeline.ingest(failed_login(event_id="att-1", ip_address="198.51.100.2"))
    assert second.status is Status.ACCEPTED and len(sink.events) == 2
    assert [e.ip_address for e in sink.events] == ["203.0.113.7", "198.51.100.2"]
    assert sink.events[1].details["event_id_conflict"] == "att-1"
    assert pipeline.stats.id_conflicts == 1
    assert pipeline.stats.warnings["event_id_conflict_rekeyed"] == 1


def test_rate_limiting_independent_of_recording(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    """The throttle blocks; every attempt, blocked or not, is still recorded."""
    now = [1000.0]
    throttle = LoginThrottle(
        ip_limit=100,
        ip_window_seconds=300,
        failure_limit=5,
        failure_window_seconds=900,
        refresh_limit=60,
        refresh_window_seconds=300,
        clock=lambda: now[0],
    )
    ip, email = "203.0.113.7", "admin@example.com"
    attempts = 12
    for i in range(attempts):
        now[0] += 0.01
        when = f"2026-11-16T09:59:59.{i:02d}Z"
        if throttle.before_login(ip, email) is not None:
            pipeline.ingest(
                failed_login(
                    event_type="auth.login_throttled",
                    outcome="blocked",
                    occurred_at=when,
                )
            )
        else:
            throttle.login_failed(ip, email)
            pipeline.ingest(failed_login(occurred_at=when))

    types = Counter(e.event_type for e in sink.events)
    assert types == {"auth.login_failed": 5, "auth.login_throttled": 7}
    assert len(sink.events) == attempts

    # The reverse direction: recording events does not move the throttle.
    other_ip = "198.51.100.2"
    for _ in range(50):
        pipeline.ingest(failed_login(ip_address=other_ip))
    assert throttle.before_login(other_ip, email) is None


def test_redaction_preserved_for_every_attempt(
    pipeline: EventPipeline, sink: MemorySink
) -> None:
    guesses = [f"Guess-{i}-s3cret" for i in range(10)]
    for g in guesses:
        pipeline.ingest(
            failed_login(
                details={
                    "email": "admin@example.com",
                    "password": g,
                    "authorization": f"Bearer {g}",
                    "nested": {"api_key": g, "attempt": 1},
                }
            )
        )
    # Reused id with different content takes the rekey path; still redacted.
    pipeline.ingest(failed_login(event_id="dup", details={"password": guesses[0]}))
    pipeline.ingest(
        failed_login(
            event_id="dup", ip_address="198.51.100.2", details={"token": guesses[1]}
        )
    )
    assert len(sink.events) == 12
    for e in sink.events:
        text = repr(e)
        assert not any(g in text for g in guesses), "secret leaked into event"
    first = sink.events[0].details
    assert first["password"] == first["authorization"] == "***REDACTED***"
    assert first["nested"] == {"api_key": "***REDACTED***", "attempt": 1}
    assert sink.events[-1].details == {
        "token": "***REDACTED***",
        "event_id_conflict": "dup",
    }
