"""UTC time provider.

Injectable so tests can control time without monkeypatching ``datetime``.
All persisted timestamps are UTC (DATABASE_DESIGN.md design rule 4).

Pure stdlib — no third-party imports, so this module is importable and
testable in any environment.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Time source abstraction."""

    def now(self) -> datetime:  # pragma: no cover - protocol definition
        ...


class SystemClock:
    """Real clock. Always returns timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """Fixed clock for deterministic tests."""

    def __init__(self, fixed: datetime) -> None:
        if fixed.tzinfo is None:
            raise ValueError("FrozenClock requires a timezone-aware datetime")
        self._fixed = fixed.astimezone(UTC)

    def now(self) -> datetime:
        return self._fixed

    def advance(self, *, seconds: float) -> None:
        from datetime import timedelta

        self._fixed = self._fixed + timedelta(seconds=seconds)


_default_clock: Clock = SystemClock()


def utc_now() -> datetime:
    """Current UTC time from the default clock."""
    return _default_clock.now()


def to_iso(value: datetime) -> str:
    """Serialise a datetime to a UTC ISO-8601 string.

    Naive datetimes are treated as UTC rather than silently shifted.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()
