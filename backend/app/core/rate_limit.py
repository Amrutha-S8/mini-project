"""In-process rate limiting for authentication endpoints (stdlib only).

Sliding-window counters held in memory. They are per process and reset on
restart, which is one reason the backend runs a single Uvicorn worker.

Lockout model (DD-05): failures are counted per (client IP, submitted email),
never per account. Repeated failures against the admin's email block only the
failing client for that email; the admin can still sign in from elsewhere.
The submitted email is used whether or not an account exists, so a throttled
response reveals nothing about which emails are registered.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable

Clock = Callable[[], float]
UNKNOWN_CLIENT = "unknown"
_MAX_EMAIL = 320


class SlidingWindowLimiter:
    """At most ``limit`` events per key within any ``window_seconds`` span.

    Memory is bounded: each key keeps at most ``limit`` timestamps, and the
    least recently used keys are evicted beyond ``max_keys``.
    """

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock: Clock = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("limit, window_seconds and max_keys must be positive")
        self.limit = limit
        self.window = float(window_seconds)
        self.max_keys = max_keys
        self._clock = clock
        self._events: OrderedDict[Hashable, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def retry_after(self, key: Hashable) -> float | None:
        """Seconds until ``key`` may act again, or None if it is not limited."""
        with self._lock:
            now = self._clock()
            return self._retry(self._prune(key, now), now)

    def record(self, key: Hashable) -> None:
        """Count one event for ``key`` unconditionally."""
        with self._lock:
            now = self._clock()
            self._record(key, self._prune(key, now), now)

    def hit(self, key: Hashable) -> float | None:
        """Count one event if allowed. Returns None, or the retry delay."""
        with self._lock:
            now = self._clock()
            events = self._prune(key, now)
            delay = self._retry(events, now)
            if delay is None:
                self._record(key, events, now)
            return delay

    def reset(self, key: Hashable) -> None:
        with self._lock:
            self._events.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    # --- internals, called with the lock held --------------------------------

    def _prune(self, key: Hashable, now: float) -> deque[float] | None:
        events = self._events.get(key)
        if events is None:
            return None
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if not events:
            del self._events[key]
            return None
        return events

    def _retry(self, events: deque[float] | None, now: float) -> float | None:
        if events is None or len(events) < self.limit:
            return None
        return max(0.0, events[0] + self.window - now)

    def _record(self, key: Hashable, events: deque[float] | None, now: float) -> None:
        if events is None:
            events = deque()
            self._events[key] = events
        else:
            self._events.move_to_end(key)
        events.append(now)
        while len(events) > self.limit:
            events.popleft()
        while len(self._events) > self.max_keys:
            self._events.popitem(last=False)


class LoginThrottle:
    """The three limits applied to /auth/login and /auth/refresh."""

    def __init__(
        self,
        *,
        ip_limit: int,
        ip_window_seconds: float,
        failure_limit: int,
        failure_window_seconds: float,
        refresh_limit: int,
        refresh_window_seconds: float,
        clock: Clock = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        def make(limit: int, window: float) -> SlidingWindowLimiter:
            return SlidingWindowLimiter(
                limit=limit, window_seconds=window, clock=clock, max_keys=max_keys
            )

        self._ip = make(ip_limit, ip_window_seconds)
        self._failures = make(failure_limit, failure_window_seconds)
        self._refresh = make(refresh_limit, refresh_window_seconds)

    @staticmethod
    def _pair(ip: str | None, email: str) -> tuple[str, str]:
        return (ip or UNKNOWN_CLIENT, email.strip().lower()[:_MAX_EMAIL])

    def before_login(self, ip: str | None, email: str) -> float | None:
        """None if the attempt may proceed, else seconds to wait."""
        delay = self._failures.retry_after(self._pair(ip, email))
        if delay is not None:
            return delay
        return self._ip.hit(ip or UNKNOWN_CLIENT)

    def login_failed(self, ip: str | None, email: str) -> None:
        self._failures.record(self._pair(ip, email))

    def login_succeeded(self, ip: str | None, email: str) -> None:
        self._failures.reset(self._pair(ip, email))

    def before_refresh(self, ip: str | None) -> float | None:
        return self._refresh.hit(ip or UNKNOWN_CLIENT)
