"""Rate limiter and login throttle (SR-AUTH-11, SR-AUTH-13, DD-05). Stdlib only."""

from __future__ import annotations

import math
import threading

import pytest

from app.core.rate_limit import LoginThrottle, SlidingWindowLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def _throttle(clock: FakeClock, **overrides: int) -> LoginThrottle:
    params = {
        "ip_limit": 20,
        "ip_window_seconds": 300,
        "failure_limit": 5,
        "failure_window_seconds": 900,
        "refresh_limit": 60,
        "refresh_window_seconds": 300,
    }
    params.update(overrides)
    return LoginThrottle(clock=clock, **params)  # type: ignore[arg-type]


def test_allows_up_to_limit_then_blocks(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=3, window_seconds=60, clock=clock)
    assert [limiter.hit("k") for _ in range(3)] == [None, None, None]
    delay = limiter.hit("k")
    assert delay is not None and math.isclose(delay, 60)


def test_retry_after_shrinks_and_window_expires(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60, clock=clock)
    limiter.hit("k")
    clock.now += 30
    assert math.isclose(limiter.retry_after("k") or 0, 30)
    clock.now += 30.001
    assert limiter.hit("k") is None


def test_blocked_hit_is_not_recorded(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60, clock=clock)
    limiter.hit("k")
    clock.now += 59
    assert limiter.hit("k") is not None
    clock.now += 1.001
    assert limiter.hit("k") is None, "a rejected attempt must not extend the block"


def test_keys_are_isolated_and_reset_clears(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60, clock=clock)
    limiter.hit("a")
    assert limiter.hit("b") is None
    limiter.reset("a")
    assert limiter.retry_after("a") is None


def test_memory_is_bounded(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60, clock=clock, max_keys=3)
    for key in "wxyz":
        limiter.record(key)
    assert len(limiter) == 3
    assert limiter.retry_after("w") is None, "least recently used key evicted"
    assert limiter.retry_after("z") is not None


def test_expired_keys_are_dropped(clock: FakeClock) -> None:
    limiter = SlidingWindowLimiter(limit=2, window_seconds=10, clock=clock)
    limiter.record("k")
    clock.now += 11
    assert limiter.retry_after("k") is None
    assert len(limiter) == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0, "window_seconds": 1},
        {"limit": 1, "window_seconds": 0},
        {"limit": 1, "window_seconds": 1, "max_keys": 0},
    ],
)
def test_invalid_configuration_rejected(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        SlidingWindowLimiter(**kwargs)  # type: ignore[arg-type]


def test_exact_count_under_thread_contention() -> None:
    limiter = SlidingWindowLimiter(limit=500, window_seconds=60)
    allowed: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(100):
            ok = limiter.hit("shared") is None
            with lock:
                allowed.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(allowed) == 500


# --- LoginThrottle -----------------------------------------------------------

ADMIN = "admin@home.example"
ATTACKER_IP = "203.0.113.9"
ADMIN_IP = "192.168.1.10"


def _fail(throttle: LoginThrottle, ip: str, email: str, n: int) -> None:
    for _ in range(n):
        assert throttle.before_login(ip, email) is None
        throttle.login_failed(ip, email)


def test_attacker_ip_blocked_after_failure_limit(clock: FakeClock) -> None:
    throttle = _throttle(clock)
    _fail(throttle, ATTACKER_IP, ADMIN, 5)
    assert throttle.before_login(ATTACKER_IP, ADMIN) is not None


def test_admin_not_locked_out_by_attacker(clock: FakeClock) -> None:
    """The defence against deliberate administrator lockout."""
    throttle = _throttle(clock)
    _fail(throttle, ATTACKER_IP, ADMIN, 5)
    assert throttle.before_login(ADMIN_IP, ADMIN) is None


def test_email_key_is_normalised(clock: FakeClock) -> None:
    throttle = _throttle(clock)
    _fail(throttle, ATTACKER_IP, ADMIN, 5)
    assert throttle.before_login(ATTACKER_IP, "  Admin@Home.EXAMPLE ") is not None


def test_attacker_can_still_try_other_accounts_until_ip_cap(clock: FakeClock) -> None:
    throttle = _throttle(clock, ip_limit=8)
    _fail(throttle, ATTACKER_IP, ADMIN, 5)
    assert throttle.before_login(ATTACKER_IP, "other@home.example") is None
    assert throttle.before_login(ATTACKER_IP, "third@home.example") is None
    assert throttle.before_login(ATTACKER_IP, "fourth@home.example") is None
    assert throttle.before_login(ATTACKER_IP, "fifth@home.example") is not None


def test_unknown_and_known_emails_throttled_identically(clock: FakeClock) -> None:
    """The throttle never consults the database, so it cannot reveal accounts."""
    known = _throttle(clock)
    unknown = _throttle(clock)
    _fail(known, ATTACKER_IP, ADMIN, 5)
    _fail(unknown, ATTACKER_IP, "nobody@home.example", 5)
    assert known.before_login(ATTACKER_IP, ADMIN) == unknown.before_login(
        ATTACKER_IP, "nobody@home.example"
    )


def test_success_resets_failure_count(clock: FakeClock) -> None:
    throttle = _throttle(clock)
    _fail(throttle, ADMIN_IP, ADMIN, 4)
    throttle.login_succeeded(ADMIN_IP, ADMIN)
    _fail(throttle, ADMIN_IP, ADMIN, 4)
    assert throttle.before_login(ADMIN_IP, ADMIN) is None


def test_failure_block_expires(clock: FakeClock) -> None:
    throttle = _throttle(clock)
    _fail(throttle, ATTACKER_IP, ADMIN, 5)
    clock.now += 901
    assert throttle.before_login(ATTACKER_IP, ADMIN) is None


def test_refresh_is_capped_per_ip(clock: FakeClock) -> None:
    throttle = _throttle(clock, refresh_limit=2)
    assert throttle.before_refresh(ATTACKER_IP) is None
    assert throttle.before_refresh(ATTACKER_IP) is None
    assert throttle.before_refresh(ATTACKER_IP) is not None
    assert throttle.before_refresh(ADMIN_IP) is None


def test_missing_client_ip_is_still_limited(clock: FakeClock) -> None:
    throttle = _throttle(clock, ip_limit=1)
    assert throttle.before_login(None, ADMIN) is None
    assert throttle.before_login(None, "x@home.example") is not None
