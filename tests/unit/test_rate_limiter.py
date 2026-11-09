"""Component tests: password failure rate limiter.

State transition model (per key):

      record_failure (n < max-1)          record_failure (n == max-1)
  OPEN ---------------------------> OPEN ------------------------------> LOCKED
   ^                                                                       |
   |  window elapses since oldest failure / record_success                |
   +-----------------------------------------------------------------------+

Tests reach every state and every valid transition (valid-transition coverage), plus
BVA on the count and window thresholds.
"""

import pytest

from garmin_mcp.security import FailureRateLimiter

pytestmark = [pytest.mark.risk("R01")]


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def limiter(clock):
    return FailureRateLimiter(per_key_max=5, per_key_window=900, global_max=30,
                              global_window=3600, clock=clock)


@pytest.mark.parametrize(("failures", "locked"), [(4, False), (5, True), (6, True)])
def test_count_boundary(limiter, failures, locked):
    for _ in range(failures):
        limiter.record_failure("1.2.3.4")
    assert limiter.is_locked("1.2.3.4") is locked


def test_open_to_locked_to_open_by_window(limiter, clock):
    for _ in range(5):
        limiter.record_failure("ip")
    assert limiter.is_locked("ip")                     # LOCKED
    clock.t += 899
    assert limiter.is_locked("ip")                     # window - 1: still LOCKED
    clock.t += 1
    assert not limiter.is_locked("ip")                 # window: OPEN again


def test_sliding_window_counts_only_recent(limiter, clock):
    for _ in range(4):
        limiter.record_failure("ip")
    clock.t += 901                                      # first four age out
    limiter.record_failure("ip")
    assert not limiter.is_locked("ip")


def test_success_resets_key(limiter):
    for _ in range(4):
        limiter.record_failure("ip")
    limiter.record_success("ip")
    for _ in range(4):
        limiter.record_failure("ip")
    assert not limiter.is_locked("ip")


def test_keys_are_independent(limiter):
    for _ in range(5):
        limiter.record_failure("attacker")
    assert limiter.is_locked("attacker")
    assert not limiter.is_locked("owner")


@pytest.mark.parametrize(("failures", "locked"), [(29, False), (30, True), (31, True)])
def test_global_boundary_across_many_ips(limiter, failures, locked):
    """Distributed guessing from many IPs still hits the global cap."""
    for i in range(failures):
        limiter.record_failure(f"10.0.0.{i}")
    assert limiter.is_locked("fresh-ip") is locked


def test_global_lock_survives_success_on_one_key(limiter):
    for i in range(30):
        limiter.record_failure(f"10.0.0.{i}")
    limiter.record_success("10.0.0.1")
    assert limiter.is_locked("10.0.0.1")


def test_global_window_expiry(limiter, clock):
    for i in range(30):
        limiter.record_failure(f"10.0.0.{i}")
    clock.t += 3600
    assert not limiter.is_locked("any")


@pytest.mark.risk("R07")
@pytest.mark.parametrize(("keys", "expected_size"), [(2, 2), (3, 3), (4, 3)])
def test_memory_bound_on_keys(clock, keys, expected_size):
    lim = FailureRateLimiter(per_key_max=5, max_keys=3, global_max=10**6, clock=clock)
    for i in range(keys):
        clock.t += 1
        lim.record_failure(f"ip{i}")
    assert len(lim._hits) == expected_size
    if keys > 3:
        assert "ip0" not in lim._hits   # oldest evicted
