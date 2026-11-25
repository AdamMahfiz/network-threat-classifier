from src.threat_classifier.utils.security import LoginThrottle


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_locks_after_max_failures_and_unlocks_after_window():
    clock = FakeClock()
    t = LoginThrottle(max_failures=3, lockout_seconds=60, clock=clock)
    for _ in range(3):
        t.record_failure('alice', '10.0.0.1')
    assert t.is_locked('alice', '10.0.0.9')  # same user, different IP is still locked
    clock.now += 61
    assert not t.is_locked('alice', '10.0.0.1')


def test_success_clears_user_failures_but_not_ip_counter():
    clock = FakeClock()
    t = LoginThrottle(max_failures=3, lockout_seconds=60, clock=clock)
    t.record_failure('bob', '10.0.0.2')
    t.record_failure('bob', '10.0.0.2')
    t.record_success('bob', '10.0.0.2')
    # The user's counter was reset, so one more failure from a new IP does not lock the account.
    t.record_failure('bob', '10.0.0.9')
    assert not t.is_locked('bob', '10.0.0.9')
    # The IP keeps its own count, so brute force from one address is still stopped.
    t.record_failure('bob', '10.0.0.2')
    assert t.is_locked('someone_else', '10.0.0.2')


def test_ip_lockout_blocks_other_usernames():
    clock = FakeClock()
    t = LoginThrottle(max_failures=2, lockout_seconds=60, clock=clock)
    t.record_failure('u1', '203.0.113.5')
    t.record_failure('u2', '203.0.113.5')
    assert t.is_locked('u3', '203.0.113.5')
    assert not t.is_locked('u3', '198.51.100.1')


def test_old_failures_fall_out_of_window():
    clock = FakeClock()
    t = LoginThrottle(max_failures=3, lockout_seconds=60, clock=clock)
    t.record_failure('carol', '10.0.0.3')
    t.record_failure('carol', '10.0.0.3')
    clock.now += 61
    t.record_failure('carol', '10.0.0.3')
    assert not t.is_locked('carol', '10.0.0.3')
