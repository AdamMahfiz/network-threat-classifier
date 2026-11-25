"""
Security helpers for Network Threat Classifier 2.0.

LoginThrottle  - in-memory lockout after repeated failed logins (per username and per client IP).
                 Good for a single-process deployment. For multiple workers, move the
                 counters to a shared store such as Redis.
SECURITY_HEADERS - headers added to every response.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Dict, Deque


class LoginThrottle:
    def __init__(self, max_failures: int = 5, lockout_seconds: int = 900, clock=time.monotonic):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures: Dict[str, Deque[float]] = defaultdict(deque)
        self._locked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _key(self, scope: str, value: str) -> str:
        return f"{scope}:{(value or '').strip().lower()}"

    def is_locked(self, username: str, ip: str) -> bool:
        with self._lock:
            now = self._clock()
            return any(
                self._locked_until.get(k, 0) > now
                for k in (self._key('user', username), self._key('ip', ip))
            )

    def seconds_remaining(self, username: str, ip: str) -> int:
        with self._lock:
            now = self._clock()
            remaining = [
                self._locked_until.get(k, 0) - now
                for k in (self._key('user', username), self._key('ip', ip))
            ]
            return max(0, int(max(remaining)))

    def record_failure(self, username: str, ip: str) -> None:
        with self._lock:
            now = self._clock()
            window_start = now - self.lockout_seconds
            for k in (self._key('user', username), self._key('ip', ip)):
                q = self._failures[k]
                q.append(now)
                while q and q[0] < window_start:
                    q.popleft()
                if len(q) >= self.max_failures:
                    self._locked_until[k] = now + self.lockout_seconds
                    q.clear()

    def record_success(self, username: str, ip: str) -> None:
        with self._lock:
            self._failures.pop(self._key('user', username), None)
            self._locked_until.pop(self._key('user', username), None)


SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
}
