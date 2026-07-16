"""
Rate governance: per-token token buckets plus an AIMD concurrency controller.

Two independent throttles, because the backend has two independent ceilings:

  1. Rate: ~3 req/s per user identity (the tight one). Every LRQ API call
     (launch, each poll, cancel) is one request, so polls count against the
     budget too. Each service-user token gets its own TokenBucket at ~2.5 rps.

  2. Concurrency: a cap on simultaneously in-flight slices. The AIMD controller
     starts optimistic, multiplicatively backs off when the tenant returns 429s,
     and additively grows again after sustained success, so it self-tunes to
     whatever the backend tolerates right now instead of a hardcoded guess
     (same control law as TCP congestion control).
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator


class TokenBucket:
    """Classic token bucket. acquire() blocks until a token is available."""

    def __init__(self, rps: float, burst: int):
        self.rps = float(rps)
        self.capacity = float(max(1, burst))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, n: float = 1.0) -> float:
        """Block until n tokens are available. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rps)
                if self._tokens >= n:
                    self._tokens -= n
                    return waited
                needed = (n - self._tokens) / self.rps
            time.sleep(needed)
            waited += needed


class AIMDController:
    """Additive-increase / multiplicative-decrease concurrency limit.

    Callers gate work with `slot()`. Concurrency never exceeds the current limit.
    Report outcomes with on_success()/on_throttle() so the limit adapts.
    """

    def __init__(self, initial: int, minimum: int = 1, maximum: int = 64,
                 increase_after: int = 8):
        self._limit = float(max(minimum, min(initial, maximum)))
        self._min = minimum
        self._max = maximum
        self._increase_after = increase_after
        self._active = 0
        self._success_streak = 0
        self._cond = threading.Condition()

    @property
    def limit(self) -> int:
        return int(self._limit)

    def on_success(self) -> None:
        with self._cond:
            self._success_streak += 1
            if self._success_streak >= self._increase_after and self._limit < self._max:
                self._limit = min(self._max, self._limit + 1)
                self._success_streak = 0
                self._cond.notify_all()

    def on_throttle(self) -> None:
        """Multiplicative decrease on a 429/backoff signal."""
        with self._cond:
            self._limit = max(self._min, self._limit / 2.0)
            self._success_streak = 0
            # Do not notify; shrinking the limit should not admit new work.

    @contextmanager
    def slot(self) -> Iterator[None]:
        with self._cond:
            while self._active >= int(self._limit):
                self._cond.wait(timeout=1.0)
            self._active += 1
        try:
            yield
        finally:
            with self._cond:
                self._active -= 1
                self._cond.notify_all()

    def snapshot(self) -> dict:
        with self._cond:
            return {"limit": int(self._limit), "active": self._active,
                    "success_streak": self._success_streak}
