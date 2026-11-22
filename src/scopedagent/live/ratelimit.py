"""A serial rate limit (D-E45): at most N requests per second across the whole run, one at a time."""

from __future__ import annotations

import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        per_second: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 1 <= per_second <= 10:
            raise ValueError("the rate is 1 to 10 requests per second")
        self._interval = 1.0 / per_second
        self._clock, self._sleep = clock, sleep
        self._next = 0.0

    def wait(self) -> float:
        """Block until the next request may start. Returns how long it waited."""
        now = self._clock()
        delay = max(0.0, self._next - now)
        if delay:
            self._sleep(delay)
        self._next = max(now, self._next) + self._interval
        return delay
