"""Bounded connection admission policy shared by transport adapters."""

import asyncio
import math
import time


class ConnectionPacer:
    """No burst: one admission per interval, shared by workers and retries."""

    def __init__(self, rate: float):
        if not isinstance(rate, (int, float)) or isinstance(rate, bool):
            raise ValueError('connection rate must be numeric')
        try:
            rate = float(rate)
        except OverflowError as exc:
            raise ValueError('connection rate is outside the supported numeric range') from exc
        if not math.isfinite(rate) or rate <= 0 or not math.isfinite(1 / rate):
            raise ValueError('connection rate must define a finite positive interval')
        self.interval = 1 / rate
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        await self._lock.acquire()
        try:
            delay = self._next - time.perf_counter()
            # Older Windows event loops use a coarse GetTickCount64 clock.
            # Measure the actual interval with the monotonic high-resolution
            # counter, and recheck even when the loop wakes its timer early.
            while delay > 0:
                await asyncio.sleep(delay)
                delay = self._next - time.perf_counter()
            self._next = time.perf_counter() + self.interval

            # Keep ownership until this caller has continued to its next yield.
            # Preemption between the timestamp and returning to the caller must
            # not consume the next interval and permit a catch-up burst.
            asyncio.get_running_loop().call_soon(self._handoff)
        except BaseException:
            self._lock.release()
            raise

    def _handoff(self) -> None:
        """Start the next interval after the admitted continuation has run."""
        self._next = max(self._next, time.perf_counter() + self.interval)
        self._lock.release()
