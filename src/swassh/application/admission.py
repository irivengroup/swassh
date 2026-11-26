"""Constant-space adaptive admission and aggregate metrics, independent of OS I/O."""
from __future__ import annotations
import asyncio
import time
from ..domain.models import Status


class Admission:
    def __init__(self, workers, rate, *, adaptive=False, threshold=5):
        self.maximum = self.limit = workers
        self.rate, self.adaptive, self.threshold = rate, adaptive, threshold
        self.condition = asyncio.Condition()
        self.active = self.peak = self.completed = self.skipped = self.failures = 0
        self.consecutive = self.successes = self.reductions = 0
        self.circuit_open = False
        self.started = time.monotonic()
        self.wait_seconds = self.client_seconds = 0.0
        self.next_start = 0.0

    async def acquire(self):
        started = time.monotonic()
        async with self.condition:
            while not self.circuit_open and self.active >= self.limit:
                await self.condition.wait()
            if self.circuit_open:
                self.skipped += 1
                return False
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.adaptive:
                now = time.monotonic()
                slot = max(now, self.next_start)
                self.next_start = slot + self.maximum / (self.rate * self.limit)
                # Timers may wake early on coarse platform clocks. Keep the
                # reservation until its deadline rather than exceeding the cap.
                while now < slot:
                    await asyncio.sleep(slot - now)
                    now = time.monotonic()
                if self.circuit_open:
                    async with self.condition:
                        self.active -= 1
                        self.skipped += 1
                        self.condition.notify_all()
                    return False
            self.wait_seconds += time.monotonic() - started
            return True
        except BaseException:
            async with self.condition:
                self.active -= 1
                self.condition.notify_all()
            raise

    async def complete(self, result):
        async with self.condition:
            self.active -= 1
            self.completed += 1
            self.client_seconds += result.duration
            if result.status in {Status.TIMEOUT, Status.UNREACHABLE}:
                self.failures += 1
                self.consecutive += 1
                self.successes = 0
                if self.adaptive:
                    lower = max(1, self.limit // 2)
                    self.reductions += lower < self.limit
                    self.limit = lower
                    if self.consecutive >= self.threshold:
                        self.circuit_open = True
            else:
                self.consecutive = 0
                if result.status == Status.SUCCESS and self.adaptive:
                    self.successes += 1
                    if self.successes >= max(2, self.limit * 2):
                        self.limit = min(self.maximum, self.limit + 1)
                        self.successes = 0
            self.condition.notify_all()

    def snapshot(self, total, counts):
        elapsed = max(0.001, time.monotonic() - self.started)
        finished = sum(counts.values())
        return {'total': total, 'active': self.active, 'completed': finished,
            'skipped': counts[Status.SKIPPED.value], 'peak_active': self.peak,
            'admission_limit': self.limit, 'ceiling': self.maximum,
            'circuit_open': self.circuit_open, 'reductions': self.reductions,
            'network_failures': self.failures, 'admission_wait_seconds': round(self.wait_seconds, 6),
            'client_seconds': round(self.client_seconds, 6), 'elapsed_seconds': round(elapsed, 6),
            'completed_per_second': round(finished / elapsed, 3)}
