"""Persistent one-shot scheduler: one fleet at a time, no replay after claiming."""
from __future__ import annotations

from .task_ownership import wait_owned

import asyncio
import math
from datetime import UTC, datetime

from ..domain.scheduling import JobState, ScheduleError, utc_time
from .contracts import RunSummary
from .ports import AuditFactory
from .schedule_contracts import ScheduleStore, ScheduledExecutor, ExecutionFailure
from .durable import DurableOutbox


class SchedulingService(DurableOutbox):
    def __init__(self, store: ScheduleStore, executor: ScheduledExecutor, *,
                 audit_factory: AuditFactory, audit_path: str, clock=None):
        super().__init__(store, audit_factory=audit_factory, audit_path=audit_path, audit_scope='scheduler')
        self.executor = executor
        self.clock = clock or (lambda: datetime.now(UTC))

    def _finish_if_running(self, *args, **kwargs):
        # A cancelled shielded commit may already have made the job terminal.
        info = self.store.get(args[0])
        if info.state == JobState.RUNNING:
            return self.store.finish(*args, **kwargs)
        return info

    async def _dispatch(self, job, stop):
        execution = asyncio.create_task(self.executor(job), name='swassh-scheduled-execution')
        stopping = asyncio.create_task(stop.wait())
        persisting = False
        try:
            done, _ = await asyncio.wait([execution, stopping], return_when=asyncio.FIRST_COMPLETED)
            if execution not in done:
                execution.cancel()
                await asyncio.gather(execution, return_exceptions=True)
                await self._io(self._finish_if_running, job.info.id, JobState.INTERRUPTED,
                               utc_time(self.clock()), reason='worker_stopped')
                return
            summary = await execution
            if not isinstance(summary, RunSummary) or summary.total != job.info.host_count:
                raise ScheduleError('invalid execution summary')
            persisting = True
            await self._io(self._finish_if_running, job.info.id,
                           JobState.SUCCEEDED if summary.ok else JobState.FAILED,
                           utc_time(self.clock()), summary=summary,
                           reason=None if summary.ok else 'host_or_canary_failed')
        except asyncio.CancelledError:
            execution.cancel()
            while not execution.done():
                try:
                    await wait_owned(execution)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            await self._io(self._finish_if_running, job.info.id, JobState.INTERRUPTED,
                           utc_time(self.clock()), reason='worker_cancelled')
            raise
        except Exception as error:
            # A failed durable completion is not evidence that execution failed.
            # Propagate it; recovery interrupts the claim without replaying it.
            if persisting:
                raise
            finish_failure = getattr(self.store, 'finish_failure', None)
            if finish_failure is not None:
                await self._io(finish_failure, job.info.id, utc_time(self.clock()),
                               ExecutionFailure.capture(error))
            else:
                # Preserve stores injected through the original public port.
                await self._io(self._finish_if_running, job.info.id, JobState.FAILED,
                               utc_time(self.clock()), reason='execution_or_report_error')
        finally:
            stopping.cancel()
            await asyncio.gather(stopping, return_exceptions=True)

    async def serve(self, *, once=False, stop_event: asyncio.Event | None = None, poll_interval=1.0):
        if (isinstance(poll_interval, bool) or not isinstance(poll_interval, (float, int))
                or not math.isfinite(poll_interval) or not 0.1 <= poll_interval <= 60):
            raise ScheduleError('poll interval must be between 0.1 and 60 seconds')
        stop = stop_event if stop_event is not None else asyncio.Event()
        processed = 0
        # One lock for the full lifetime, including crash recovery and audit export.
        with self.store.worker_lock():
            # Storage owns its worker until cancellation and final audit export
            # have joined; unrelated default-executor work cannot starve it.
            async with self._native_scope():
                try:
                    await self._io_then_flush(self.store.recover_running, utc_time(self.clock()))
                    while not stop.is_set():
                        job = await self._io_then_flush(self.store.claim_due, utc_time(self.clock()))
                        if job is not None:
                            if stop.is_set():
                                await self._io(self._finish_if_running, job.info.id, JobState.INTERRUPTED,
                                               utc_time(self.clock()), reason='worker_stopped')
                                break
                            await self._dispatch(job, stop)
                            processed += 1
                            await self._flush_events()
                            if once:
                                break
                            continue
                        if once:
                            break
                        try:
                            async with asyncio.timeout(poll_interval):
                                await stop.wait()
                        except TimeoutError:
                            pass
                finally:
                    # Covers cancellation immediately after a durable claim, before dispatch.
                    await self._io_then_flush(self.store.recover_running, utc_time(self.clock()))
        return processed
