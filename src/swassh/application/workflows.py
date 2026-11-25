"""Sequential durable DAG orchestration; each fleet keeps its own bounded swarm."""
from __future__ import annotations

from .task_ownership import wait_owned

import asyncio
from datetime import UTC, datetime
import math

from ..domain.workflows import WorkflowError
from .contracts import RunSummary
from .durable import DurableOutbox
from .schedule_contracts import ExecutionFailure


class WorkflowService(DurableOutbox):
    """Never replay a claimed checkpoint after process loss or cancellation."""

    def __init__(self, store, executor, *, audit_factory, audit_path, clock=None):
        super().__init__(store, audit_factory=audit_factory, audit_path=audit_path, audit_scope='workflow')
        self.executor = executor
        self.clock = clock if clock is not None else lambda: datetime.now(UTC)

    @staticmethod
    async def _drain(task):
        """Wait for cancellation cleanup even when the caller cancels repeatedly."""
        task.cancel()
        # The gathering Future already owns the join; an extra Task would add
        # callbacks and debug-stack collection without extending its lifetime.
        cleanup = asyncio.gather(task, return_exceptions=True)
        while not cleanup.done():
            try:
                await wait_owned(cleanup)
            except asyncio.CancelledError:
                continue
        cleanup.result()

    async def _dispatch(self, id, step, invocation, stop):
        if stop.is_set():
            return False
        execution = asyncio.create_task(self.executor(id, step, invocation), name='swassh-workflow-execution')
        stopping = asyncio.create_task(stop.wait())
        persisting = False
        try:
            done, _ = await asyncio.wait((execution, stopping), return_when=asyncio.FIRST_COMPLETED)
            if execution not in done:
                await self._drain(execution)
                return False
            summary = await execution
            if not isinstance(summary, RunSummary):
                raise WorkflowError('invalid workflow executor result')
            persisting = True
            _, records = await self._io(self._operate_and_read, self.store.finish_step,
                                        id, step.id, summary.ok, self.clock(), summary=summary)
        except asyncio.CancelledError:
            await self._drain(execution)
            raise
        except Exception as error:
            if persisting:
                raise
            _, records = await self._io(self._operate_and_read, self.store.finish_step,
                                        id, step.id, False, self.clock(),
                                        failure=ExecutionFailure.capture(error))
        finally:
            await self._drain(stopping)
        # Snapshot reads share the completion handoff, but delivery retains the
        # original boundary after the stop watcher has been joined. Audit close
        # still precedes its separate durable acknowledgement transaction.
        await self._deliver_events(records)
        return True

    async def serve(self, *, once=False, stop_event=None, poll_interval=1.0):
        if type(once) is not bool:
            raise WorkflowError('once must be boolean')
        if (type(poll_interval) not in (int, float) or not math.isfinite(poll_interval)
                or not 0.1 <= poll_interval <= 60):
            raise WorkflowError('workflow polling interval must be 0.1..60 seconds')
        stop = stop_event if stop_event is not None else asyncio.Event()
        if not isinstance(stop, asyncio.Event):
            raise WorkflowError('stop_event must be an asyncio Event')
        processed = 0
        with self.store.worker_lock():
            async with self._native_scope():
                try:
                    await self._io_then_flush(self.store.recover, self.clock())
                    while not stop.is_set():
                        id, prepared = await self._io_then_flush_read(
                            self.store.claim_run, self.store.definition, self.clock())
                        if id is None:
                            if once:
                                break
                            try:
                                async with asyncio.timeout(poll_interval):
                                    await stop.wait()
                            except TimeoutError:
                                pass
                            continue
                        steps = {step.id: step for step in prepared.workflow.ordered_steps}
                        while not stop.is_set():
                            step_id = await self._io_then_flush(self.store.claim_step, id, self.clock())
                            if step_id is None:
                                break
                            if step_id not in steps:
                                raise WorkflowError('persisted workflow step does not match its definition')
                            if not await self._dispatch(id, steps[step_id], prepared.invocation(step_id), stop):
                                break
                        processed += 1
                        if once:
                            break
                finally:
                    await self._io_then_flush(self.store.recover, self.clock())
        return processed
