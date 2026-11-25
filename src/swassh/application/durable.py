"""Cancellation-safe durable I/O and transactional audit-outbox delivery."""

from .task_ownership import wait_owned
import asyncio
from contextvars import copy_context
from contextlib import asynccontextmanager
import queue
from concurrent.futures import ThreadPoolExecutor
from functools import partial


class _NativeOwner:
    """One serial, bounded command slot on a workflow-owned native worker.

    Each command carries its own copied context. A pending command and the
    worker remain owned through cancellation; the workflow joins both before
    releasing its storage lock. No remote effect executes on this worker.
    """

    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.commands = queue.Queue(maxsize=1)
        self.pending = None
        self.closing = False
        self.failure = None
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='swassh-workflow')
        operation = partial(copy_context().run, self._run)
        try:
            self.worker = self.loop.run_in_executor(self.executor, operation)
        except BaseException:
            self.executor.shutdown(wait=True)
            raise
        self.worker.add_done_callback(self._worker_done)

    @staticmethod
    def _complete(future, value, error):
        # A queued notification may race cancellation of an invalid caller;
        # the physical worker is still joined by the scope in that case.
        if not future.done():
            if error is None:
                future.set_result(value)
            else:
                future.set_exception(error)

    def _run(self):
        while True:
            command = self.commands.get()
            if command is None:
                return
            operation, future = command
            try:
                value = operation()
            except BaseException as error:
                self.loop.call_soon_threadsafe(self._complete, future, None, error)
            else:
                self.loop.call_soon_threadsafe(self._complete, future, value, None)

    def _worker_done(self, worker):
        if self.pending is not None and not self.pending.done():
            error = (RuntimeError('native workflow owner was cancelled')
                if worker.cancelled() else worker.exception())
            self.pending.set_exception(error if error is not None
                else RuntimeError('native workflow owner stopped before command completion'))

    def submit(self, operation):
        if self.closing or self.worker.done():
            self.worker.result() if self.worker.done() else None
            raise RuntimeError('native workflow owner is closed')
        if self.pending is not None:
            raise RuntimeError('concurrent workflow storage command refused')
        future = self.loop.create_future()
        self.commands.put_nowait((operation, future))
        self.pending = future
        return future

    def release(self, future):
        if self.pending is future:
            self.pending = None

    @staticmethod
    async def _join(future):
        cancelled = False
        while not future.done():
            try:
                await asyncio.wait((future,))
            except asyncio.CancelledError:
                cancelled = True
        return cancelled

    async def close(self):
        cancelled = False
        if not self.closing:
            self.closing = True
            if self.pending is not None:
                cancelled = await self._join(self.pending)
                try:
                    self.pending.result()
                except BaseException as error:
                    self.failure = error
            if not self.worker.done():
                self.commands.put_nowait(None)
        cancelled = await self._join(self.worker) or cancelled
        try:
            self.worker.result()
            if self.failure is not None:
                raise self.failure
            if cancelled:
                raise asyncio.CancelledError
        finally:
            # The native operation is already joined; this also retires its
            # one thread before the workflow releases the storage lock.
            self.executor.shutdown(wait=True)


class DurableOutbox:
    """Share the existing scheduler's I/O/audit invariants with workflow workers."""

    def __init__(self, store, *, audit_factory, audit_path, audit_scope):
        self.store = store
        self.audit_factory, self.audit_path = audit_factory, audit_path
        self.audit_scope = audit_scope
        self._native = None

    async def _io(self, function, *args, **kwargs):
        # Own the executor Future itself: an extra coroutine Task adds callback
        # and debug-stack work without changing native-operation ownership.
        operation = partial(copy_context().run, function, *args, **kwargs)
        owner = self._native
        future = (asyncio.get_running_loop().run_in_executor(None, operation)
            if owner is None else owner.submit(operation))
        try:
            return await wait_owned(future)
        except asyncio.CancelledError:
            while not future.done():
                try:
                    await wait_owned(future)
                except asyncio.CancelledError:
                    continue
            future.result()
            raise
        finally:
            if owner is not None:
                owner.release(future)

    @asynccontextmanager
    async def _native_scope(self):
        """Keep the workflow's native worker alive until all owned I/O is joined."""
        if self._native is not None:
            raise RuntimeError('nested native workflow owner refused')
        owner = _NativeOwner()
        self._native = owner
        try:
            yield
        finally:
            try:
                await owner.close()
            finally:
                self._native = None

    def _operate_and_read(self, function, /, *args, **kwargs):
        """Keep native commits separate while avoiding a second thread handoff.

        The read retains the caller's context even if the adapter changes it.
        Cancellation still joins this entire bounded native operation; its read
        cannot emit another audit record or perform a remote effect.
        """
        context = copy_context()
        result = function(*args, **kwargs)
        return result, context.run(self.store.events)

    async def _io_then_flush(self, function, /, *args, **kwargs):
        """Return an operation's result only after its audit outbox is drained."""
        result, records = await self._io(self._operate_and_read, function, *args, **kwargs)
        await self._deliver_events(records)
        return result

    async def _deliver_events(self, records, *, after=None):
        """Close each durable sink before committing its outbox cursor."""
        while records:
            async with self.audit_factory(self.audit_path, self.audit_scope) as audit:
                for event_id, record in records:
                    await audit.emit(record['event'], {'event_id': event_id, **record['fields']})
            if after is None:
                _, records = await self._io(self._operate_and_read,
                    self.store.acknowledge_events, records[-1][0])
            else:
                records, value = await self._io(self._ack_and_read_after, records[-1][0], after)
                if not records:
                    return value
        if after is not None:
            return await self._io(after)

    def _ack_and_read_after(self, through, after):
        """Keep the subsequent read after final acknowledgement, in caller context."""
        context = copy_context()
        _, records = self._operate_and_read(self.store.acknowledge_events, through)
        return records, context.run(after) if not records else None

    async def _io_then_flush_read(self, function, reader, /, *args, **kwargs):
        """Drain the operation's outbox before one read-only continuation.

        A nonempty final batch shares its acknowledgement's native handoff with
        the read, retaining every transaction, validation and operation order.
        """
        result, records = await self._io(self._operate_and_read, function, *args, **kwargs)
        if result is None:
            await self._deliver_events(records)
            return None, None
        value = await self._deliver_events(records, after=partial(reader, result))
        return result, value

    async def _flush_events(self):
        """Acknowledge only after the rotating audit sink has durably closed."""
        await self._deliver_events(await self._io(self.store.events))
