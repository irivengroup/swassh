"""One bounded report process with serialized RPCs, deadlines and forced cleanup."""
from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import math
import multiprocessing
import tempfile
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Self

from ..application.contracts import RunSummary
from ..domain.models import Result
from .lifecycle import finish_task
from .filesystem import trusted_parents
from .bastion import specification, current_reservation
from .spool import initialize_store, store_operation


class ProcessReportWriter:
    """Own a serialized spool and accept batches funded by admitted memory."""

    # Other injected ports retain their historical worker-sized backpressure.
    supports_spare_memory_batches = True

    def __init__(self, directory: str | Path, max_bytes: int, *, operation_timeout: float = 60.0, options=None):
        try:
            if (not isinstance(operation_timeout, (float, int)) or isinstance(operation_timeout, bool)
                    or not math.isfinite(operation_timeout) or operation_timeout <= 0):
                raise ValueError("report operation timeout must be finite and positive")
        except OverflowError as exc:
            raise ValueError("report operation timeout must be finite and positive") from exc
        self.directory, self.max_bytes, self.operation_timeout = directory, max_bytes, operation_timeout
        self._budget = specification(options) if options else None
        self.worker_pid = None
        self._executor = None
        self._stopping = False
        self._shutdown_owner = None
        self._directory = None
        self._store_path = None
        self._cancelled = None
        self._parent_sender = self._parent_receiver = None
        self._rpc_lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        if self._executor is not None or self._shutdown_owner is not None:
            raise RuntimeError('report writer is already open or shutdown remains unresolved')
        trusted_parents(Path(self.directory) / "swassh-report-boundary")
        context = multiprocessing.get_context("spawn")
        self._cancelled = context.Event()
        self._parent_receiver, self._parent_sender = context.Pipe(duplex=False)
        self._directory = tempfile.TemporaryDirectory(prefix="swassh-report-", dir=self.directory)
        try:
            self._executor = ProcessPoolExecutor(max_workers=1, mp_context=context,
                initializer=initialize_store,
                initargs=(self._directory.name, self.max_bytes, self._cancelled, self._parent_receiver, self._budget, current_reservation()))
            self._stopping = False
            self._store_path, self.worker_pid = await self._call("identity")
            self._parent_receiver.close()
            self._parent_receiver = None
            return self
        except BaseException:
            await self._close()
            raise

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self._close()

    async def _shutdown(self, *, force: bool) -> None:
        executor = self._executor
        if executor is None:
            return
        # Keep ownership until termination is confirmed. A failed close may be
        # retried; dropping this reference would let that retry delete a live
        # worker's spool. Refuse new RPCs while its shutdown is unresolved.
        self._stopping = True
        # CPython 3.11-3.13 has no public terminate_workers API. Retain the process
        # handles before shutdown clears the mapping; exercised by the supplied CI matrix.
        if self._shutdown_owner is None:
            self._shutdown_owner = (list((getattr(executor, "_processes", None) or {}).values()),
                                    getattr(executor, "_executor_manager_thread", None))
        # shutdown(wait=False) clears these fields on the executor immediately.
        # Retain our original handles across failed/repeated close attempts.
        processes, manager = self._shutdown_owner
        def shutdown():
            if force:
                for process in processes:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
            executor.shutdown(wait=False, cancel_futures=True)
            # The executor manager exclusively reaps children. Concurrent Process.join
            # calls race with its waitpid and can corrupt the observed exit status.
            if manager is not None:
                manager.join(timeout=2)
                if manager.is_alive():
                    for process in processes:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    manager.join(timeout=2)
                if manager.is_alive():
                    raise RuntimeError("report process cannot stop; retain its private spool for recovery")
        task = asyncio.create_task(asyncio.to_thread(shutdown))
        try:
            await wait_owned(task)
        except asyncio.CancelledError:
            await finish_task(task)
            self._executor = None
            self._shutdown_owner = None
            raise
        self._executor = None
        self._shutdown_owner = None

    async def _call(self, operation: str, *arguments: object) -> object:
        async with self._rpc_lock:
            if self._executor is None or self._stopping:
                raise RuntimeError("report writer is not open")
            future = asyncio.get_running_loop().run_in_executor(self._executor, store_operation, operation, *arguments)
            try:
                async with asyncio.timeout(self.operation_timeout):
                    # wait() protects the worker future from caller cancellation
                    # without installing shield's late-error logging callback
                    # on affected Python 3.14 runtimes. Its result is always
                    # retrieved here or by the forced-shutdown callback below.
                    await asyncio.wait((future,))
                    return future.result()
            except (asyncio.CancelledError, TimeoutError):
                self._cancelled.set()
                try:
                    async with asyncio.timeout(2):
                        await asyncio.wait((future,))
                        future.result()
                except (Exception, asyncio.CancelledError):
                    future.add_done_callback(lambda item: item.exception() if not item.cancelled() else None)
                    await self._shutdown(force=True)
                raise

    async def prepare(self, path: Path) -> None:
        trusted_parents(path)
        if not path.parent.is_dir() or path.is_dir():
            raise ValueError('report destination must name a file in an existing directory')

    async def append(self, results: Sequence[Result]) -> None:
        await self._call("append", list(results))

    async def summary(self) -> dict[str, int]:
        return await self._call("summary")

    async def export(self, path: Path, format: str, command: str, summary: RunSummary) -> None:
        await self._call("export", path, format, command, summary)

    async def _close(self) -> None:
        closing = asyncio.create_task(self._close_impl())
        try:
            await wait_owned(closing)
        except asyncio.CancelledError:
            await finish_task(closing)
            raise

    async def _close_impl(self) -> None:
        try:
            if self._executor is not None and not self._stopping and self._store_path is not None:
                await self._call("close")
        finally:
            # Never delete the staging of a process that failed to terminate.
            await self._shutdown(force=False)
            for connection in (self._parent_sender, self._parent_receiver):
                if connection is not None:
                    connection.close()
            self._parent_sender = self._parent_receiver = None
            if self._store_path is not None:
                for suffix in ("", "-journal", "-wal", "-shm"):
                    Path(self._store_path + suffix).unlink(missing_ok=True)
                self._store_path = None
            if self._directory is not None:
                self._directory.cleanup()
                self._directory = None
