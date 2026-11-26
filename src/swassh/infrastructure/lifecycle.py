"""Finish bounded cleanup even if the caller receives repeated cancellation."""

from ..application.task_ownership import wait_owned
import asyncio
import os
import sys
import tempfile


def ensure_subprocess_loop():
    if sys.platform == 'win32':
        loop = asyncio.get_running_loop()
        proactor = getattr(asyncio, 'ProactorEventLoop', None)
        if proactor is None or not isinstance(loop, proactor):
            raise ValueError('Windows SSH/SFTP requires the default ProactorEventLoop')


async def finish_task(task):
    while not task.done():
        try:
            await wait_owned(task)
        except asyncio.CancelledError:
            continue
    return task.result()


class NativeStagingDirectory:
    """Own staging until asynchronous Windows job-handle teardown completes.

    A reaped guardian has requested descendant termination, but Win32 can
    briefly retain a descendant's diagnostic file handle. Retry only sharing
    violations 32/33 for at most two seconds; other errors remain failures.
    Caller cancellation never abandons a cleanup thread or starts a competing
    removal. This deadline bounds retries, not an uninterruptible OS I/O call.
    """
    def __init__(self, **settings):
        self.directory=tempfile.TemporaryDirectory(**settings)

    async def __aenter__(self):
        return self.directory.name

    async def _cleanup(self):
        loop=asyncio.get_running_loop()
        deadline=loop.time()+2
        while True:
            try:
                await asyncio.to_thread(self.directory.cleanup)
                return
            except PermissionError as error:
                remaining=deadline-loop.time()
                if os.name!='nt' or getattr(error,'winerror',None) not in (32,33) or remaining<=0:
                    raise
                await asyncio.sleep(min(0.01,remaining))

    async def __aexit__(self, kind, value, traceback):
        cleanup=asyncio.create_task(self._cleanup())
        try:
            await wait_owned(cleanup)
        except asyncio.CancelledError:
            await finish_task(cleanup)
            raise
