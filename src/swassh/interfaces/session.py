"""Explicit async session scope, retaining normal command reports and audit."""

from ..application.task_ownership import wait_owned
from contextlib import AsyncExitStack
from contextvars import ContextVar
import asyncio
from dataclasses import replace

from ..application.options import Options
from ..application.profiles import ProfileResolver
from ..infrastructure.bastion import invocation_budget, independent_invocation
from ..infrastructure.resources import resource_plan
from ..infrastructure.session import PersistentSSHTransport
from ..infrastructure.lifecycle import finish_task
from .api import Swarm

_ACTIVE = ContextVar('swassh_active_session', default=False)


class _BorrowedTransport:
    """A run borrows the connection; only its enclosing session may close it."""
    _native_guarded = True
    _persistent_master = True
    def __init__(self, transport):
        self.transport = transport

    async def execute(self, host, command):
        return await self.transport.execute(host, command)

    def metrics(self):
        return self.transport.metrics()


class Session:
    """Reuse one authenticated connection with ``async with Session(host)``.

    ``run(command)`` returns the existing Report format. Commands are serialized;
    each opens a fresh remote channel (working directory/environment do not
    persist). The context must be entered and exited by the same asyncio task.
    Native connection leases remain held until the master and descendants stop.
    """
    def __init__(self, host, options=None, *, lifetime=300):
        self.options = replace(options or Options(), concurrency=1)
        self.host, = ProfileResolver(self.options).targets([host])
        self.lifetime = lifetime
        self.stack = None
        self.transport = None
        self.used = False
        self.lock = asyncio.Lock()
        self.token = None
        self.owner = None
        self.running = None
        self.closing = False

    async def __aenter__(self):
        if self.used:
            raise RuntimeError('a Session context cannot be reopened')
        if _ACTIVE.get():
            raise RuntimeError('nested or inherited Session scopes cannot share a memory reservation')
        self.used = True
        self.owner = asyncio.current_task()
        resource_plan(self.options, guarded=True, persistent_master=True)
        self.stack = AsyncExitStack()
        self.token = _ACTIVE.set(True)
        try:
            self.stack.enter_context(independent_invocation())
            await self.stack.enter_async_context(invocation_budget(self.options))
            self.transport = PersistentSSHTransport(self.options, self.host, self.lifetime)
            self.stack.push_async_callback(self.transport.aclose)
            await self.transport.open()
        except BaseException:
            try:
                await self.stack.aclose()
            finally:
                _ACTIVE.reset(self.token)
                self.token = None
            raise
        return self

    async def run(self, command):
        """Execute once; preserve grouped outputs, canary, limits and audit."""
        if self.closing or self.transport is None or self.transport.closed:
            raise RuntimeError('enter an open Session before running a command')
        async with self.lock:
            # A caller may have queued before __aexit__ began. Never create a
            # reporter/channel after the enclosing reservation is released.
            if self.closing or self.transport.closed:
                raise RuntimeError('SSH session is closing or closed')
            self.running = asyncio.current_task()
            try:
                return await Swarm(self.options, transport=_BorrowedTransport(self.transport)).run([self.host], command)
            except BaseException:
                await self.transport.aclose()
                raise
            finally:
                self.running = None

    async def __aexit__(self, kind, value, traceback):
        if asyncio.current_task() is not self.owner:
            raise RuntimeError('Session must be exited by its entering task')
        self.closing = True
        # Drain child runs before releasing the master's memory/connection
        # reservation, even when cancellation interrupts context exit.
        # The exit stack owns ContextVar tokens, so execute it in this task.
        cancelled = False
        try:
            running = self.running
            if running is not None:
                running.cancel()
                async def drain():
                    await asyncio.gather(running, return_exceptions=True)
                draining = asyncio.create_task(drain())
                try:
                    await wait_owned(draining)
                except asyncio.CancelledError:
                    await finish_task(draining)
                    cancelled = True
            result = await self.stack.__aexit__(kind, value, traceback)
            if cancelled:
                raise asyncio.CancelledError
            return result
        finally:
            _ACTIVE.reset(self.token)
            self.token = None
