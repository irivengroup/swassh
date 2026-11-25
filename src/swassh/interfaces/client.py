"""Small explicit sync/async clients sharing the existing guarded swarm engine."""
from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import threading
from collections.abc import AsyncIterator, Callable, Iterable, Iterator
from contextlib import aclosing
from dataclasses import replace
from pathlib import Path
from typing import Self

from ..application.options import Options
from ..application.ports import Transport
from ..domain.inventory import normalize_hosts
from ..domain.models import Host, Result
from ..infrastructure.bastion import independent_invocation
from ..infrastructure.inventory import load_inventory
from ..infrastructure.lifecycle import finish_task
from .api import Swarm

Targets = Host | str | Iterable[Host | str]


def _sync_only() -> None:
    """Reject blocking an application loop before allocating any coroutine."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError('use AsyncClient inside an event loop')


class ResultStream(AsyncIterator[Result]):
    """A single-consumer, single-use managed stream with one buffered result.

    Enter with ``async with`` before iterating. A dedicated producer owns all
    invocation contexts; consumer tasks never inherit their reservations.
    Exit cancels pending work and waits for cleanup, including repeated caller
    cancellation. A slow consumer applies backpressure to the bounded engine.
    """
    def __init__(self, service: Swarm, hosts: tuple[Host, ...], command: str, check: bool):
        self._service, self._hosts, self._command, self._check = service, hosts, command, check
        self._queue: asyncio.Queue[Result] = asyncio.Queue(maxsize=1)
        self._producer: asyncio.Task | None = None
        self._used = self._closed = self._reading = False
        self._failure_observed = False
        self._loop = None

    async def __aenter__(self) -> Self:
        if self._used:
            raise RuntimeError('a result stream cannot be reopened')
        self._used = True
        self._loop = asyncio.get_running_loop()
        self._producer = asyncio.create_task(self._produce(), name='swassh-client-stream')
        return self

    async def _produce(self) -> None:
        with independent_invocation():
            async with aclosing(self._service.iter_results(self._hosts, self._command)) as results:
                async for result in results:
                    await self._queue.put(result)

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> Result:
        if self._producer is None or self._loop is not asyncio.get_running_loop():
            raise RuntimeError('enter the result stream in this event loop first')
        if self._closed:
            raise StopAsyncIteration
        if self._reading:
            raise RuntimeError('a result stream supports one reader at a time')
        self._reading = True
        getter = None
        try:
            if not self._queue.empty():
                result = self._queue.get_nowait()
            else:
                getter = asyncio.create_task(self._queue.get())
                done, _ = await asyncio.wait((getter, self._producer), return_when=asyncio.FIRST_COMPLETED)
                if getter in done:
                    result = getter.result()
                elif not self._queue.empty():
                    result = self._queue.get_nowait()
                else:
                    # Retrieve producer failures; never turn a partial run into
                    # a successful end-of-stream or an unobserved task error.
                    self._failure_observed = True
                    self._producer.result()
                    raise StopAsyncIteration
            if self._check:
                result.raise_for_status()
            return result
        finally:
            if getter is not None:
                getter.cancel()
                await asyncio.gather(getter, return_exceptions=True)
            self._reading = False

    async def __aexit__(self, kind, value, traceback) -> None:
        if self._loop is not asyncio.get_running_loop():
            raise RuntimeError('close the result stream in its owning event loop')
        if self._closed:
            return
        self._closed = True
        if self._producer is None:
            return
        finished = self._producer.done()
        if not finished:
            self._producer.cancel()
        async def drain():
            return (await asyncio.gather(self._producer, return_exceptions=True))[0]
        cleanup = asyncio.create_task(drain())
        try:
            outcome = await wait_owned(cleanup)
        except asyncio.CancelledError:
            outcome = await finish_task(cleanup)
            if isinstance(outcome, Exception) and not self._failure_observed:
                raise outcome
            raise
        finally:
            while not self._queue.empty():
                self._queue.get_nowait()
        # A normal early break cancels the producer, but an adapter failure
        # during its cleanup is not successful cancellation and must surface.
        if not self._failure_observed and (isinstance(outcome, Exception) or
                                          (kind is None and finished and isinstance(outcome, BaseException))):
            raise outcome


class _Settings:
    """Immutable options and normalized inventory shared by both client styles."""
    def __init__(self, hosts: Targets, *, options: Options | None = None,
                 transport_factory: Callable[[Options], Transport] | None = None, **settings):
        if options is not None and not isinstance(options, Options):
            raise TypeError('options must be an Options instance')
        if transport_factory is not None and not callable(transport_factory):
            raise TypeError('transport_factory must be callable')
        self._hosts = normalize_hosts((hosts,) if isinstance(hosts, (Host, str)) else hosts)
        self._options = replace(options or Options(), **settings)
        self._factory = transport_factory

    @property
    def hosts(self) -> tuple[Host, ...]:
        return self._hosts

    @property
    def options(self) -> Options:
        return self._options

    @classmethod
    def from_inventory(cls, path: str | Path, **settings) -> Self:
        """Read an existing bounded inventory format once, without connecting."""
        return cls(load_inventory(path), **settings)

    def with_options(self, **settings) -> Self:
        """Return an independent client; never mutate an in-flight operation."""
        return type(self)(self.hosts, options=replace(self.options, **settings), transport_factory=self._factory)

    def on(self, hosts: Targets) -> Self:
        """Return an independent client for an explicitly supplied target set."""
        return type(self)(hosts, options=self.options, transport_factory=self._factory)

    def _service(self, check: bool, settings) -> Swarm:
        if type(check) is not bool:
            raise TypeError('check must be boolean')
        options = replace(self.options, **settings)
        return Swarm(options, transport_factory=self._factory)


class AsyncClient(_Settings):
    """Awaitable application API; construction opens no network resources.

    Every operation keeps existing canary, resource, audit and output contracts.
    ``check=False`` returns all host statuses; ``check=True`` raises a typed
    exception after collecting the complete report. Settings are Options fields.
    """
    async def run(self, command: str, *, check: bool = False, **settings):
        with independent_invocation():
            report = await self._service(check, settings).run(self.hosts, command)
        return report.raise_for_status() if check else report

    async def converge(self, action, *, check: bool = False, **settings):
        """Run a DesiredState across this inventory with native durable intents."""
        from .convergence import ConvergentSwarm
        if type(check) is not bool:
            raise TypeError('check must be boolean')
        options = replace(self.options, **settings)
        service = ConvergentSwarm(action, options, transport_factory=self._factory)
        with independent_invocation():
            report = await service.run(self.hosts)
        return report.raise_for_status() if check else report

    def _interaction_service(self, handler_factory, check, settings):
        from ..bootstrap import InteractionFactory
        if self._factory is not None:
            raise ValueError('interaction requires the native transport')
        if type(check) is not bool:
            raise TypeError('check must be boolean')
        options = replace(self.options, **settings)
        if options.stdin_file or options.retries:
            raise ValueError('interaction requires no stdin_file and retries=0')
        return Swarm(options, transport_factory=InteractionFactory(handler_factory))

    async def interact(self, command: str, handler_factory, *, check: bool = False, **settings):
        """React to live per-host byte events with bounded asynchronous stdin.

        The factory receives Host and returns an async (event, input) callback.
        Callbacks for one host are serialized; different hosts run concurrently.
        Failures stop that host, retain its report and never replay its command.
        """
        service = self._interaction_service(handler_factory, check, settings)
        with independent_invocation():
            report = await service.run(self.hosts, command)
        return report.raise_for_status() if check else report

    def interact_stream(self, command: str, handler_factory, *, check: bool = False,
                        **settings) -> ResultStream:
        """Live callbacks plus bounded completed results, inside async with."""
        return ResultStream(self._interaction_service(handler_factory, check, settings),
                            self.hosts, command, check)

    async def run_to_file(self, command: str, path: str | Path, format: str = 'json',
                          *, spool_dir: str | Path | None = None, **settings):
        """Export through the bounded reporter without collecting fleet outputs."""
        with independent_invocation():
            return await self._service(False, settings).run_to_file(
                self.hosts, command, path, format, spool_dir=spool_dir)

    def stream(self, command: str, *, check: bool = False, **settings) -> ResultStream:
        """Yield completed hosts, not live byte chunks; requires async with.

        With check=True the first failed result raises CommandError. Exiting
        the context cancels pending work; already executed commands are not undone.
        """
        return ResultStream(self._service(check, settings), self.hosts, command, check)

    def session(self, *, lifetime: float = 300):
        """Create the existing explicit persistent Session for a single host."""
        from .session import Session
        if len(self.hosts) != 1 or self._factory is not None:
            raise ValueError('session requires one host and the native transport')
        return Session(self.hosts[0], self.options, lifetime=lifetime)

    def channel(self, command: str, **settings):
        """Create a bounded binary SSHChannel scope for exactly one host."""
        from .channels import SSHChannel
        if len(self.hosts) != 1 or self._factory is not None:
            raise ValueError('channel requires one host and the native transport')
        return SSHChannel(self.hosts[0],command,replace(self.options,**settings))

    def tunnel(self, forward, *, lifetime=300, **settings):
        """Create a loopback-only SSHTunnel scope for exactly one host."""
        from .channels import SSHTunnel
        if len(self.hosts) != 1 or self._factory is not None:
            raise ValueError('tunnel requires one host and the native transport')
        return SSHTunnel(self.hosts[0],forward,replace(self.options,**settings),lifetime=lifetime)


class _SyncStream(Iterator[Result]):
    """Own a private loop only for the duration of a synchronous stream scope."""
    def __init__(self, stream: ResultStream):
        self._stream, self._runner = stream, None
        self._used = self._closed = False
        self._owner = None

    def __enter__(self) -> Self:
        _sync_only()
        if self._used:
            raise RuntimeError('a result stream cannot be reopened')
        self._used = True
        self._owner = threading.get_ident()
        self._runner = asyncio.Runner()
        try:
            self._runner.run(self._stream.__aenter__())
        except BaseException:
            self._runner.close()
            raise
        return self

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Result:
        _sync_only()
        if self._owner is not None and self._owner != threading.get_ident():
            raise RuntimeError('use the synchronous stream in its entering thread')
        if self._runner is None:
            raise RuntimeError('enter the result stream first')
        if self._closed:
            raise StopIteration
        try:
            return self._runner.run(self._stream.__anext__())
        except StopAsyncIteration:
            raise StopIteration from None

    def __exit__(self, kind, value, traceback) -> None:
        _sync_only()
        if self._owner != threading.get_ident():
            raise RuntimeError('close the synchronous stream in its entering thread')
        if self._closed:
            return
        self._closed = True
        try:
            self._runner.run(self._stream.__aexit__(kind, value, traceback))
        finally:
            self._runner.close()


class Client(_Settings):
    """Blocking API for scripts; use AsyncClient in notebooks and async apps."""
    def _async(self) -> AsyncClient:
        _sync_only()
        return AsyncClient(self.hosts, options=self.options, transport_factory=self._factory)

    def run(self, command: str, *, check: bool = False, **settings):
        return asyncio.run(self._async().run(command, check=check, **settings))

    def converge(self, action, *, check: bool = False, **settings):
        """Synchronous desired-state operation; use AsyncClient in a loop."""
        return asyncio.run(self._async().converge(action, check=check, **settings))

    def run_to_file(self, command: str, path: str | Path, format: str = 'json',
                    *, spool_dir: str | Path | None = None, **settings):
        return asyncio.run(self._async().run_to_file(command, path, format, spool_dir=spool_dir, **settings))

    def stream(self, command: str, *, check: bool = False, **settings) -> _SyncStream:
        return _SyncStream(self._async().stream(command, check=check, **settings))
