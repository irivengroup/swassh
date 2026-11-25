"""Scoped native SSH processes: private configuration, guardian and finite I/O."""
from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import math
import os
from pathlib import Path
import time

from ..domain.channels import ChannelCapture
from .authentication import Authentication
from .lifecycle import ensure_subprocess_loop, finish_task, NativeStagingDirectory
from .filesystem import PinnedDirectory
from .native_ready import NativeReady
from .process_guard import launch_native, native_relay
from .ssh import SSHTransport, _config, _cleanup_process, _command_diagnostic, _diagnostic_bytes, _DiagnosticRead, _outcome, DIAGNOSTIC_LIMIT


class NativeSSHScope:
    """One authenticated native connection whose descendants cannot outlive it."""

    def __init__(self, host, options, lifetime, *, command=None, forward=None):
        if (type(lifetime) not in (int,float) or not math.isfinite(lifetime) or lifetime <= 0
                or forward is not None and not 1 <= lifetime <= 3600):
            raise ValueError('SSH lifetime must be finite and positive; tunnels require 1..3600 seconds')
        if (command is None) == (forward is None):
            raise ValueError('choose one command channel or local forward')
        self.host, self.options, self.lifetime = host, options, lifetime
        self.command, self.forward = command, forward
        self.transport = SSHTransport(options)
        self.settings = self.transport.profiles.for_host(host)
        if command is not None:
            self.lifetime = self.settings.command_timeout
        self.process = self.directory = self.watcher = None
        self.failure = None
        self._closing = None
        self.started = None
        self.active_at = None
        self.readiness = None
        self.startup_timeout = self.settings.connect_timeout + self.options.report_timeout

    def _diagnostic(self):
        # Windows OpenSSH deliberately denies live log readers. Metadata still
        # enforces the same cap; the private native callback proves readiness.
        if self.readiness is not None and self.process is not None and self.process.returncode is None:
            if self.diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                raise ValueError('SSH diagnostic budget exceeded')
            return ''
        data = _diagnostic_bytes(self.diagnostic)
        if len(data) > DIAGNOSTIC_LIMIT:
            raise ValueError('SSH diagnostic budget exceeded')
        return data.decode('utf-8', 'replace')

    async def open(self):
        if self.directory is not None or self._closing is not None:
            raise RuntimeError('native SSH scopes cannot be reopened')
        ensure_subprocess_loop()
        self.staging = NativeStagingDirectory(prefix='swassh-scope-')
        self.directory = self.staging.directory
        try:
            root = Path(self.directory.name)
            with PinnedDirectory(root, private=True):
                pass
            config, self.diagnostic = root / 'config', root / 'diagnostic'
            config.write_text(_config(self.host, self.options, self.settings,
                wire_lifetime=self.lifetime+(self.startup_timeout if self.forward is not None else 0)), encoding='utf-8')
            config.chmod(0o600)
            self.diagnostic.touch(mode=0o600)
            arguments = (['-N','-T','-o','ClearAllForwardings=no','-o','ExitOnForwardFailure=yes',
                          '-o','GatewayPorts=no','-L',self.forward.argument]
                         if self.forward is not None else ['-T'])
            if os.name == 'nt':
                self.readiness = NativeReady(root)
                arguments += ['-o', 'PermitLocalCommand=yes', '-o', 'LocalCommand=' + self.readiness.command()]
            await self.transport._pacer.acquire()
            self.started = time.monotonic()
            native_lifetime = self.lifetime + (self.startup_timeout if self.forward is not None else 0)
            relay = ({'host': self.host.hostname, 'port': self.host.port,
                      'connect_timeout': self.settings.connect_timeout,
                      'connector': getattr(self.transport, 'relay_connector', None)}
                     if os.name == 'posix' and self.options.jump_host is None
                        and self.settings.auth_method != 'gssapi' else None)
            # Use the same guardian-owned direct path as command and device
            # transports. Trust, addressing, accounting and the full lifetime
            # stay in that owner; no second budget-proxy Python bootstrap is
            # needed. Jump/GSSAPI/Windows keep their existing configured path.
            with native_relay(relay, native_lifetime):
                self.process = await launch_native(self.transport.executable, '-F', str(config), '-E', str(self.diagnostic),
                    *arguments, 'swassh-target', *([self.command] if self.command is not None else []),
                    options=self.options, max_native_seconds=native_lifetime,
                    stdin=asyncio.subprocess.PIPE if self.command is not None else asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE if self.command is not None else asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE if self.command is not None else asyncio.subprocess.DEVNULL,
                    env=Authentication.environment(self.options,self.settings), limit=65536,
                    start_new_session=os.name=='posix')
            self.watcher = asyncio.create_task(self._watch(), name='swassh-scope-deadline')
            startup = self.startup_timeout if self.forward is not None else min(self.lifetime,self.startup_timeout)
            async with asyncio.timeout(startup):
                while True:
                    text = (await _DiagnosticRead(self._diagnostic).read()).lower()
                    # A sharing violation is still unconfirmed readiness. The
                    # unchanged outer startup deadline also bounds this read.
                    authenticated = (await _DiagnosticRead(self.readiness.observed).read() if self.readiness is not None else
                        'authenticated to ' in text or 'authentication succeeded' in text)
                    listening = (self.readiness is not None or self.forward is None or
                        f'local forwarding listening on {self.forward.bind_address} port {self.forward.local_port}' in text)
                    if authenticated and listening and self.failure is None:
                        if self.forward is not None and self.process.returncode is not None:
                            raise OSError('SSH forwarding exited before it became available')
                        self.active_at = time.monotonic()
                        return self
                    if self.process.returncode is not None or self.failure:
                        raise OSError('SSH authentication or forwarding setup failed')
                    await asyncio.sleep(0.025)
        except BaseException:
            await self.aclose()
            raise

    async def _watch(self):
        try:
            while self.process.returncode is None:
                base = self.active_at if self.forward is not None and self.active_at is not None else self.started
                duration = self.startup_timeout if self.forward is not None and self.active_at is None else self.lifetime
                if time.monotonic() - base >= duration:
                    self.failure = 'SSH scope deadline exceeded; remote work may still be running'
                    break
                self._diagnostic()
                await asyncio.sleep(0.05)
        except (OSError,ValueError):
            self.failure = 'SSH diagnostic I/O or budget failed; remote state may be unknown'
        if self.failure:
            await _cleanup_process(self.process, [])

    async def aclose(self):
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        try:
            await wait_owned(self._closing)
        except asyncio.CancelledError:
            await finish_task(self._closing)
            raise

    async def _close(self):
        try:
            if self.watcher is not None:
                self.watcher.cancel()
                await asyncio.gather(self.watcher,return_exceptions=True)
            if self.process is not None:
                await _cleanup_process(self.process,[])
        finally:
            try:
                await self.transport.aclose()
            finally:
                if self.directory is not None:
                    await self.staging.__aexit__(None, None, None)
                    self.directory = None


class NativeChannel:
    """Binary reads apply backpressure through two four-fragment bounded queues.

    Captures never exceed max_output_bytes per stream. Exceeding a cap closes
    the channel explicitly; byte loss is never presented as successful output.
    ``wait`` drains unread queue entries and returns the full bounded capture.
    """

    def __init__(self, scope):
        self.scope = scope
        self.queues = {stream:asyncio.Queue(4) for stream in ('stdout','stderr')}
        self.buffers = {stream:bytearray() for stream in self.queues}
        self.read_locks = {stream:asyncio.Lock() for stream in self.queues}
        self.write_lock = asyncio.Lock()
        self.remaining = scope.options.max_stdin_bytes
        self.eof = set()
        self.closed = False
        self.input_closed = False
        self.failure = None
        self._waiter = None
        self._discarding = False
        self._closing = None
        self._failure_cleanup = None
        # Task factories may execute readers synchronously during construction.
        # Publish every field they own before starting either pump.
        self.pumps = [asyncio.create_task(self._pump(stream),name='swassh-channel-'+stream) for stream in self.queues]

    async def _pump(self, stream):
        reader = getattr(self.scope.process,stream)
        try:
            while chunk := await reader.read(4096):
                if self._discarding:
                    continue
                if len(self.buffers[stream]) + len(chunk) > self.scope.options.max_output_bytes:
                    self.failure = 'SSH channel output budget exceeded'
                    self._start_failure_cleanup()
                    continue
                self.buffers[stream].extend(chunk)
                await self.queues[stream].put(chunk)
        except (OSError,ValueError):
            self.failure = 'SSH channel read failed; remote state may be unknown'
            self._start_failure_cleanup()
        finally:
            self.eof.add(stream)
            if self._failure_cleanup is not None:
                await wait_owned(self._failure_cleanup)

    def _discard_output(self):
        """Release bounded queues and keep reading until native pipes reach EOF.

        Cancelling readers before process.wait() can leave a full StreamReader
        paused. Explicit close/failure discards subsequent chunks without
        growing captures; successful open channels retain their original caps.
        """
        self._discarding = True
        for queue in self.queues.values():
            while not queue.empty():
                queue.get_nowait()

    def _start_failure_cleanup(self):
        """A failed pump must keep draining while the owned native close runs."""
        self._discard_output()
        if self._failure_cleanup is None:
            self._failure_cleanup = asyncio.create_task(self.scope.aclose())

    def _check(self):
        if self.closed:
            raise RuntimeError('SSH channel scope is closed')
        if self.failure or self.scope.failure:
            raise OSError(self.failure or self.scope.failure)

    async def _guard(self):
        # A watcher publishes failure before native termination completes.
        # Await that termination before surfacing a failed async I/O operation.
        if self.failure or self.scope.failure:
            self._discard_output()
            await self.scope.aclose()
        self._check()

    async def read(self, stream='stdout'):
        """Read the next fragment of at most 4096 bytes, or b'' at stream EOF."""
        if stream not in self.queues:
            raise ValueError('channel stream must be stdout or stderr')
        async with self.read_locks[stream]:
            await self._guard()
            queue = self.queues[stream]
            while queue.empty():
                await self._guard()
                if stream in self.eof:
                    return b''
                await asyncio.sleep(0.01)
            return queue.get_nowait()

    async def send(self,data):
        async with self.write_lock:
            await self._guard()
            if self.input_closed:
                raise ValueError('SSH channel input is closed')
            if not isinstance(data,bytes) or len(data)>16384 or len(data)>self.remaining:
                raise ValueError('channel input requires bytes within per-send and cumulative budgets')
            self.remaining -= len(data)
            self.scope.process.stdin.write(data)
            await self.scope.process.stdin.drain()

    def close_input(self):
        self._check()
        if not self.input_closed:
            self.input_closed=True
            self.scope.process.stdin.close()

    async def wait(self):
        """Drain unread fragments and return both complete byte captures."""
        await self._guard()
        if self._waiter is None:
            self._waiter=asyncio.create_task(self._complete())
        return await wait_owned(self._waiter)

    async def _complete(self):
        async def drain(stream):
            while await self.read(stream):
                pass
        await asyncio.gather(*(drain(stream) for stream in self.queues))
        code=await self.scope.process.wait()
        await self._guard()
        text=_command_diagnostic(await _DiagnosticRead(self.scope._diagnostic).read(),getattr(self.scope,'command',None))
        # Sharing teardown can yield after the first guard. A concurrent owner
        # close or watcher failure must still prevent a successful capture.
        await self._guard()
        status,error,_=_outcome(code,text,True,self.scope.settings.auth_method)
        return ChannelCapture(status,code,bytes(self.buffers['stdout']),bytes(self.buffers['stderr']),error)

    async def aclose(self):
        self.closed=True
        self._discard_output()
        if self._closing is None:
            tasks=self.pumps + ([self._waiter] if self._waiter is not None else [])
            self._closing=asyncio.create_task(self._close(tasks))
        try:
            await wait_owned(self._closing)
        except asyncio.CancelledError:
            await finish_task(self._closing)
            raise

    async def _close(self,tasks):
        try:
            await self.scope.aclose()
        finally:
            # Readers remain alive until termination has closed the native
            # pipes. Cancellation only follows that ownership boundary.
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            if self._failure_cleanup is not None:
                await finish_task(self._failure_cleanup)
