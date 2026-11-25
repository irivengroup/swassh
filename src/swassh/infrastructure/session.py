"""Scoped OpenSSH multiplexing: the guarded master owns the connection lease."""

from ..application.task_ownership import wait_owned
import asyncio
import os
from pathlib import Path
import stat
import tempfile
import time

from ..domain.models import Status
from .authentication import Authentication
from .ssh import SSHTransport, _config, _cleanup_process, DIAGNOSTIC_LIMIT
from .process_guard import launch_native
from .lifecycle import finish_task


class PersistentSSHTransport(SSHTransport):
    """One host, one guarded master, serialized channels, no reconnect fallback.

    The private socket is scoped to this object. ControlPersist is disabled:
    neither normal exit nor parent death may leave an unmanaged SSH master.
    """
    def __init__(self, options, host, lifetime=300):
        if os.name != 'posix':
            raise ValueError('persistent sessions require a POSIX OpenSSH client with multiplexing support')
        if type(lifetime) not in (int, float) or not 1 <= lifetime <= 3600:
            raise ValueError('session lifetime must be between 1 and 3600 seconds')
        super().__init__(options)
        self.host = host
        self.lifetime = lifetime
        self.master = None
        self.directory = None
        self.watch = None
        self.lock = asyncio.Lock()
        self.closed = False
        self._close_task = None

    async def open(self):
        """Acquire shared capacity and authenticate before publishing the session."""
        if self.directory is not None or self.closed:
            raise RuntimeError('session cannot be opened twice')
        # Keep UNIX socket names short even when the caller has a long TMPDIR.
        self.directory = tempfile.TemporaryDirectory(prefix='swassh-mux-', dir='/tmp')
        root = Path(self.directory.name)
        self.socket = root/'control'
        config, diagnostic = root/'config', root/'diagnostic'
        settings = self.profiles.for_host(self.host)
        config.write_text(_config(self.host, self.options, settings,
            wire_lifetime=self.lifetime+settings.connect_timeout+self.options.report_timeout), encoding='utf-8')
        config.chmod(0o600)
        diagnostic.touch(mode=0o600)
        try:
            async with asyncio.timeout(settings.connect_timeout + self.options.report_timeout):
                self.master = await launch_native(self.executable, '-F', str(config),
                    '-E', str(diagnostic), '-M', '-N', '-S', str(self.socket),
                    '-o', 'ControlPersist=no', 'swassh-target', options=self.options,
                    max_native_seconds=self.lifetime,
                    stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=Authentication.environment(self.options, settings))
                while True:
                    if self.master.returncode is not None:
                        raise OSError('SSH session authentication or multiplexing failed')
                    if diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                        raise OSError('SSH session diagnostic budget exceeded')
                    try:
                        mode = self.socket.lstat().st_mode
                    except FileNotFoundError:
                        mode = 0
                    if stat.S_ISSOCK(mode):
                        break
                    if mode:
                        raise OSError('SSH session control path is not a socket')
                    await asyncio.sleep(0.05)
            self.watch = asyncio.create_task(self._watch(diagnostic))
        except BaseException:
            await self.aclose()
            raise
        return self

    async def _watch(self, diagnostic):
        deadline = time.monotonic() + self.lifetime
        try:
            while self.master.returncode is None:
                if time.monotonic() >= deadline or diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                    return
                await asyncio.sleep(0.1)
        finally:
            await _cleanup_process(self.master, [])

    def channel_arguments(self):
        # OpenSSH normally falls back to a fresh TCP connection if mux fails.
        # A failing proxy forbids that fallback; it cannot bypass admission or
        # accidentally authenticate and replay a command on a new connection.
        return ['-S', str(self.socket), '-o', 'LogLevel=DEBUG2', '-o', 'ControlMaster=no', '-o', 'ProxyJump=none',
                '-o', 'ProxyCommand=false']

    def channel_connected(self):
        return False

    def classify(self, code, diagnostic, complete, auth_method):
        if not complete:
            return Status.ERROR, 'SSH session diagnostic limit exceeded; remote state may be unknown', False
        if code == 0:
            return Status.SUCCESS, None, False
        if 'Received exit status from master ' in diagnostic:
            return Status.FAILED, None, False
        return Status.INTERRUPTED, 'SSH session interrupted; remote state may be unknown', False

    async def execute(self, host, command):
        async with self.lock:
            if host != self.host or self.closed or self.master is None or self.master.returncode is not None:
                raise RuntimeError('SSH session is closed or belongs to a different host')
            result = await super().execute(host, command)
            if result.status in (Status.TIMEOUT, Status.INTERRUPTED, Status.ERROR):
                await self.aclose()
            return result

    async def aclose(self):
        """Stop every native descendant before releasing the socket and lease."""
        self.closed = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        try:
            await wait_owned(self._close_task)
        except asyncio.CancelledError:
            await finish_task(self._close_task)
            raise

    async def _close(self):
        """One shared cleanup task prevents cancellation and concurrent closes
        from skipping the master or deleting its control directory too early.
        """
        try:
            if self.watch is not None:
                self.watch.cancel()
                await asyncio.gather(self.watch, return_exceptions=True)
                self.watch = None
            if self.master is not None:
                await _cleanup_process(self.master, [])
                self.master = None
        finally:
            try:
                await super().aclose()
            finally:
                if self.directory is not None:
                    self.directory.cleanup()
                    self.directory = None
