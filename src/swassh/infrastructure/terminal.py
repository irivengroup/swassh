"""Single-target interactive SSH with bounded lifetime and terminal restoration."""
import asyncio
import os
from pathlib import Path
import signal
import sys
import tempfile
import uuid

from .authentication import Authentication
from .audit import AuditTrail
from .preflight import LocalPreflight
from .process_guard import launch_native
from .ssh import _config, _cleanup_process, DIAGNOSTIC_LIMIT
from ..application.profiles import ProfileResolver


class TerminalMode:
    """Save and restore local POSIX terminal state even on exception/cancellation."""
    def __enter__(self):
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError('interactive shell requires a local input and output terminal')
        self.saved = None
        self.windows_modes = []
        if os.name == 'posix':
            import termios
            import tty
            self.fd = sys.stdin.fileno()
            self.saved = termios.tcgetattr(self.fd)
            try:
                tty.setraw(self.fd, termios.TCSANOW)
            except BaseException:
                termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
                raise
        elif os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            self.console = ctypes.WinDLL('kernel32', use_last_error=True)
            self.console.GetStdHandle.argtypes = [wintypes.DWORD]
            self.console.GetStdHandle.restype = wintypes.HANDLE
            self.console.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            self.console.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            for index in (-10, -11):
                handle = self.console.GetStdHandle(index & 0xffffffff)
                mode = wintypes.DWORD()
                if not self.console.GetConsoleMode(handle, ctypes.byref(mode)):
                    raise OSError('interactive shell requires native Windows console handles')
                self.windows_modes.append((handle, mode.value))
        else:
            raise ValueError('unsupported terminal platform')
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
        for handle, mode in self.windows_modes:
            if not self.console.SetConsoleMode(handle, mode):
                raise OSError('cannot restore Windows console mode')


class InteractiveShell:
    """Stream directly to a real terminal; never broadcast user keystrokes."""
    def __init__(self, options, host):
        if options.stdin_file or options.stream_output:
            raise ValueError('interactive shell cannot combine file stdin or JSON live output')
        self.options = options
        self.host, = ProfileResolver(options).targets([host])
        self.settings = ProfileResolver(options).for_host(self.host)

    async def run(self):
        executable = LocalPreflight().transport(self.options)
        process = watcher = waiter = None
        old_winch = None
        with tempfile.TemporaryDirectory(prefix='swassh-shell-') as directory:
            config, diagnostic = Path(directory)/'config', Path(directory)/'diagnostic'
            config.write_text(_config(self.host, self.options, self.settings), encoding='utf-8')
            config.chmod(0o600)
            diagnostic.touch(mode=0o600)
            async with AuditTrail(self.options.log_file, uuid.uuid4().hex) as audit:
                await audit.emit('shell_started', {'target': self.host.target})
                try:
                    with TerminalMode():
                        async with asyncio.timeout(self.settings.command_timeout):
                            process = await launch_native(executable, '-F', str(config), '-E', str(diagnostic),
                                '-tt', 'swassh-target', options=self.options,
                                max_native_seconds=self.settings.command_timeout,
                                stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                                env=Authentication.environment(self.options, self.settings))
                            if os.name == 'posix':
                                old_winch = signal.getsignal(signal.SIGWINCH)
                                def resize(signum, frame):
                                    try:
                                        os.killpg(process.pid, signal.SIGWINCH)
                                    except ProcessLookupError:
                                        pass
                                signal.signal(signal.SIGWINCH, resize)
                            async def watch():
                                while True:
                                    if diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                                        raise OSError('interactive SSH diagnostic budget exceeded')
                                    await asyncio.sleep(0.1)
                            watcher = asyncio.create_task(watch())
                            waiter = asyncio.create_task(process.wait())
                            done, _ = await asyncio.wait((watcher, waiter), return_when=asyncio.FIRST_COMPLETED)
                            if watcher in done:
                                await watcher
                            code = await waiter
                    await audit.emit('shell_finished', {'target': self.host.target, 'exit_code': code})
                    return code
                finally:
                    if old_winch is not None:
                        signal.signal(signal.SIGWINCH, old_winch)
                    await _cleanup_process(process, [t for t in (watcher, waiter) if t is not None])
