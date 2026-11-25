"""Final native diagnostics retain a bounded grace for Win32 sharing teardown."""
import asyncio
import ctypes
from ctypes import wintypes
import io
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host, Options, Status
from swassh.infrastructure import ssh
from swassh.infrastructure.channels import NativeChannel


class DiagnosticReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_posix_reader_preserves_bytes_and_the_existing_diagnostic_cap(self):
        stream = io.BytesIO(b'x' * (ssh.DIAGNOSTIC_LIMIT + 3))
        stream.read = Mock(wraps=stream.read)
        path = Mock()
        path.open.return_value = stream
        port = SimpleNamespace(**vars(os))
        port.name = 'posix'
        with patch.object(ssh, 'os', port):
            value = ssh._diagnostic_bytes(path)
        self.assertEqual(value, b'x' * (ssh.DIAGNOSTIC_LIMIT + 1))
        stream.read.assert_called_once_with(ssh.DIAGNOSTIC_LIMIT + 1)
        path.open.assert_called_once_with('rb')
        self.assertTrue(stream.closed)

    async def test_windows_reader_uses_the_existing_native_no_reparse_opener(self):
        stream = io.BytesIO(b'\x00\xffexact-native-bytes')
        stream.read = Mock(wraps=stream.read)
        path = Mock()
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        port.fdopen = Mock(return_value=stream)
        with patch.object(ssh, 'os', port), \
                patch('swassh.infrastructure.windows.open_file_without_reparse', return_value=17) as native_open:
            self.assertEqual(ssh._diagnostic_bytes(path), b'\x00\xffexact-native-bytes')
        native_open.assert_called_once_with(path, os.O_RDONLY)
        port.fdopen.assert_called_once_with(17, 'rb')
        stream.read.assert_called_once_with(ssh.DIAGNOSTIC_LIMIT + 1)
        self.assertTrue(stream.closed)

    async def test_success_returns_the_exact_bounded_reader_value(self):
        reader = Mock(return_value=b'private-diagnostic')
        self.assertEqual(await ssh._DiagnosticRead(reader).read(), b'private-diagnostic')
        reader.assert_called_once_with()

    async def test_only_windows_sharing_errors_receive_a_retry(self):
        for platform, code, retry in (('nt', 32, True), ('nt', 33, True),
                                       ('nt', 5, False), ('nt', None, False), ('posix', 32, False)):
            with self.subTest(platform=platform, code=code):
                error = PermissionError('synthetic access refusal')
                error.winerror = code
                reader = Mock(side_effect=[error, 'exact-text'])
                port = SimpleNamespace(**vars(os))
                port.name = platform
                sleep = AsyncMock()
                async_port = SimpleNamespace(**vars(asyncio))
                async_port.sleep = sleep
                with patch.object(ssh, 'os', port), patch.object(ssh, 'asyncio', async_port):
                    if retry:
                        self.assertEqual(await ssh._DiagnosticRead(reader).read(), 'exact-text')
                        sleep.assert_awaited_once()
                        self.assertGreater(sleep.await_args.args[0], 0)
                        self.assertLessEqual(sleep.await_args.args[0], 0.01)
                    else:
                        with self.assertRaises(PermissionError) as raised:
                            await ssh._DiagnosticRead(reader).read()
                        self.assertIs(raised.exception, error)
                        sleep.assert_not_awaited()

    async def test_persistent_sharing_failure_stops_at_the_same_two_second_grace(self):
        error = PermissionError('synthetic persistent sharing violation')
        error.winerror = 32
        reader = Mock(side_effect=error)
        clock = [0.0]
        delays = []
        async def sleep(delay):
            delays.append(delay)
            clock[0] += 1.01
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        async_port = SimpleNamespace(**vars(asyncio))
        async_port.get_running_loop = lambda: SimpleNamespace(time=lambda: clock[0])
        async_port.sleep = sleep
        with patch.object(ssh, 'os', port), patch.object(ssh, 'asyncio', async_port):
            with self.assertRaises(PermissionError) as raised:
                await ssh._DiagnosticRead(reader).read()
        self.assertIs(raised.exception, error)
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(delays, [0.01, 0.01])

    async def test_other_io_errors_are_never_hidden_or_retried(self):
        error = OSError('synthetic disk failure')
        reader = Mock(side_effect=error)
        with self.assertRaises(OSError) as raised:
            await ssh._DiagnosticRead(reader).read()
        self.assertIs(raised.exception, error)
        reader.assert_called_once_with()

    async def test_cancellation_abandons_no_background_reader(self):
        error = PermissionError('synthetic sharing violation')
        error.winerror = 33
        reader = Mock(side_effect=error)
        entered = asyncio.Event()
        async def sleep(delay):
            entered.set()
            await asyncio.Future()
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        async_port = SimpleNamespace(**vars(asyncio))
        async_port.sleep = sleep
        with patch.object(ssh, 'os', port), patch.object(ssh, 'asyncio', async_port):
            task = asyncio.create_task(ssh._DiagnosticRead(reader).read())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        reader.assert_called_once_with()


class DiagnosticChannelOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_during_final_read_cannot_publish_a_successful_capture(self):
        reading, release_read = asyncio.Event(), asyncio.Event()
        closing, release_close = asyncio.Event(), asyncio.Event()
        error = PermissionError('synthetic final-read sharing violation')
        error.winerror = 32
        diagnostic = Mock(side_effect=[error, 'Authenticated to synthetic\nExit status 0\n'])
        class Scope:
            options = Options()
            failure = None
            settings = SimpleNamespace(auth_method='publickey')
            def __init__(self):
                self.process = SimpleNamespace(stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(),
                                               wait=AsyncMock(return_value=0))
                self.process.stdout.feed_eof()
                self.process.stderr.feed_eof()
            def _diagnostic(self):
                return diagnostic()
            async def aclose(self):
                closing.set()
                await release_close.wait()
        async def retry_sleep(delay):
            reading.set()
            await release_read.wait()
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        async_port = SimpleNamespace(**vars(asyncio))
        async_port.sleep = retry_sleep
        channel = NativeChannel(Scope())
        waiter = asyncio.create_task(channel.wait())
        close_task = None
        try:
            with patch.object(ssh, 'os', port), patch.object(ssh, 'asyncio', async_port):
                await reading.wait()
                close_task = asyncio.create_task(channel.aclose())
                await closing.wait()
                release_read.set()
                with self.assertRaisesRegex(RuntimeError, 'closed'):
                    await waiter
        finally:
            release_read.set()
            release_close.set()
            if close_task is not None:
                await close_task
            await channel.aclose()


@unittest.skipUnless(os.name == 'nt', 'Win32 exclusive diagnostic handles')
class DiagnosticSharingIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_final_diagnostic_waits_for_owned_win32_handle_without_relaunch(self):
        from swassh.infrastructure import windows
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        release = threading.Event()
        closed = threading.Event()
        close_errors, read_errors, workers, launches = [], [], [], []
        original_open = Path.open
        native_open = windows.open_file_without_reparse
        process = SimpleNamespace(returncode=255, stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader())
        process.stdout.feed_eof()
        process.stderr.feed_eof()
        process.wait = AsyncMock(return_value=255)
        async def launch(*arguments, **settings):
            launches.append(arguments)
            diagnostic = Path(arguments[arguments.index('-E') + 1])
            diagnostic.write_text('ssh: connect to host synthetic port 22: Connection refused\n')
            handle = kernel.CreateFileW(str(diagnostic), 0x80000000, 0, None, 3, 0x80, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            probe = kernel.CreateFileW(str(diagnostic), 0x80000000, 3, None, 3, 0x80, None)
            self.assertEqual(probe, ctypes.c_void_p(-1).value)
            self.assertEqual(ctypes.get_last_error(), 32)
            def close_when_observed():
                release.wait()
                if not kernel.CloseHandle(handle):
                    close_errors.append(ctypes.get_last_error())
                closed.set()
            worker = threading.Thread(target=close_when_observed)
            workers.append(worker)
            worker.start()
            return process
        def observed_open(path, mode='r', *arguments, **settings):
            try:
                return original_open(path, mode, *arguments, **settings)
            except PermissionError as error:
                if path.name == 'diagnostic' and mode == 'rb':
                    read_errors.append(getattr(error, 'winerror', None))
                    # The holder closes only after a real failed read. No
                    # sleep is used to guess when native teardown will finish.
                    release.set()
                raise
        def observed_native_open(path, flags):
            try:
                return native_open(path, flags)
            except PermissionError as error:
                if path.name == 'diagnostic':
                    read_errors.append(getattr(error, 'winerror', None))
                    release.set()
                raise
        async def cleanup(native, tasks):
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            return {}
        with patch.object(ssh.LocalPreflight, 'transport', return_value=sys.executable), \
                patch('swassh.infrastructure.relay_connect.NativeConnector.find', return_value=None):
            transport = ssh.SSHTransport(Options())
        try:
            with patch.object(ssh, 'launch_native', launch), patch.object(Path, 'open', observed_open), \
                    patch.object(windows, 'open_file_without_reparse', observed_native_open), \
                    patch.object(ssh, '_cleanup_process', cleanup):
                result = await transport.execute(Host('synthetic'), 'true')
            self.assertEqual(result.status, Status.UNREACHABLE, (result, read_errors))
            self.assertEqual(result.exit_code, 255)
            self.assertEqual(result.attempts, 1)
            self.assertEqual(len(launches), 1)
            self.assertTrue(read_errors)
            self.assertTrue(all(code == 32 for code in read_errors))
        finally:
            release.set()
            for worker in workers:
                await asyncio.to_thread(worker.join, 2)
                self.assertFalse(worker.is_alive())
            await transport.aclose()
        self.assertTrue(closed.is_set())
        self.assertEqual(close_errors, [])
