"""Private post-authentication acknowledgements never replace SSH trust checks."""
import asyncio
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from swassh import Host, LocalForward, Options
from swassh.infrastructure import channels, native_ready
from swassh.infrastructure.filesystem import PinnedDirectory
from swassh.infrastructure.native_ready import NativeReady


def envelope(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


class NativeReadyContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='swassh-readiness-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        with PinnedDirectory(self.root, private=True):
            pass

    def test_synthetic_peer_keeps_the_real_acknowledgement_when_extra_processes_are_unavailable(self):
        """The synthetic peer needs no fourth process to validate its callback."""
        import channel_peer
        ready = NativeReady(self.root)
        arguments = ['synthetic-peer', '-E', str(self.root/'diagnostic'),
                     '-L', '127.0.0.1:8080:internal:443', 'LocalCommand=' + ready.command(), 'swassh-target']
        with patch.object(channel_peer.sys, 'argv', arguments), \
                patch('subprocess.run', side_effect=OSError('synthetic process capacity exhausted')) as spawn, \
                patch.object(channel_peer.time, 'sleep'):
            self.assertEqual(channel_peer.main(), 0)
        self.assertTrue(ready.observed())
        spawn.assert_not_called()

    def test_synthetic_callback_preserves_validation_failure_and_its_three_second_cap(self):
        import channel_peer
        import threading
        self.assertEqual(channel_peer.ReadinessCallback.TIMEOUT, 3.0)
        with self.assertRaisesRegex(ValueError, 'invalid native readiness request'):
            channel_peer.ReadinessCallback().run('%%%')
        self.assertFalse((self.root/'authenticated').exists())
        release, entered = threading.Event(), threading.Event()
        threads = []
        actual_thread = threading.Thread

        def create(*args, **kwargs):
            thread = actual_thread(*args, **kwargs)
            threads.append(thread)
            return thread

        def blocked(request):
            entered.set()
            release.wait(1)

        try:
            with patch.object(channel_peer.threading, 'Thread', side_effect=create), \
                    patch.object(channel_peer.ReadinessCallback, 'TIMEOUT', .02), \
                    patch.object(NativeReady, 'record', side_effect=blocked), \
                    self.assertRaisesRegex(TimeoutError, 'exceeded its deadline'):
                channel_peer.ReadinessCallback().run('controlled-blocked-request')
            self.assertTrue(entered.is_set())
            self.assertFalse((self.root/'authenticated').exists())
        finally:
            release.set()
            for thread in threads:
                thread.join(timeout=1)
                self.assertFalse(thread.is_alive())


    def test_native_callback_entrypoint_is_silent_and_refuses_invalid_requests(self):
        import subprocess
        import sys
        ready = NativeReady(self.root)
        request = ready.command().rsplit(' ', 1)[-1]
        process = subprocess.run([sys.executable, '-m', 'swassh.infrastructure.native_ready', request],
            capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, b'')
        self.assertEqual(process.stderr, b'')
        self.assertTrue(ready.observed())
        before = ready.path.read_bytes()
        invalid = 'synthetic-private-invalid-request'
        process = subprocess.run([sys.executable, '-m', 'swassh.infrastructure.native_ready', invalid],
            capture_output=True, timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(process.stdout, b'')
        self.assertIn(b'ValueError: invalid native readiness request', process.stderr)
        self.assertNotIn(invalid.encode(), process.stderr)
        self.assertEqual(ready.path.read_bytes(), before)

    def test_atomic_acknowledgement_exact_token_and_missing_malformed_refusals(self):
        ready = NativeReady(self.root)
        self.assertFalse(ready.observed())
        self.assertFalse(ready.path.exists())
        request = ready.command().rsplit(' ', 1)[-1]
        native_ready.main([request])
        self.assertTrue(ready.observed())
        self.assertEqual(ready.path.read_bytes(), ready.token.encode())
        self.assertEqual(list(self.root.iterdir()), [ready.path])
        for value in (b'', b'wrong', ready.token.encode() + b'X' * 1024):
            ready.path.write_bytes(value)
            with self.subTest(value_length=len(value)), self.assertRaisesRegex(ValueError, 'mismatch'):
                ready.observed()
        ready.path.unlink()
        with patch.object(native_ready.sys, 'argv', ['native_ready', request]):
            native_ready.main()
        self.assertTrue(ready.observed())

    def test_rejects_injection_and_oversized_generated_command(self):
        ready = NativeReady(self.root)
        for character in '%!&|<>^\r\n\0"':
            with self.subTest(character=repr(character)), patch.object(native_ready.sys, 'executable', 'unsafe' + character), \
                    self.assertRaisesRegex(ValueError, 'literal Windows interpreter'):
                ready.command()
        ready.path = Path('x' * 2100) / 'authenticated'
        with self.assertRaisesRegex(ValueError, 'budget'):
            ready.command()

    def test_rejects_invalid_envelopes_fields_paths_and_tokens(self):
        path, token = str(self.root / 'authenticated'), 'a' * 64
        values = [None, {}, [], [path], [path, token, 'extra'], [1, token], [path, 1],
            [str(self.root / 'other'), token], ['authenticated', token], [path, 'a' * 63], [path, 'z' * 64]]
        requests = [envelope(value) for value in values]
        requests += [None, 'x' * 4097, '%%%', base64.urlsafe_b64encode(b'\xff').decode(),
            base64.urlsafe_b64encode(b'[' * 1100).decode(), base64.urlsafe_b64encode(b' ' * 2049).decode()]
        for request in requests:
            with self.subTest(request_type=type(request).__name__), self.assertRaisesRegex(ValueError, '^invalid native readiness request$'):
                NativeReady.record(request)
        for arguments in ([], ['one', 'two']):
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                native_ready.main(arguments)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_callback_storage_failure_propagates_without_acknowledgement(self):
        ready = NativeReady(self.root)
        with patch.object(native_ready, 'AtomicOutput', side_effect=OSError('synthetic storage refusal')), \
                self.assertRaisesRegex(OSError, 'storage refusal'):
            NativeReady.record(envelope([str(ready.path), ready.token]))
        self.assertFalse(ready.observed())

    def test_acknowledgement_rejects_special_files_and_hard_links(self):
        ready = NativeReady(self.root)
        NativeReady.record(envelope([str(ready.path), ready.token]))
        for mode, links in ((0o010000, 1), (0o100600, 2)):
            with self.subTest(mode=mode, links=links), \
                    patch.object(native_ready.os, 'fstat', return_value=SimpleNamespace(st_mode=mode, st_nlink=links)), \
                    patch.object(native_ready, 'PinnedDirectory') as directory:
                # Retain a real descriptor while isolating only metadata, so the
                # refusal cannot leak the already-open acknowledgement handle.
                directory.return_value.__enter__.return_value.open.side_effect = lambda *args: os.open(ready.path, os.O_RDONLY)
                with self.assertRaisesRegex(ValueError, 'regular file without hard links'):
                    ready.observed()


class WindowsScopeReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_posix_log_strategy_requires_authentication_and_forward_confirmation(self):
        for marker in ('Authenticated to synthetic', 'Authentication succeeded'):
            for forward in (True, False):
                scope = self.scope()
                if not forward:
                    with patch.object(channels, 'SSHTransport', return_value=scope.transport):
                        scope = channels.NativeSSHScope(Host('synthetic'), scope.options, 5, command='synthetic-command')
                process = SimpleNamespace(returncode=None)
                polls = []
                async def launch(*argv, **kwargs):
                    self.assertFalse(any(arg.startswith('LocalCommand=') for arg in argv))
                    scope.diagnostic.write_text('Connecting\n')
                    return process
                async def watch():
                    await asyncio.Future()
                real_sleep = asyncio.sleep
                async def sleep(delay):
                    polls.append(delay)
                    scope.diagnostic.write_text(marker + '\n' + (
                        'Local forwarding listening on 127.0.0.1 port 8080\n' if len(polls) == 2 else ''))
                    await real_sleep(0)
                port = SimpleNamespace(**vars(asyncio))
                port.sleep = sleep
                with self.subTest(marker=marker, forward=forward), \
                        patch.object(channels, 'os', SimpleNamespace(name='posix')), \
                        patch.object(channels, 'asyncio', port), \
                        patch.object(channels, 'launch_native', side_effect=launch), \
                        patch.object(scope, '_watch', side_effect=watch), \
                        patch.object(channels, '_cleanup_process', new_callable=AsyncMock) as cleanup:
                    try:
                        self.assertIs(await scope.open(), scope)
                        self.assertEqual(polls, [0.025] * (2 if forward else 1))
                        self.assertIsNone(scope.readiness)
                        self.assertIsNotNone(scope.active_at)
                    finally:
                        await scope.aclose()
                cleanup.assert_awaited_once_with(process, [])
                self.assertIsNone(scope.directory)

    async def test_log_reader_handles_unlaunched_scope_and_keeps_the_original_content_cap(self):
        scope = self.scope()
        with tempfile.TemporaryDirectory() as directory:
            scope.diagnostic = Path(directory) / 'diagnostic'
            scope.readiness = object()
            scope.process = None
            scope.diagnostic.write_bytes(b'bounded text')
            self.assertEqual(scope._diagnostic(), 'bounded text')
            scope.readiness = None
            scope.diagnostic.write_bytes(b'x' * (channels.DIAGNOSTIC_LIMIT + 1))
            with self.assertRaisesRegex(ValueError, 'SSH diagnostic budget exceeded'):
                scope._diagnostic()

    def scope(self):
        options = Options()
        transport = SimpleNamespace(executable='synthetic-ssh', profiles=SimpleNamespace(for_host=lambda host: options),
            _pacer=SimpleNamespace(acquire=AsyncMock()), aclose=AsyncMock())
        with patch.object(channels, 'SSHTransport', return_value=transport):
            return channels.NativeSSHScope(Host('synthetic'), options, 5, forward=LocalForward(8080, 'internal', 443))

    async def test_windows_readiness_uses_only_owned_callback_and_metadata_while_live(self):
        scope = self.scope()
        process = SimpleNamespace(returncode=None)
        arguments = []
        async def launch(*argv, **kwargs):
            arguments.extend(argv)
            # A real native client owns the log exclusively until it exits.
            request = next(arg for arg in argv if arg.startswith('LocalCommand=')).rsplit(' ', 1)[-1]
            NativeReady.record(request)
            return process
        async def watch():
            await asyncio.Future()
        with patch.object(channels, 'os', SimpleNamespace(name='nt')), \
                patch.object(channels, 'launch_native', side_effect=launch), \
                patch.object(scope, '_watch', side_effect=watch), \
                patch.object(channels, '_cleanup_process', new_callable=AsyncMock) as cleanup:
            try:
                self.assertIs(await scope.open(), scope)
                self.assertIn('PermitLocalCommand=yes', arguments)
                self.assertIn('EscapeChar none', (Path(scope.directory.name) / 'config').read_text())
                with patch.object(Path, 'open', side_effect=PermissionError('native writer denies readers')):
                    self.assertEqual(scope._diagnostic(), '')
                scope.diagnostic.write_bytes(b'x' * (channels.DIAGNOSTIC_LIMIT + 1))
                with self.assertRaisesRegex(ValueError, 'budget'):
                    scope._diagnostic()
                scope.diagnostic.write_text('Authenticated to synthetic\nExit status 0\n')
                process.returncode = 0
                self.assertIn('Exit status 0', scope._diagnostic())
            finally:
                await scope.aclose()
        cleanup.assert_awaited_once_with(process, [])
        self.assertIsNone(scope.directory)


if __name__ == '__main__':
    unittest.main()
