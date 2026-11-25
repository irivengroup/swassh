"""Non-regression contracts for explicit session and PTY modes."""
import contextlib
import asyncio
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import time
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from swassh import Host,Options
from swassh.interfaces.cli import main
from swassh.infrastructure.session import PersistentSSHTransport
from swassh.infrastructure.terminal import TerminalMode
from swassh.infrastructure import session as native_session


import shutil


class NativeLifetimeFixture:
    """Publish a real execution marker before a long native wait.

    The guardian's original lifetime includes all native startup. A second
    instrumented Python interpreter is unrelated to this process-ownership
    contract. No timer, expected outcome, or guardian path is substituted.
    """

    def __init__(self, directory: Path, marker: Path):
        self.directory, self.marker = directory, marker

    def environment(self):
        """Return a private environment; never change the test process state."""
        return {**os.environ, 'SWASSH_NATIVE_READY': str(self.marker)}

    def arguments(self):
        """Use system-native blocking utilities, with no external network I/O."""
        if os.name == 'nt':
            system = Path(os.environ['SystemRoot']) / 'System32'
            command, sleeper = system / 'cmd.exe', system / 'ping.exe'
            if not command.is_file() or not sleeper.is_file():
                raise RuntimeError('native lifetime fixture requires Windows cmd and ping')
            script = self.directory / 'native-lifetime.cmd'
            # Only fixed batch syntax is interpreted. The private marker path
            # is expanded once inside quotes; Windows names cannot contain ".
            script.write_bytes(b'@echo off\r\n> "%SWASSH_NATIVE_READY%" echo started\r\n'
                b'"%SystemRoot%\\System32\\ping.exe" -n 61 -w 1000 127.0.0.1 >NUL\r\n')
            return [str(command), '/d', '/q', '/c', str(script)]
        shell, sleeper = shutil.which('sh'), shutil.which('sleep')
        if shell is None or sleeper is None:
            raise RuntimeError('native lifetime fixture requires sh and sleep')
        return [shell, '-c', 'printf started > "$1"; exec "$2" 60',
                'swassh-lifetime-fixture', str(self.marker), sleeper]


class PersistentStartupIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_guardian_does_not_extend_the_declared_lifetime_for_authentication(self):
        options=Options(connect_timeout=2,report_timeout=2)
        platform=SimpleNamespace(**vars(os));platform.name='posix'
        with patch.object(native_session,'os',platform),\
                patch('swassh.infrastructure.ssh.LocalPreflight.transport',return_value='synthetic-ssh'),\
                patch('swassh.infrastructure.relay_connect.NativeConnector.find',return_value=None):
            transport=PersistentSSHTransport(options,Host('one'),lifetime=1)
        factory=tempfile.TemporaryDirectory;temporary=SimpleNamespace(**vars(tempfile));staging=[]
        def allocate(*args,**kwargs):
            self.assertEqual(kwargs.pop('dir'),'/tmp')
            value=factory(*args,**kwargs);staging.append(Path(value.name));return value
        temporary.TemporaryDirectory=allocate
        original_lstat=Path.lstat
        def metadata(path,*args,**kwargs):
            if path==getattr(transport,'socket',None):return SimpleNamespace(st_mode=stat.S_IFSOCK|0o600)
            return original_lstat(path,*args,**kwargs)
        process=SimpleNamespace(returncode=None);calls=[]
        async def launch(*args,**kwargs):calls.append((args,kwargs));return process
        try:
            with patch.object(native_session,'tempfile',temporary),patch.object(Path,'lstat',metadata),\
                    patch.object(native_session,'launch_native',side_effect=launch),\
                    patch.object(native_session,'_cleanup_process',new_callable=AsyncMock):
                self.assertIs(await transport.open(),transport)
                self.assertEqual(len(calls),1)
                self.assertEqual(calls[0][1]['max_native_seconds'],1)
                config=staging[0]/'config'
                self.assertIn('ControlPersist=no',calls[0][0]);self.assertTrue(config.is_file())
                await transport.aclose()
        finally:
            # Closing also revokes the real private temporary directory.
            if transport.directory is not None:
                with patch.object(native_session,'_cleanup_process',new_callable=AsyncMock):await transport.aclose()
        self.assertFalse(staging[0].exists());self.assertTrue(transport.closed)


class SessionContracts(unittest.TestCase):
    def test_pty_is_explicit_and_strictly_boolean(self):
        self.assertFalse(Options().pty)
        self.assertTrue(Options(pty=True).pty)
        with self.assertRaises(ValueError):
            Options(pty=1)

    def test_idle_master_memory_is_reserved_in_addition_to_the_channel(self):
        from swassh.infrastructure.resources import resource_plan
        with patch('swassh.infrastructure.resources._available_memory', return_value=None):
            direct = resource_plan(Options(memory_budget_mib=64), guarded=True)
            self.assertGreaterEqual(direct.workers, 1)
            with self.assertRaises(ValueError):
                resource_plan(Options(memory_budget_mib=64), guarded=True, persistent_master=True)
            session = resource_plan(Options(memory_budget_mib=96, concurrency=1), guarded=True, persistent_master=True)
            self.assertEqual(session.memory_budget_bytes, 64 * 1024**2)
            self.assertEqual(session.workers, 1)

    def test_session_commands_are_bounded_validated_before_connecting(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'commands.json'
            for value, expected in [(['true', 'uname -r'], 0), ([], 2), ([None], 2), ([''], 2), ({'command': 'true'}, 2)]:
                source.write_text(json.dumps(value))
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(['session', '-H', 'host', '--commands-file', str(source), '--plan-only']), expected)

    def test_shell_refuses_fleet_and_nonterminal(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['shell', '-H', 'one', 'two', '--plan-only']), 2)
            with self.assertRaises(ValueError):
                with TerminalMode():
                    self.fail('nonterminal input accepted')

    @unittest.skipUnless(os.name == 'posix', 'session platform check is POSIX')
    def test_check_rejects_missing_session_commands_before_reporting_success(self):
        from swassh.application.preflight import CheckReport
        with tempfile.TemporaryDirectory() as directory:
            with patch('swassh.interfaces.cli.LocalPreflight.inspect', return_value=CheckReport(())):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(['session', '-H', 'host', '--commands-file', str(Path(directory)/'missing'), '--check']), 2)

    def test_windows_multiplexing_is_rejected_without_silent_fallback(self):
        with patch('swassh.infrastructure.session.os.name', 'nt'):
            with self.assertRaisesRegex(ValueError, 'POSIX'):
                PersistentSSHTransport(Options(), None)


class SessionLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_closed_master_and_queued_run_cannot_create_another_swarm(self):
        from swassh.interfaces import session as facade
        @contextlib.asynccontextmanager
        async def budget(options):
            yield
        class Transport:
            closed = False
            async def open(self):
                return self
            async def aclose(self):
                self.closed = True
        for queued in (False, True):
            transport = Transport()
            with patch.object(facade, 'PersistentSSHTransport', return_value=transport), \
                    patch.object(facade, 'invocation_budget', budget), \
                    patch.object(facade, 'resource_plan'), patch.object(facade, 'Swarm') as swarm:
                session = facade.Session('one')
                async with session:
                    if queued:
                        await session.lock.acquire()
                        pending = asyncio.create_task(session.run('true'))
                        await asyncio.sleep(0)
                        self.assertFalse(pending.done())
                        await transport.aclose()
                        session.lock.release()
                        with self.assertRaisesRegex(RuntimeError, 'closing or closed'):
                            await pending
                    else:
                        await transport.aclose()
                        with self.assertRaisesRegex(RuntimeError, 'enter an open Session'):
                            await session.run('true')
                with self.assertRaisesRegex(RuntimeError, 'enter an open Session'):
                    await session.run('true')
                swarm.assert_not_called()

    async def test_session_does_not_borrow_an_enclosing_invocation(self):
        from swassh import Session
        from swassh.infrastructure.bastion import _HELD, current_reservation
        from unittest.mock import AsyncMock, MagicMock
        observed=[]
        @contextlib.asynccontextmanager
        async def budget(options):
            observed.append(current_reservation())
            yield
        transport=MagicMock()
        transport.open=AsyncMock()
        transport.aclose=AsyncMock()
        token=_HELD.set(('synthetic-parent','parent-reservation'))
        try:
            with patch('swassh.interfaces.session.PersistentSSHTransport',return_value=transport), \
                    patch('swassh.interfaces.session.resource_plan'), \
                    patch('swassh.interfaces.session.invocation_budget',budget):
                async with Session('synthetic'):
                    self.assertEqual(observed,[None])
            self.assertEqual(current_reservation(),'parent-reservation')
            transport.aclose.assert_awaited_once()
        finally:
            _HELD.reset(token)

    async def test_guardian_enforces_lifetime_while_parent_loop_is_blocked(self):
        from swassh.infrastructure.process_guard import launch_native, release_guardian
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/'native-started'
            fixture = NativeLifetimeFixture(Path(directory), marker)
            process = await launch_native(*fixture.arguments(), env=fixture.environment(),
                options=Options(), connected=False, max_native_seconds=0.5,
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            try:
                # Prove native execution started; a protocol rejection returning
                # the same guardian code must never make this test pass.
                async with asyncio.timeout(3):
                    while not marker.exists():
                        self.assertIsNone(process.returncode, 'guardian rejected the request')
                        await asyncio.sleep(0.01)
                # Deliberately prevent any parent asyncio timer from firing.
                time.sleep(1)
                async with asyncio.timeout(3):
                    self.assertEqual(await process.wait(), 125)
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                release_guardian(process)
        for invalid in (0, -1, float('inf'), True):
            with self.assertRaises(ValueError):
                await launch_native(sys.executable, options=Options(), max_native_seconds=invalid)

    async def test_invalid_native_lifetimes_fail_before_resource_creation(self):
        """Invalid configuration must not depend on the native lifecycle case."""
        from swassh.infrastructure.process_guard import launch_native
        invalid = (0, -1, float('nan'), float('inf'), float('-inf'), True, False, '1')
        for value in invalid:
            with self.subTest(value=repr(value)):
                with patch('swassh.infrastructure.process_guard.tempfile.TemporaryDirectory') as allocate:
                    with self.assertRaises(ValueError):
                        await launch_native(sys.executable, options=Options(), max_native_seconds=value)
                    allocate.assert_not_called()

    async def test_scope_reuses_transport_and_releases_after_failure(self):
        from swassh import Session, Result, Status
        from unittest.mock import AsyncMock
        @contextlib.asynccontextmanager
        async def budget(options):
            yield
        class Transport:
            def __init__(self, options, host, lifetime):
                self.host, self.closed = host, False
                self.open = AsyncMock()
                self.execute = AsyncMock(return_value=Result(host, Status.SUCCESS, 'retained output'))
            def metrics(self):
                return {}
            async def aclose(self):
                self.closed = True
        with tempfile.TemporaryDirectory() as directory:
            options = Options(log_file=str(Path(directory)/'audit'), budget_dir=str(Path(directory)/'budgets'))
            with patch('swassh.interfaces.session.PersistentSSHTransport', Transport), patch('swassh.interfaces.session.invocation_budget', budget):
                session = Session('host', options)
                with self.assertRaises(RuntimeError):
                    await session.run('true')
                async with session:
                    for _ in range(2):
                        report = await session.run('true')
                        self.assertTrue(report.ok)
                        self.assertIn('retained output', report.to_text())
                    self.assertEqual(session.transport.execute.await_count, 2)
                    with self.assertRaisesRegex(RuntimeError, 'nested'):
                        async with Session('other', options):
                            self.fail('nested memory reservation accepted')
                    entered = asyncio.Event()
                    async def blocked(host, command):
                        entered.set()
                        await asyncio.Future()
                    session.transport.execute.side_effect = blocked
                    pending = asyncio.create_task(session.run('true'))
                    await entered.wait()
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                    self.assertTrue(session.transport.closed)
                with self.assertRaises(RuntimeError):
                    async with session:
                        self.fail('session reopened')

    async def test_open_failure_cleans_scope_and_allows_a_new_context(self):
        from swassh import Session
        from unittest.mock import AsyncMock, MagicMock
        @contextlib.asynccontextmanager
        async def budget(options):
            yield
        transport = MagicMock()
        transport.open = AsyncMock(side_effect=OSError('fixture open failure'))
        transport.aclose = AsyncMock()
        with patch('swassh.interfaces.session.PersistentSSHTransport', return_value=transport), patch('swassh.interfaces.session.invocation_budget', budget):
            for _ in range(2):
                with self.assertRaises(OSError):
                    async with Session('host'):
                        self.fail('failed master exposed')
            self.assertEqual(transport.aclose.await_count, 2)

    async def test_channel_never_opens_a_new_connection_or_retries(self):
        from swassh import Status
        transport = object.__new__(PersistentSSHTransport)
        transport.socket = Path('/private/control')
        self.assertIn('ProxyCommand=false', transport.channel_arguments())
        self.assertFalse(transport.channel_connected())
        for code, diagnostic, complete, expected in [
            (0, '', True, Status.SUCCESS), (7, 'Received exit status from master 7', True, Status.FAILED),
            (255, '', True, Status.INTERRUPTED), (0, '', False, Status.ERROR)]:
            status, error, retry = transport.classify(code, diagnostic, complete, 'publickey')
            self.assertEqual(status, expected)
            self.assertFalse(retry)

    @unittest.skipUnless(os.name == 'posix', 'POSIX terminal attributes')
    async def test_terminal_restored_when_body_raises(self):
        import pty
        import termios
        master, slave = pty.openpty()
        try:
            with os.fdopen(os.dup(slave), 'r') as input_stream, os.fdopen(os.dup(slave), 'w') as output_stream:
                saved = termios.tcgetattr(slave)
                with patch('sys.stdin', input_stream), patch('sys.stdout', output_stream):
                    with self.assertRaisesRegex(RuntimeError, 'fixture'):
                        with TerminalMode():
                            self.assertNotEqual(termios.tcgetattr(slave), saved)
                            raise RuntimeError('fixture')
                self.assertEqual(termios.tcgetattr(slave), saved)
        finally:
            os.close(master)
            os.close(slave)
