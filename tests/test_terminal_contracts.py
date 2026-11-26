"""Terminal restoration and native-session lifecycle at injected OS boundaries."""
import asyncio
import contextlib
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import Host,Options,Result,Status
from swassh.infrastructure import session,terminal
from swassh.infrastructure.ssh import SSHTransport


class TerminalRestorationTests(unittest.TestCase):
    def test_unsupported_platform_is_refused_before_entering_an_unmanaged_terminal_mode(self):
        stream = SimpleNamespace(isatty=lambda: True)
        with patch.object(terminal, 'os', SimpleNamespace(name='unsupported')), \
                patch.object(terminal.sys, 'stdin', stream), patch.object(terminal.sys, 'stdout', stream):
            with self.assertRaisesRegex(ValueError, 'unsupported terminal platform'):
                terminal.TerminalMode().__enter__()

    def test_posix_raw_mode_is_restored_after_normal_exit_body_error_and_setup_error(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.name='posix'
        for failure in (None,'body','setup'):
            termios=SimpleNamespace(TCSANOW=0,tcgetattr=Mock(return_value=['saved']),tcsetattr=Mock())
            tty=SimpleNamespace(setraw=Mock(side_effect=OSError('setup') if failure=='setup' else None))
            stream=Mock();stream.isatty.return_value=True;stream.fileno.return_value=12
            with patch.object(terminal,'os',fake_os),patch.object(terminal.sys,'stdin',stream),patch.object(terminal.sys,'stdout',stream),patch.dict(sys.modules,{'termios':termios,'tty':tty}):
                if failure:
                    with self.assertRaisesRegex(OSError,failure):
                        with terminal.TerminalMode():raise OSError('body')
                else:
                    with terminal.TerminalMode() as mode:self.assertEqual(mode.saved,['saved'])
            termios.tcgetattr.assert_called_once_with(12)
            termios.tcsetattr.assert_called_once_with(12,0,['saved'])
            tty.setraw.assert_called_once_with(12,0)

    def test_console_contracts_save_both_handles_and_surface_restoration_failure(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.name='nt'
        stream=Mock();stream.isatty.return_value=True
        for failing_get in (False,True):
            console=Mock();console.GetStdHandle.side_effect=(10,11)
            def get(handle,pointer):pointer._obj.value=7;return not failing_get
            console.GetConsoleMode.side_effect=get;console.SetConsoleMode.return_value=1
            with patch.object(terminal,'os',fake_os),patch.object(terminal.sys,'stdin',stream),patch.object(terminal.sys,'stdout',stream),patch('ctypes.WinDLL',return_value=console,create=True):
                if failing_get:
                    with self.assertRaisesRegex(OSError,'native Windows'):terminal.TerminalMode().__enter__()
                else:
                    mode=terminal.TerminalMode().__enter__()
                    self.assertEqual(mode.windows_modes,[(10,7),(11,7)])
                    mode.__exit__(None,None,None)
                    self.assertEqual([call.args for call in console.SetConsoleMode.call_args_list],[(10,7),(11,7)])
                    console.SetConsoleMode.return_value=0
                    with self.assertRaisesRegex(OSError,'restore'):mode.__exit__(None,None,None)
        for incoming,outgoing in ((False,True),(True,False)):
            with patch.object(terminal.sys,'stdin',SimpleNamespace(isatty=lambda:incoming)),patch.object(terminal.sys,'stdout',SimpleNamespace(isatty=lambda:outgoing)),self.assertRaises(ValueError):
                terminal.TerminalMode().__enter__()


class InteractiveShellBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_shell_completion_diagnostic_failure_timeout_and_resize_always_drain_tasks(self):
        for mode in ('success','failed','diagnostic','timeout','launch','resize-gone','windows'):
            with self.subTest(mode=mode):
                events=[];handlers={};fake_os=SimpleNamespace(**vars(os));fake_os.name='posix';fake_os.killpg=Mock(side_effect=ProcessLookupError() if mode=='resize-gone' else None)
                if mode == 'windows':
                    fake_os.name = 'nt'
                fake_signal=SimpleNamespace(**vars(signal));fake_signal.SIGWINCH=getattr(signal,'SIGWINCH',28)
                fake_signal.getsignal=lambda number:'previous-handler'
                def register(number,callback):handlers[number]=callback;events.append('restore' if callback=='previous-handler' else 'install')
                fake_signal.signal=register
                class Audit:
                    def __init__(self,*args):pass
                    async def __aenter__(self):return self
                    async def __aexit__(self,*args):events.append('audit-close')
                    async def emit(self,name,fields):events.append((name,fields))
                process=SimpleNamespace(pid=123,returncode=0)
                async def wait():
                    if mode=='timeout':await asyncio.Future()
                    await asyncio.sleep(0)
                    if fake_signal.SIGWINCH in handlers:handlers[fake_signal.SIGWINCH](0,None)
                    return 7 if mode=='failed' else 0
                process.wait=wait
                async def launch(*args,**kwargs):
                    if mode=='launch':raise OSError('launch')
                    self.assertEqual(kwargs['max_native_seconds'],0.01 if mode=='timeout' else 2)
                    if mode=='diagnostic':Path(args[args.index('-E')+1]).write_bytes(b'x'*(terminal.DIAGNOSTIC_LIMIT+1))
                    events.append('launch');return process
                async def cleanup(native,tasks):
                    for task in tasks:task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
                    events.append('cleanup')
                    self.assertTrue(all(task.done() for task in tasks))
                options=Options(command_timeout=0.01 if mode=='timeout' else 2)
                with patch.object(terminal,'os',fake_os),patch.object(terminal,'signal',fake_signal),patch.object(terminal,'AuditTrail',Audit),patch.object(terminal,'TerminalMode',return_value=contextlib.nullcontext()),patch.object(terminal.LocalPreflight,'transport',return_value='synthetic-client'),patch.object(terminal,'launch_native',side_effect=launch),patch.object(terminal,'_cleanup_process',side_effect=cleanup):
                    shell=terminal.InteractiveShell(options,Host('one'))
                    if mode in ('diagnostic','timeout','launch'):
                        with self.assertRaises(TimeoutError if mode=='timeout' else OSError):await shell.run()
                    else:self.assertEqual(await shell.run(),7 if mode=='failed' else 0)
                self.assertEqual(events[-2:],['cleanup','audit-close'])
                if mode not in ('launch', 'windows'):self.assertIn('restore',events)
                if mode == 'windows':
                    self.assertNotIn('install', events)
                    self.assertNotIn('restore', events)
                if mode=='failed':self.assertIn(('shell_finished',{'target':'one:22','exit_code':7}),events)
        for options in (Options(stdin_file='input'),Options(stream_output=True)):
            with self.assertRaises(ValueError):terminal.InteractiveShell(options,Host('one'))


class MultiplexedSessionBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_lifetime_validation_unopened_master_and_closed_scope_refuse_new_channels(self):
        port = SimpleNamespace(**vars(os))
        port.name = 'posix'
        with patch.object(session, 'os', port), \
                patch('swassh.infrastructure.ssh.LocalPreflight.transport', return_value='synthetic-client'), \
                patch('swassh.infrastructure.relay_connect.NativeConnector.find', return_value=None):
            for lifetime in (True, None, '1', 0, 3601, float('nan')):
                with self.subTest(lifetime=lifetime), self.assertRaisesRegex(ValueError, 'session lifetime'):
                    session.PersistentSSHTransport(Options(), Host('one'), lifetime)
            transport = session.PersistentSSHTransport(Options(), Host('one'))
        with patch.object(SSHTransport, 'execute', new_callable=AsyncMock) as execute, \
                patch.object(session, '_cleanup_process', new_callable=AsyncMock) as cleanup:
            with self.assertRaisesRegex(RuntimeError, 'session is closed'):
                await transport.execute(Host('one'), 'true')
            transport.master = SimpleNamespace(returncode=255)
            with self.assertRaisesRegex(RuntimeError, 'session is closed'):
                await transport.execute(Host('one'), 'true')
            diagnostic = Mock()
            await transport._watch(diagnostic)
            diagnostic.stat.assert_not_called()
            cleanup.assert_awaited_once_with(transport.master, [])
            transport.master = None
            await transport.aclose()
            await transport.aclose()
            with self.assertRaisesRegex(RuntimeError, 'cannot be opened twice'):
                await transport.open()
            execute.assert_not_awaited()
        self.assertIsNone(transport.directory)

    async def test_session_authentication_socket_publication_and_errors_close_the_scope(self):
        original_temporary=tempfile.TemporaryDirectory;original_lstat=Path.lstat
        for outcome in ('ready','late-ready','authentication','diagnostic','wrong-file'):
            with self.subTest(outcome=outcome):
                fake_os=SimpleNamespace(**vars(os));fake_os.name='posix'
                native=SimpleNamespace(returncode=255 if outcome=='authentication' else None)
                snapshots=[];stat_calls=[]
                def lstat(path,*args,**kwargs):
                    if path.name=='control':
                        stat_calls.append(path)
                        if outcome=='late-ready' and len(stat_calls)==1:raise FileNotFoundError(path)
                        return SimpleNamespace(st_mode=stat.S_IFREG if outcome=='wrong-file' else stat.S_IFSOCK)
                    return original_lstat(path,*args,**kwargs)
                async def launch(*args,**kwargs):
                    snapshots.append((args,kwargs))
                    if outcome=='diagnostic':Path(args[args.index('-E')+1]).write_bytes(b'x'*(session.DIAGNOSTIC_LIMIT+1))
                    return native
                async def cleanup(process,tasks):native.returncode=0
                with patch.object(session,'os',fake_os),patch.object(session.tempfile,'TemporaryDirectory',side_effect=lambda **kw:original_temporary(prefix=kw['prefix'])),patch.object(Path,'lstat',lstat),patch.object(session,'launch_native',side_effect=launch),patch.object(session,'_cleanup_process',side_effect=cleanup),patch('swassh.infrastructure.ssh.LocalPreflight.transport',return_value='synthetic-client'):
                    transport=session.PersistentSSHTransport(Options(),Host('one'),lifetime=3)
                    if outcome in ('authentication','diagnostic','wrong-file'):
                        with self.assertRaises(OSError):await transport.open()
                        self.assertTrue(transport.closed);self.assertIsNone(transport.directory)
                    else:
                        self.assertIs(await transport.open(),transport)
                        self.assertEqual(snapshots[0][1]['max_native_seconds'],3)
                        self.assertIn('ControlPersist=no',snapshots[0][0])
                        with self.assertRaises(RuntimeError):await transport.open()
                        with patch.object(SSHTransport,'execute',return_value=Result(Host('one'),Status.SUCCESS,exit_code=0)) as execute:
                            result=await transport.execute(Host('one'),'opaque');self.assertTrue(result.ok)
                            execute.assert_awaited_once_with(Host('one'),'opaque')
                            with self.assertRaises(RuntimeError):await transport.execute(Host('another'),'opaque')
                        with patch.object(SSHTransport,'execute',return_value=Result(Host('one'),Status.TIMEOUT)):
                            self.assertEqual((await transport.execute(Host('one'),'opaque')).status,Status.TIMEOUT)
                        self.assertTrue(transport.closed);self.assertIsNone(transport.directory)
                        with self.assertRaises(RuntimeError):await transport.execute(Host('one'),'opaque')

    async def test_master_watch_expires_on_deadline_or_diagnostic_growth_and_cleans_up(self):
        for oversized in (False,True):
            transport=object.__new__(session.PersistentSSHTransport)
            transport.master=SimpleNamespace(returncode=None);transport.lifetime=1
            path=Mock();path.stat.return_value=SimpleNamespace(st_size=session.DIAGNOSTIC_LIMIT+1 if oversized else 0)
            with patch.object(session.time,'monotonic',side_effect=(0,0.5 if oversized else 1.5)),patch.object(session,'_cleanup_process',new_callable=AsyncMock) as cleanup:
                await transport._watch(path)
            cleanup.assert_awaited_once_with(transport.master,[])
