"""Native guardian control-flow contracts with in-memory kernel/process ports.

These tests do not signal the host, start commands, or publish credentials.
Private request/receipt files belong to isolated integration fixtures; process
and kernel failures are deterministic and retain cleanup-order assertions.
"""
import contextlib
import asyncio
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Host,Options
from swassh.infrastructure import process_guard as guard

SIGWINCH=getattr(signal,'SIGWINCH',28)
SIGKILL=getattr(signal,'SIGKILL',9)


class GuardianRequestTests(unittest.TestCase):
    def test_windows_guardian_refuses_an_embedded_posix_relay_before_native_launch(self):
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        parent, job, pool = Mock(), Mock(), Mock()
        parent.alive.return_value = True
        pool.ticket.return_value.poll.return_value = True
        request = self.request() | {'parent_fd': None, 'parent_token': 1234,
                                   'relay': {'host': 'synthetic', 'port': 22, 'connect_timeout': 1}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'
            path.write_text(json.dumps(request), encoding='utf-8')
            with patch.object(guard, 'os', port), patch.object(guard.signal, 'signal'), \
                    patch.object(guard, 'SharedBudget', return_value=pool), \
                    patch('swassh.infrastructure.windows.ParentProcess', return_value=parent), \
                    patch('swassh.infrastructure.windows.KillJob', return_value=job), \
                    patch.object(guard.subprocess, 'Popen') as launch, \
                    self.assertRaisesRegex(ValueError, 'one admitted POSIX connection'):
                guard.main(path)
        launch.assert_not_called()
        pool.ticket.return_value.close.assert_called_once()
        pool.close.assert_called_once()
        parent.close.assert_called_once()

    @staticmethod
    def request():
        return dict(argv=['synthetic-ssh','target'],budget={},connections=1,bandwidth=1024,
                    parent_pid=41,parent_token=None,parent_fd=7,invocation=None,max_native_seconds=None)

    def test_malformed_request_and_lifetime_never_admit_or_launch(self):
        original=self.request()
        values=[None,[],{}, {**original,'extra':1},{**original,'argv':[]},{**original,'argv':'ssh'},
                {**original,'argv':[1]},{**original,'argv':['bad\0argument']}]
        for lifetime in (True,'1',0,-1,float('nan'),float('inf')):
            values.append({**original,'max_native_seconds':lifetime})
        for value in values:
            with self.subTest(value=str(value)[:100]),patch('builtins.open',return_value=io.BytesIO(json.dumps(value).encode())),patch.object(guard,'SharedBudget') as pool,patch.object(guard.subprocess,'Popen') as launch,self.assertRaises(ValueError):
                guard.main('unused-request')
            pool.assert_not_called();launch.assert_not_called()
        with patch('builtins.open',return_value=io.BytesIO(b'x'*131073)),self.assertRaisesRegex(ValueError,'too large'):
            guard.main('unused-request')

    def test_control_pipe_type_and_descriptor_bounds_are_rejected(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.name='posix'
        for fd in (None,True,'7',-1,0,2):
            raw=json.dumps({**self.request(),'parent_fd':fd}).encode()
            with patch('builtins.open',return_value=io.BytesIO(raw)),patch.object(guard,'os',fake_os),patch.object(guard.signal,'signal'),self.assertRaisesRegex(ValueError,'control pipe'):
                guard.main('unused-request')


class GuardianLifecycleTests(unittest.TestCase):
    def run_case(self,*,exit_code=0,alive=None,polls=None,lifetime=None,connection_failure=None,
                 relay=False,relay_error=False,signal_during_poll=None,existing_metrics=False,connections=1,invocation=None,
                 admission_limit=None,relay_diagnostic=True,expect_invalid_relay=False):
        events=[];handlers={};clock=iter((0.,0.01,0.02,0.5,0.6,0.7,0.8,0.9,1.,1.1,1.2))
        fake_os=SimpleNamespace(**vars(os));fake_os.name='posix';fake_os.killpg=Mock()
        fake_signal=SimpleNamespace(**vars(signal));fake_signal.SIGWINCH=SIGWINCH;fake_signal.SIGKILL=SIGKILL
        process=Mock(pid=12345,returncode=exit_code)
        values=iter(polls or [exit_code])
        def poll():
            if signal_during_poll:handlers[signal_during_poll](0,None)
            return next(values,exit_code)
        process.poll.side_effect=poll
        process.wait.side_effect=lambda *a,**kw:events.append('native-stopped') or exit_code
        lease=Mock();lease.poll.side_effect=[False,True];lease.retry_after=0.01
        lease.close.side_effect=lambda:events.append('lease-closed')
        pool=Mock();pool.ticket.return_value=lease;pool.close.side_effect=lambda:events.append('pool-closed')
        embedded=Mock();embedded.arguments.side_effect=lambda argv:argv
        embedded.failed.is_set.return_value=bool(connection_failure or relay_error)
        embedded.connection_failure=connection_failure
        embedded.close.side_effect=lambda:events.append('relay-closed')
        # Only the guardian's clock is synthetic. Receipt writers and unittest
        # keep their own clocks and cannot consume the deterministic samples.
        fake_time=SimpleNamespace(**vars(guard.time));fake_time.monotonic=lambda:next(clock);fake_time.sleep=Mock()
        alive_values=iter(alive or [True]*20)
        def selected(*args):return ([],[],[]) if next(alive_values,False) else ([7],[],[])
        def register(number,callback):handlers[number]=callback
        data={**GuardianRequestTests.request(),'max_native_seconds':lifetime,'connections':connections,'invocation':invocation}
        if admission_limit is not None:data['admission_wait_limit']=admission_limit
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'request.json';diagnostic=Path(directory)/'diagnostic.log'
            if relay:
                data.update(relay={'hostname':'synthetic','port':22})
                if relay_diagnostic:data['argv']+=['-E',str(diagnostic)]
            path.write_text(json.dumps(data),encoding='utf-8')
            if existing_metrics:(path.parent/'metrics.json').write_text('original metric',encoding='utf-8')
            fake_signal.signal=register
            with patch.object(guard,'os',fake_os),patch.object(guard,'signal',fake_signal),patch.object(guard.select,'select',side_effect=selected),patch.object(guard,'time',fake_time),patch.object(guard,'SharedBudget',return_value=pool),patch.object(guard.subprocess,'Popen',return_value=process) as launch,patch('swassh.infrastructure.socket_relay.GuardianRelay',return_value=embedded):
                error=None
                try:value=guard.main(path)
                except ValueError as failure:
                    if not expect_invalid_relay:raise
                    value=None;error=failure
            metrics=(path.parent/'metrics.json').read_text(encoding='utf-8')
            marker=diagnostic.read_text(encoding='utf-8') if diagnostic.exists() else ''
        return SimpleNamespace(value=value,events=events,pool=pool,lease=lease,launch=launch,
                               process=process,os=fake_os,metrics=metrics,marker=marker,embedded=embedded,sleep=fake_time.sleep,error=error)

    def test_grant_observed_after_admission_deadline_is_released_without_native_spawn(self):
        case=self.run_case(admission_limit=0.2)
        self.assertEqual(case.value,125);case.launch.assert_not_called()
        self.assertEqual(case.lease.poll.call_count,2)
        case.lease.close.assert_called_once();case.pool.close.assert_called_once()
        self.assertEqual(case.events[-2:],['lease-closed','pool-closed'])

    def test_relay_rejects_a_multiple_connection_reservation_before_native_launch(self):
        case=self.run_case(relay=True,connections=2,expect_invalid_relay=True)
        self.assertIsInstance(case.error,ValueError);self.assertIn('one admitted POSIX connection',str(case.error))
        case.launch.assert_not_called();case.embedded.arguments.assert_not_called()
        case.lease.close.assert_called_once();case.pool.close.assert_called_once()

    def test_relay_failure_without_diagnostic_argument_never_fabricates_a_marker(self):
        case=self.run_case(relay=True,relay_error=True,connection_failure='timeout',relay_diagnostic=False,polls=[None,0])
        self.assertEqual(case.value,125);self.assertEqual(case.marker,'');case.launch.assert_called_once()
        self.assertLess(case.events.index('native-stopped'),case.events.index('relay-closed'))
        self.assertLess(case.events.index('relay-closed'),case.events.index('lease-closed'))

    def test_success_signal_exit_and_no_network_budget_have_explicit_receipts(self):
        for code in (0,255,-15):
            with self.subTest(code=code):
                case=self.run_case(exit_code=code)
                self.assertEqual(case.value,code if code>=0 else 128-code)
                self.assertLess(case.events.index('native-stopped'),case.events.index('lease-closed'))
                self.assertLess(case.events.index('lease-closed'),case.events.index('pool-closed'))
                self.assertEqual(set(json.loads(case.metrics)),{'admission_wait_seconds','native_seconds'})
                case.pool.ticket.assert_called_once_with(connections=1,bandwidth=1024,parent=None,activate=True)
        case=self.run_case(connections=0)
        self.assertEqual(case.value,0);case.pool.ticket.assert_not_called()
        case=self.run_case(connections=0,invocation='a'*32)
        case.pool.ticket.assert_called_once_with(connections=0,bandwidth=1024,parent='a'*32,activate=True)

    def test_parent_death_at_each_admission_boundary_prevents_or_stops_launch(self):
        for samples,launched in (([False],False),([True,False],False),([True,True,False],False),([True,True,True,False],True)):
            with self.subTest(samples=samples):
                case=self.run_case(alive=samples,polls=[None,None])
                self.assertEqual(case.value,125)
                if launched:case.launch.assert_called_once()
                else:case.launch.assert_not_called()
        # Normal admission then parent-pipe EOF while the child is running.
        case=self.run_case(polls=[None,None],signal_during_poll=signal.SIGTERM)
        self.assertEqual(case.value,125);case.launch.assert_called_once()
        self.assertEqual(case.events[-2:],['lease-closed','pool-closed'])

    def test_independent_lifetime_and_resize_forwarding_keep_cleanup_order(self):
        case=self.run_case(polls=[None,None],lifetime=0.1,relay=True)
        self.assertEqual(case.value,125)
        self.assertLess(case.events.index('native-stopped'),case.events.index('relay-closed'))
        self.assertLess(case.events.index('relay-closed'),case.events.index('lease-closed'))
        case=self.run_case(polls=[None,0],signal_during_poll=SIGWINCH)
        self.assertEqual(case.value,0)
        self.assertIn(((12345,SIGWINCH),{}),[(call.args,call.kwargs) for call in case.os.killpg.call_args_list])

    def test_only_proven_preconnect_failures_create_constant_private_markers(self):
        for reason,expected in (('timeout','connection timed out'),('unreachable','connection refused'),(None,'')):
            with self.subTest(reason=reason):
                case=self.run_case(polls=[None,0],relay=True,connection_failure=reason,relay_error=True)
                self.assertEqual(case.value,125)
                if expected:self.assertEqual(case.marker,'swassh guardian: '+expected+' before authentication\n')
                else:self.assertEqual(case.marker,'')
                self.assertNotIn('synthetic',case.marker)
        case=self.run_case(existing_metrics=True)
        self.assertEqual(case.value,0)
        self.assertEqual(case.metrics,'original metric')
        self.assertEqual(case.events[-1],'pool-closed')

    def test_stop_native_handles_disappeared_groups_and_escalates_after_grace(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.name='posix';fake_os.killpg=Mock(side_effect=ProcessLookupError())
        fake_signal=SimpleNamespace(**vars(signal));fake_signal.SIGKILL=SIGKILL
        process=Mock(pid=100);process.wait.side_effect=[subprocess.TimeoutExpired('synthetic',0.35),0]
        with patch.object(guard,'os',fake_os),patch.object(guard,'signal',fake_signal):guard._stop_native(process)
        self.assertEqual([call.args[1] for call in fake_os.killpg.call_args_list],[signal.SIGTERM,SIGKILL])
        self.assertEqual(process.wait.call_args_list[0].kwargs,{'timeout':0.35})
        for running in (True,False):
            fake_os.name='nt';process=Mock();process.poll.return_value=None if running else 0
            with patch.object(guard,'os',fake_os):guard._stop_native(process)
            self.assertEqual(process.kill.call_count,int(running));process.wait.assert_called_once_with()

    def test_windows_parent_identity_and_job_termination_precede_any_lease_release(self):
        fake_os=SimpleNamespace(**vars(os));fake_os.name='nt'
        for alive in (False,True):
            events=[];parent=Mock();parent.alive.return_value=alive
            parent.close.side_effect=lambda:events.append('parent-close')
            pool=Mock();lease=pool.ticket.return_value;lease.poll.return_value=True
            lease.close.side_effect=lambda:events.append('lease-close')
            pool.close.side_effect=lambda:events.append('pool-close')
            job=Mock();job.terminate.side_effect=lambda code:events.append(('job-terminate',code))
            native=Mock(returncode=7);native.poll.return_value=7
            data={**GuardianRequestTests.request(),'parent_fd':None,'parent_token':1234}
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'request.json';path.write_text(json.dumps(data),encoding='utf-8')
                with patch.object(guard,'os',fake_os),patch.object(guard.signal,'signal'),patch('swassh.infrastructure.windows.KillJob',return_value=job),patch('swassh.infrastructure.windows.ParentProcess',return_value=parent) as create_parent,patch.object(guard,'SharedBudget',return_value=pool),patch.object(guard.subprocess,'Popen',return_value=native) as launch,contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(guard.main(path),7 if alive else 125)
            create_parent.assert_called_once_with(41,1234)
            self.assertEqual(events[0],('job-terminate',7 if alive else 125))
            self.assertEqual(events[-1],'parent-close')
            if alive:
                self.assertLess(events.index(('job-terminate',7)),events.index('lease-close'))
                native.wait.assert_called_once();launch.assert_called_once()
            else:launch.assert_not_called();pool.ticket.assert_not_called()


class GuardianMetricTests(unittest.TestCase):
    def test_metrics_bounds_types_missing_and_double_release(self):
        self.assertEqual(guard.native_metrics(SimpleNamespace()),{})
        with tempfile.TemporaryDirectory() as directory:
            folder=SimpleNamespace(name=directory,cleanup=Mock())
            process=SimpleNamespace(_swassh_guardian=(None,folder))
            path=Path(directory)/'metrics.json'
            for value in ([],None,{}, {'admission_wait_seconds':True,'native_seconds':0},
                          {'admission_wait_seconds':-1,'native_seconds':0},
                          {'admission_wait_seconds':0,'native_seconds':1e12},
                          {'admission_wait_seconds':0,'native_seconds':float('nan')}):
                path.write_text(json.dumps(value),encoding='utf-8')
                self.assertEqual(guard.native_metrics(process),{})
            path.write_text('x'*1025,encoding='utf-8');self.assertEqual(guard.native_metrics(process),{})
            # Parsing succeeds; size rejection must be independent of JSON errors.
            path.write_text(' '*1023+'{}',encoding='utf-8')
            self.assertEqual(len(path.read_bytes()),1025);self.assertEqual(json.loads(path.read_bytes()),{})
            self.assertEqual(guard.native_metrics(process),{})
            path.write_text('{"admission_wait_seconds":0.1,"native_seconds":2}',encoding='utf-8')
            self.assertEqual(guard.native_metrics(process),{'admission_wait_seconds':0.1,'native_seconds':2})
            path.unlink();self.assertEqual(guard.native_metrics(process),{})
            guard.release_guardian(process);guard.release_guardian(process)
            folder.cleanup.assert_called_once();self.assertIsNone(process._swassh_guardian)


class GuardianLaunchIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_lifetime_and_jump_cost_are_serialized_with_real_owned_pipe_cleanup(self):
        port=SimpleNamespace(**vars(os));port.name='posix';observed=[]
        request={'host':'synthetic','port':22,'connect_timeout':2,'connector':None}
        process=SimpleNamespace(returncode=0)
        async def create(*argv,**kwargs):
            path=Path(argv[-1]);observed.append((json.loads(path.read_bytes()),kwargs,path.parent));return process
        with patch.object(guard,'os',port),patch.object(asyncio,'create_subprocess_exec',side_effect=create),\
                guard.native_relay(request,3):
            returned=await guard.launch_native('synthetic-ssh','target',options=Options(jump_host=Host('jump')),max_native_seconds=5)
        self.assertIs(returned,process);self.assertEqual(len(observed),1)
        data,settings,directory=observed[0]
        self.assertEqual(data['relay'],request);self.assertEqual(data['max_native_seconds'],3)
        self.assertEqual(data['admission_wait_limit'],3);self.assertEqual(data['connections'],2)
        self.assertEqual(settings['pass_fds'],(data['parent_fd'],))
        writer=process._swassh_guardian[0]
        try:
            with self.assertRaises(OSError):os.fstat(data['parent_fd'])
            self.assertIsNotNone(os.fstat(writer));self.assertIsNone(guard._RELAY.get())
        finally:guard.release_guardian(process)
        with self.assertRaises(OSError):os.fstat(writer)
        self.assertFalse(directory.exists());self.assertIsNone(process._swassh_guardian)

    async def test_windows_creation_failure_releases_staging_and_parent_identity(self):
        port=SimpleNamespace(**vars(os));port.name='nt';parent=Mock(token=4321);paths=[]
        async def create(*argv,**kwargs):
            path=Path(argv[-1]);paths.append(path.parent)
            self.assertEqual(json.loads(path.read_bytes())['parent_token'],4321)
            raise OSError('synthetic process creation failure')
        with patch.object(guard,'os',port),patch('swassh.infrastructure.windows.ParentProcess',return_value=parent),\
                patch.object(asyncio,'create_subprocess_exec',side_effect=create),\
                self.assertRaisesRegex(OSError,'synthetic process creation failure'):
            await guard.launch_native('synthetic',options=Options())
        parent.close.assert_called_once_with();self.assertEqual(len(paths),1);self.assertFalse(paths[0].exists())

    async def test_cancellation_waits_for_creation_then_terminates_only_a_live_windows_guardian(self):
        for alive in (False,True):
            port=SimpleNamespace(**vars(os));port.name='nt';parent=Mock(token=4321)
            process=Mock(returncode=None if alive else 7);process.wait=AsyncMock(return_value=0)
            entered,release=asyncio.Event(),asyncio.Event();paths=[]
            async def create(*argv,**kwargs):
                paths.append(Path(argv[-1]).parent);entered.set();await release.wait();return process
            with self.subTest(alive=alive),patch.object(guard,'os',port),\
                    patch('swassh.infrastructure.windows.ParentProcess',return_value=parent),\
                    patch.object(asyncio,'create_subprocess_exec',side_effect=create):
                task=asyncio.create_task(guard.launch_native('synthetic',options=Options()))
                try:
                    async with asyncio.timeout(3):
                        await entered.wait();task.cancel();await asyncio.sleep(0)
                        self.assertFalse(task.done());release.set()
                        with self.assertRaises(asyncio.CancelledError):await task
                finally:
                    release.set();await asyncio.gather(task,return_exceptions=True)
            self.assertEqual(process.terminate.call_count,int(alive));self.assertEqual(process.wait.await_count,int(alive))
            process.kill.assert_not_called();self.assertFalse(paths[0].exists());parent.close.assert_called_once()


class GuardianReleaseOwnershipTests(unittest.TestCase):
    def test_pipe_close_error_cleans_the_real_directory_without_reclosing_the_fd(self):
        folder = tempfile.TemporaryDirectory(prefix='swassh-guardian-release-')
        root = Path(folder.name)
        (root / 'request.json').write_text('synthetic request', encoding='utf-8')
        reader, writer = os.pipe()
        failure = InterruptedError('controlled close failure after descriptor release')
        actual_close = os.close
        closed = []
        port = SimpleNamespace(**vars(os))
        def closing(descriptor):
            self.assertEqual(descriptor, writer)
            actual_close(descriptor)
            closed.append(descriptor)
            raise failure
        port.close = closing
        process = SimpleNamespace(_swassh_guardian=(writer, folder))
        try:
            with patch.object(guard, 'os', port):
                with self.assertRaises(InterruptedError) as raised:
                    guard.release_guardian(process)
                self.assertIs(raised.exception, failure)
                self.assertIsNone(process._swassh_guardian)
                self.assertEqual(closed, [writer])
                with self.assertRaises(OSError):
                    os.fstat(writer)
                self.assertFalse(root.exists(), 'pipe close failure skipped owned directory cleanup')
                guard.release_guardian(process)
                self.assertEqual(closed, [writer], 'released descriptor was closed a second time')
        finally:
            if not closed:
                actual_close(writer)
            actual_close(reader)
            folder.cleanup()
