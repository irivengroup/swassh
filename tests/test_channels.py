"""Binary-channel resource boundaries and isolated native guardian integration."""
import asyncio
import io
import json
from dataclasses import replace
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from swassh import AsyncClient, Host, Options, LocalForward, SSHChannel, SSHTunnel, Status, Session, ChannelCapture
from swassh.infrastructure.channels import NativeChannel, NativeSSHScope
from swassh.infrastructure.process_guard import launch_native
from swassh.infrastructure.bastion import invocation_budget, SharedBudget, specification
from swassh.interfaces import cli
from swassh.infrastructure import channels as native_channels


class Writer:
    def __init__(self): self.data=bytearray(); self.closed=False
    def write(self,data): self.data.extend(data)
    async def drain(self): await asyncio.sleep(0)
    def close(self): self.closed=True


class MemoryScope:
    def __init__(self,**settings):
        self.options=Options(**settings)
        self.failure=None; self.closed=False
        self.settings=SimpleNamespace(auth_method='publickey')
        async def wait(): return 0
        self.process=SimpleNamespace(stdin=Writer(),stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),wait=wait)
    async def aclose(self): self.closed=True
    def _diagnostic(self): return 'Authenticated to synthetic-host\nExit status 0'


class ContractTests(unittest.TestCase):
    def test_native_scope_rejects_invalid_lifetimes_and_ambiguous_modes_before_transport(self):
        forward=LocalForward(8080,'internal',443)
        cases=[(value,{'command':'true'}) for value in (True,'1',None,float('nan'),float('inf'),0,-1)]
        cases.extend((value,{'forward':forward}) for value in (0.5,3601))
        cases.extend((1,settings) for settings in ({},{'command':'true','forward':forward}))
        for lifetime,settings in cases:
            with self.subTest(lifetime=lifetime,settings=settings),patch.object(native_channels,'SSHTransport') as construct,\
                    self.assertRaises(ValueError):NativeSSHScope(Host('one'),Options(),lifetime,**settings)
            construct.assert_not_called()

    def test_binary_capture_cannot_claim_success_with_invalid_types_or_exit_code(self):
        good=ChannelCapture(Status.SUCCESS,0,b'data',b'')
        self.assertTrue(good.ok)
        for fields in ({'status':'success'},{'exit_code':True},{'exit_code':None},
                       {'exit_code':7},{'stdout':'text'},{'stderr':bytearray()},{'error':object()}):
            with self.subTest(fields=fields),self.assertRaises(ValueError): replace(good,**fields)
        self.assertFalse(ChannelCapture(Status.INTERRUPTED,-9,b'',b'').ok)

    def test_loopback_only_forwarding_and_ipv6_escaping(self):
        self.assertEqual(LocalForward(8080,'internal',443).argument,'127.0.0.1:8080:internal:443')
        self.assertEqual(LocalForward(8080,'::1',443,'::1').argument,'[::1]:8080:[::1]:443')
        for fields in ({'bind_address':'0.0.0.0'},{'bind_address':'*'},{'local_port':0},
                       {'remote_port':True},{'remote_host':'-oProxyCommand=bad'}, {'remote_host':'fe80::1%eth0'}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):
                replace(LocalForward(8080,'internal',443),**fields)

    def test_invalid_modes_fail_before_any_connection(self):
        for settings in ({'retries':1},{'pty':True},{'stdin_file':'unused'},{'stream_output':True},
                         {'progress_interval':1},{'adaptive':True}):
            with self.assertRaises(ValueError): SSHChannel('one','command',Options(**settings))
        with self.assertRaises(ValueError): SSHChannel('one','')
        with self.assertRaises(TypeError): SSHTunnel('one',object())
        for method,arg in (('channel','command'),('tunnel',LocalForward(8080,'internal',443))):
            with self.assertRaises(ValueError): getattr(AsyncClient(['one','two']),method)(arg)
            with self.assertRaises(ValueError): getattr(AsyncClient('one',transport_factory=lambda opts:None),method)(arg)
            self.assertIsNotNone(getattr(AsyncClient('one'),method)(arg))

    def test_tunnel_cli_plan_has_no_state_or_connection_side_effect(self):
        output=io.StringIO()
        with patch('sys.stdout',output),patch('swassh.infrastructure.channels.launch_native') as launch:
            self.assertEqual(cli.main(['tunnel','-H','synthetic','--local-port','8080',
                '--remote-host','internal','--remote-port','443','--plan-only','--ssh-executable','absent']),0)
        launch.assert_not_called()
        plan=json.loads(output.getvalue())
        self.assertEqual(plan['bind_address'],'127.0.0.1')
        for extra in (['--lifetime','nan'],['--retries','1'],['--output','unused']):
            with patch('sys.stderr',io.StringIO()):
                self.assertEqual(cli.main(['tunnel','-H','synthetic','--local-port','8080',
                    '--remote-host','internal','--remote-port','443','--plan-only',*extra]),2)


class BinaryUnitTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(hasattr(asyncio, 'eager_task_factory'), 'stdlib eager task factory requires Python 3.12+')
    async def test_eager_readers_preserve_prefed_output_and_close_cleanly(self):
        scope=MemoryScope()
        scope.process.stdout.feed_data(b'eager-output'); scope.process.stdout.feed_eof()
        scope.process.stderr.feed_data(b'eager-error'); scope.process.stderr.feed_eof()
        loop=asyncio.get_running_loop()
        previous=loop.get_task_factory()
        loop.set_task_factory(asyncio.eager_task_factory)
        channel=None
        try:
            channel=NativeChannel(scope)
            self.assertEqual(await channel.read(),b'eager-output')
            capture=await channel.wait()
            self.assertTrue(capture.ok)
            self.assertEqual(capture.stdout,b'eager-output')
            self.assertEqual(capture.stderr,b'eager-error')
            self.assertTrue(all(task.done() and task.exception() is None for task in channel.pumps))
        finally:
            try:
                if channel is not None: await channel.aclose()
            finally: loop.set_task_factory(previous)

    async def test_binary_chunks_capture_and_eof_without_decoding(self):
        scope=MemoryScope(); channel=NativeChannel(scope)
        try:
            scope.process.stdout.feed_data(b'\x00\xffbinary')
            scope.process.stdout.feed_eof()
            scope.process.stderr.feed_data(b'error'); scope.process.stderr.feed_eof()
            self.assertEqual(await channel.read(),b'\x00\xffbinary')
            self.assertEqual(await channel.read(),b'')
            capture=await channel.wait()
            self.assertIs(await channel.wait(),capture)
            self.assertTrue(capture.ok)
            self.assertEqual(capture.stdout,b'\x00\xffbinary')
            self.assertEqual(capture.stderr,b'error')
            self.assertNotIn('binary',repr(capture))
        finally: await channel.aclose()
        with self.assertRaises(RuntimeError): await channel.read()

    async def test_wait_drains_bounded_queues_and_keeps_complete_capture(self):
        scope=MemoryScope(max_output_bytes=65536); channel=NativeChannel(scope)
        try:
            scope.process.stdout.feed_data(b'a'*65536); scope.process.stdout.feed_eof()
            scope.process.stderr.feed_data(b'b'*65536); scope.process.stderr.feed_eof()
            await asyncio.sleep(0)
            self.assertLessEqual(channel.queues['stdout'].qsize(),4)
            capture=await asyncio.wait_for(channel.wait(),3)
            self.assertEqual(capture.stdout,b'a'*65536)
            self.assertEqual(capture.stderr,b'b'*65536)
        finally: await channel.aclose()

    async def test_output_cap_closes_instead_of_silent_truncation(self):
        scope=MemoryScope(max_output_bytes=4); channel=NativeChannel(scope)
        try:
            scope.process.stdout.feed_data(b'12345'); scope.process.stdout.feed_eof(); scope.process.stderr.feed_eof()
            await asyncio.gather(*channel.pumps)
            self.assertTrue(scope.closed)
            self.assertLessEqual(len(channel.buffers['stdout']),4)
            with self.assertRaisesRegex(OSError,'budget'): await channel.read()
        finally: await channel.aclose()

    async def test_close_keeps_full_queue_readers_alive_until_scope_termination(self):
        drained = asyncio.Event()
        class Reader(asyncio.StreamReader):
            async def read(self, size):
                value = await super().read(size)
                if not value:
                    drained.set()
                return value
        scope = MemoryScope(max_output_bytes=65536)
        scope.process.stdout = Reader()
        scope.process.stdout.feed_data(b'x' * 49152)
        scope.process.stderr.feed_eof()
        async def close():
            # The peer keeps its pipe open until termination starts.
            scope.process.stdout.feed_eof()
            await drained.wait()
            scope.closed = True
        scope.aclose = close
        channel = NativeChannel(scope)
        await asyncio.sleep(0)
        self.assertEqual(channel.queues['stdout'].qsize(), 4)
        task = asyncio.create_task(channel.aclose())
        try:
            await asyncio.wait_for(asyncio.shield(task), 1)
        finally:
            # An unfixed implementation fails the bound, then this memory-only
            # port is released so the regression itself leaves no pending task.
            drained.set()
            await task
        self.assertTrue(scope.closed)
        self.assertTrue(all(pump.done() for pump in channel.pumps))
        self.assertLessEqual(len(channel.buffers['stdout']), 65536)

    async def test_overflow_drains_remaining_bytes_without_expanding_capture(self):
        drained = asyncio.Event()
        class Reader(asyncio.StreamReader):
            async def read(self, size):
                value = await super().read(size)
                if not value:
                    drained.set()
                return value
        scope = MemoryScope(max_output_bytes=4)
        scope.process.stdout = Reader()
        scope.process.stdout.feed_data(b'x' * 16384)
        scope.process.stderr.feed_eof()
        async def close():
            # The peer keeps its pipe open until termination starts.
            scope.process.stdout.feed_eof()
            await drained.wait()
            scope.closed = True
        scope.aclose = close
        channel = NativeChannel(scope)
        task = asyncio.gather(*channel.pumps)
        try:
            await asyncio.wait_for(asyncio.shield(task), 1)
            self.assertTrue(scope.closed)
            self.assertLessEqual(len(channel.buffers['stdout']), 4)
            with self.assertRaisesRegex(OSError, 'budget'):
                await channel.read()
        finally:
            drained.set()
            await task
            await channel.aclose()

    async def test_two_failed_readers_share_owned_close_and_repeated_close_is_idempotent(self):
        scope = MemoryScope()
        scope.aclose = AsyncMock(wraps=scope.aclose)
        scope.process.stdout.set_exception(OSError('synthetic'))
        scope.process.stderr.set_exception(OSError('synthetic'))
        channel = NativeChannel(scope)
        await asyncio.gather(*channel.pumps)
        scope.aclose.assert_awaited_once()
        await asyncio.gather(channel.aclose(), channel.aclose())
        self.assertEqual(scope.aclose.await_count, 2)
        self.assertTrue(channel._closing.done())
        self.assertTrue(all(pump.done() for pump in channel.pumps))

    async def test_close_error_remains_visible_and_all_pumps_are_joined(self):
        scope = MemoryScope()
        scope.aclose = AsyncMock(side_effect=OSError('synthetic close failure'))
        channel = NativeChannel(scope)
        with self.assertRaisesRegex(OSError, 'synthetic close failure'):
            await channel.aclose()
        self.assertTrue(all(pump.done() for pump in channel.pumps))

    async def test_input_limits_eof_and_stream_validation(self):
        scope=MemoryScope(max_stdin_bytes=3); channel=NativeChannel(scope)
        try:
            for data in ('text',b'x'*16385,b'1234'):
                with self.assertRaises(ValueError): await channel.send(data)
            await channel.send(b'abc')
            with self.assertRaises(ValueError): await channel.send(b'd')
            channel.close_input(); channel.close_input()
            self.assertTrue(scope.process.stdin.closed)
            with self.assertRaises(ValueError): await channel.send(b'')
            with self.assertRaises(ValueError): await channel.read('invalid')
            self.assertEqual(scope.process.stdin.data,b'abc')
        finally: await channel.aclose()

    async def test_reader_failure_is_explicit(self):
        scope=MemoryScope(); channel=NativeChannel(scope)
        try:
            scope.process.stdout.set_exception(OSError('synthetic-private-message'))
            scope.process.stderr.feed_eof()
            await asyncio.gather(*channel.pumps)
            with self.assertRaisesRegex(OSError,'^SSH channel read failed; remote state may be unknown$'):
                await channel.wait()
        finally: await channel.aclose()

    async def test_cancellation_during_normal_close_waits_then_propagates(self):
        scope=MemoryScope(); channel=NativeChannel(scope)
        entered=asyncio.Event(); release=asyncio.Event()
        async def close():
            entered.set(); await release.wait(); scope.closed=True
        scope.aclose=close
        task=asyncio.create_task(channel.aclose())
        await entered.wait()
        task.cancel(); await asyncio.sleep(0); task.cancel()
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(scope.closed)
        self.assertTrue(all(pump.done() for pump in channel.pumps))


class NativeScopePolicyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Temporary staging is real; native processes and credentials are ports."""
    def scope(self):
        options=Options();transport=SimpleNamespace(executable='synthetic-ssh',
            profiles=SimpleNamespace(for_host=lambda host:options),
            _pacer=SimpleNamespace(acquire=AsyncMock()),aclose=AsyncMock())
        with patch.object(native_channels,'SSHTransport',return_value=transport):
            return NativeSSHScope(Host('one'),options,5,forward=LocalForward(8080,'internal',443))

    async def test_forward_readiness_rejects_exited_native_or_prior_failure(self):
        for failure,code in ((None,0),('synthetic watcher failure',None)):
            scope=self.scope();process=SimpleNamespace(returncode=code)
            async def launch(*argv,**kwargs):
                scope.diagnostic.write_text('Authenticated to synthetic\nLocal forwarding listening on 127.0.0.1 port 8080\n')
                if scope.readiness is not None:
                    scope.readiness.path.write_text(scope.readiness.token)
                scope.failure=failure;return process
            with self.subTest(failure=failure,code=code),patch.object(native_channels,'launch_native',side_effect=launch) as create,\
                    patch.object(native_channels,'_cleanup_process',new_callable=AsyncMock) as cleanup,\
                    self.assertRaisesRegex(OSError,'exited before|setup failed'):
                await scope.open()
            create.assert_awaited_once();cleanup.assert_awaited_once_with(process,[])
            self.assertIsNone(scope.active_at);self.assertIsNone(scope.directory)
            scope.transport.aclose.assert_awaited_once()

    async def test_authenticated_tunnel_waits_for_listening_and_never_reopens(self):
        scope=self.scope();process=SimpleNamespace(returncode=None);polls=[];stages=[]
        async def launch(*argv,**kwargs):
            stages.append(Path(scope.directory.name))
            scope.diagnostic.write_text('Authenticated to synthetic\n');return process
        async def watch():await asyncio.Future()
        original_sleep=asyncio.sleep
        async def sleep(delay):
            polls.append(delay)
            scope.diagnostic.write_text('Authenticated to synthetic\nLocal forwarding listening on 127.0.0.1 port 8080\n')
            if scope.readiness is not None:
                scope.readiness.path.write_text(scope.readiness.token)
            await original_sleep(0)
        port=SimpleNamespace(**vars(asyncio));port.sleep=sleep
        with patch.object(native_channels,'asyncio',port),patch.object(scope,'_watch',side_effect=watch),\
                patch.object(native_channels,'launch_native',side_effect=launch),\
                patch.object(native_channels,'_cleanup_process',new_callable=AsyncMock) as cleanup:
            self.assertIs(await scope.open(),scope);self.assertEqual(polls,[0.025])
            self.assertIsNotNone(scope.active_at)
            with self.assertRaisesRegex(RuntimeError,'cannot be reopened'):await scope.open()
            await scope.aclose()
            with self.assertRaisesRegex(RuntimeError,'cannot be reopened'):await scope.open()
        cleanup.assert_awaited_once_with(process,[]);self.assertFalse(stages[0].exists())

    async def test_native_relay_wire_policy_keeps_scope_lifetimes_and_fallback_routes(self):
        """Inspect actual guardian requests at the process boundary, not a relay mock."""
        import os
        from swassh.infrastructure import process_guard
        cases=(('posix',None,'publickey',None,True),
               ('posix',None,'publickey','/trusted/native-connector',True),
               ('nt',None,'publickey',None,False),
               ('posix',Host('bastion'),'publickey',None,False),
               ('posix',None,'gssapi',None,False))
        for platform,jump,auth,connector,embedded in cases:
            for forward in (False,True):
                with self.subTest(platform=platform,jump=jump,auth=auth,connector=connector,forward=forward):
                    options=Options(connect_timeout=2,report_timeout=3,command_timeout=5,jump_host=jump,auth_method=auth)
                    transport=SimpleNamespace(executable='synthetic-ssh',relay_connector=connector,
                        profiles=SimpleNamespace(for_host=lambda host:options),
                        _pacer=SimpleNamespace(acquire=AsyncMock()),aclose=AsyncMock())
                    with patch.object(native_channels,'SSHTransport',return_value=transport):
                        scope=NativeSSHScope(Host('target.example',2222),options,5,
                            **({'forward':LocalForward(8080,'internal',443)} if forward else {'command':'true'}))
                    requests=[];process=SimpleNamespace(returncode=None)
                    async def create(*argv,**kwargs):
                        requests.append(json.loads(Path(argv[-1]).read_bytes()))
                        scope.diagnostic.write_text('Authenticated to synthetic\nLocal forwarding listening on 127.0.0.1 port 8080\n')
                        if scope.readiness is not None:scope.readiness.path.write_text(scope.readiness.token)
                        return process
                    async def cleanup(process,tasks):
                        if process is not None:process_guard.release_guardian(process)
                    with patch.object(native_channels,'os',SimpleNamespace(name=platform)), \
                            patch.object(asyncio,'create_subprocess_exec',side_effect=create), \
                            patch.object(native_channels,'_cleanup_process',side_effect=cleanup):
                        try:
                            self.assertIs(await scope.open(),scope)
                            self.assertEqual(len(requests),1)
                            request=requests[0]
                            self.assertEqual(request['connections'],2 if jump else 1)
                            self.assertEqual(request['max_native_seconds'],10 if forward else 5)
                            self.assertEqual(request['admission_wait_limit'],10 if forward else 5)
                            expected=({'host':'target.example','port':2222,'connect_timeout':2,'connector':connector} if embedded else None)
                            self.assertEqual(request['relay'],expected)
                            self.assertIn('swassh-target',request['argv'])
                        finally:await scope.aclose()
                    self.assertIsNone(process._swassh_guardian)
                    transport.aclose.assert_awaited_once()

    async def test_unopened_scope_close_survives_cancellation_before_returning_it(self):
        scope=self.scope();entered,release=asyncio.Event(),asyncio.Event()
        async def close():entered.set();await release.wait()
        scope.transport.aclose=AsyncMock(side_effect=close)
        task=asyncio.create_task(scope.aclose())
        try:
            async with asyncio.timeout(3):
                await entered.wait();task.cancel();await asyncio.sleep(0)
                self.assertFalse(task.done());release.set()
                with self.assertRaises(asyncio.CancelledError):await task
        finally:
            release.set();await asyncio.gather(task,return_exceptions=True)
        self.assertIsNone(scope.directory);scope.transport.aclose.assert_awaited_once()


class NativeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Real guardian and synthetic byte peer, not a claim of SSH interoperability."""
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.options=Options(command_timeout=5,connect_timeout=2,report_timeout=2,
            budget_dir=str(self.root/'budget'),log_file=str(self.root/'audit.jsonl'))
        self.arguments=[]; self.configs=[]
        async def synthetic(executable,*arguments,**kwargs):
            self.arguments.append(arguments)
            self.configs.append(Path(arguments[arguments.index('-F')+1]).read_text())
            # This adapter is a byte peer, not OpenSSH; it opens no target.
            # Keep the real guardian/lifetime while clearing SSH-only relay metadata.
            from swassh.infrastructure.process_guard import native_relay
            with native_relay(None,kwargs.get('max_native_seconds')):
                return await launch_native(sys.executable,str(Path(__file__).with_name('channel_peer.py')),*arguments,**kwargs)
        self.seam=patch('swassh.infrastructure.channels.launch_native',side_effect=synthetic)
        self.seam.start(); self.addCleanup(self.seam.stop)

    async def test_byte_schema_is_ready_before_native_scope_start(self):
        """Inspect real accounting before the transport boundary can open a target."""
        from swassh.interfaces import channels as channel_api
        path=Path(specification(self.options)['directory'])/'encrypted-bytes.sqlite'
        self.assertFalse(path.exists())
        checked,closed=[],[]
        test=self
        class BeforeTarget:
            failure=None
            async def open(inner):
                test.assertTrue(path.is_file())
                test.assertGreater(path.stat().st_size,0)
                checked.append(True)
                raise OSError('synthetic stop before target connection')
            async def aclose(inner):
                closed.append(True)
        manager=SSHChannel('synthetic','echo',self.options)
        with patch.object(channel_api,'NativeSSHScope',return_value=BeforeTarget()), \
                self.assertRaisesRegex(OSError,'stop before target connection'):
            await manager.__aenter__()
        self.assertEqual(checked,[True])
        self.assertEqual(closed,[True])
        self.assertIsNone(manager.token)


    async def test_binary_roundtrip_guardian_cleanup_and_scope_revocation(self):
        scope=SSHChannel('synthetic','echo',self.options)
        async with scope as channel:
            process=channel.native.process
            await channel.send(b'\x00\xffprivate-byte-input')
            channel.close_input()
            capture=await channel.wait()
            self.assertEqual(capture.stdout,b'\x00\xffprivate-byte-input')
            self.assertEqual(capture.stderr,b'synthetic-stderr')
            self.assertEqual(capture.status,Status.SUCCESS)
            with self.assertRaises(RuntimeError):
                async with SSHChannel('synthetic','echo',self.options): self.fail('nested scope admitted')
            with self.assertRaises(RuntimeError):
                async with Session('synthetic',self.options): self.fail('nested session admitted')
        self.assertIsNotNone(process.returncode)
        self.assertIsNone(process._swassh_guardian)
        self.assertIsNone(scope.native.directory)
        with self.assertRaises(RuntimeError): await scope.send(b'after')
        with self.assertRaises(RuntimeError): await scope.__aenter__()
        self.assertIn('StrictHostKeyChecking yes',self.configs[0])
        audit=(self.root/'audit.jsonl').read_text()
        self.assertNotIn('private-byte-input',audit)
        self.assertIn('ssh_scope_closed',audit)

    async def test_loopback_tunnel_flags_lifetime_and_cleanup(self):
        scope=SSHTunnel('synthetic',LocalForward(8080,'internal',443),self.options,lifetime=1)
        async with scope as tunnel:
            process=tunnel.native.process
            self.assertTrue(tunnel.is_open)
            with self.assertRaises(OSError): await asyncio.wait_for(tunnel.wait(),4)
            self.assertFalse(tunnel.is_open)
        self.assertIsNotNone(process.returncode)
        args=self.arguments[0]
        for directive in ('ClearAllForwardings=no','ExitOnForwardFailure=yes','GatewayPorts=no'):
            self.assertIn(directive,args)
        self.assertEqual(args[args.index('-L')+1],'127.0.0.1:8080:internal:443')
        self.assertFalse(scope.is_open)

    async def test_cancellation_reaps_process_and_releases_admission(self):
        started=asyncio.Event(); owner=[]
        async def use():
            async with SSHChannel('synthetic','hang',self.options) as channel:
                owner.append(channel.native.process); started.set()
                await asyncio.Future()
        task=asyncio.create_task(use())
        await asyncio.wait_for(started.wait(),5)
        task.cancel(); await asyncio.sleep(0); task.cancel()
        with self.assertRaises(asyncio.CancelledError): await asyncio.wait_for(task,5)
        self.assertIsNotNone(owner[0].returncode)
        self.assertIsNone(owner[0]._swassh_guardian)
        async with SSHChannel('synthetic','echo',self.options) as channel:
            channel.close_input(); self.assertTrue((await channel.wait()).ok)

    async def test_denied_authentication_and_output_overflow_fail_closed(self):
        scope=SSHChannel('synthetic','deny',self.options)
        with self.assertRaises(OSError): await scope.__aenter__()
        self.assertIsNone(scope.native.directory)
        async with SSHChannel('synthetic','flood',replace(self.options,max_output_bytes=16)) as channel:
            with self.assertRaisesRegex(OSError,'budget'): await channel.wait()

    async def test_diagnostic_flood_stops_hanging_channel(self):
        async with SSHChannel('synthetic','diagnostic-flood',self.options) as channel:
            await channel.send(b'diagnostic-flood\n')
            with self.assertRaises(OSError): await asyncio.wait_for(channel.read(),4)
            self.assertIsNotNone(channel.native.process.returncode)

    async def test_initialization_failure_removes_private_temporary_directory(self):
        native=NativeSSHScope(Host('synthetic'),self.options,5,command='echo')
        with patch('swassh.infrastructure.channels._config',side_effect=ValueError('synthetic config error')):
            with self.assertRaises(ValueError): await native.open()
        self.assertIsNone(native.directory)
        self.assertEqual(self.arguments,[])

    async def test_early_exit_reaps_a_peer_blocked_on_full_output(self):
        def probe():
            try:
                return subprocess.run([sys.executable,str(Path(__file__).with_name('channel_exit_probe.py')),str(self.root)],
                    capture_output=True,timeout=8,check=False)
            except subprocess.TimeoutExpired:
                self.fail('closing a channel with unread output exceeded its cleanup deadline')
        process=await asyncio.to_thread(probe)
        self.assertEqual(process.returncode,0,process.stderr.decode('utf-8','replace'))

    async def test_channel_owns_capacity_when_called_from_another_invocation(self):
        async with invocation_budget(self.options):
            async with SSHChannel('synthetic','echo',self.options) as channel:
                pool=SharedBudget(specification(self.options))
                try:
                    self.assertEqual(pool.db.execute("SELECT count(*) FROM leases WHERE kind='memory' AND active=1").fetchone()[0],2)
                finally: pool.close()
                channel.close_input(); await channel.wait()


    async def test_delayed_ready_observation_keeps_diagnostic_flood_after_entry(self):
        """A producer fault follows confirmed entry, not an arbitrary short sleep."""
        from swassh.infrastructure.ssh import _DiagnosticRead
        original = _DiagnosticRead.read
        delays = []
        async def delayed(reader):
            value = await original(reader)
            authenticated = value is True or isinstance(value, str) and 'authenticated to ' in value.lower()
            if authenticated and not delays:
                delays.append(True)
                await asyncio.sleep(0.25)
            return value
        with patch.object(_DiagnosticRead, 'read', delayed):
            await self.test_diagnostic_flood_stops_hanging_channel()
        self.assertEqual(len(delays), 1)




class CoreBenchmarkBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_synthetic_channel_benchmark_keeps_the_real_guardian_without_ssh_relay_metadata(self):
        """A Python peer must not receive OpenSSH options under the POSIX policy."""
        import importlib.util
        spec=importlib.util.spec_from_file_location('swassh_core_benchmark',
            Path(__file__).resolve().parents[1]/'benchmarks/core.py')
        self.assertIsNotNone(spec)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        create=asyncio.create_subprocess_exec
        requests=[]
        async def observed(*argv,**kwargs):
            if argv[1:3]==('-m','swassh.infrastructure.process_guard'):
                request=json.loads(Path(argv[3]).read_bytes())
                self.assertIsNone(request['relay'])
                self.assertEqual(request['max_native_seconds'],10)
                self.assertEqual(request['connections'],1)
                self.assertEqual(request['argv'][0],sys.executable)
                self.assertEqual(Path(request['argv'][1]).name,'channel_peer.py')
                requests.append(request)
            return await create(*argv,**kwargs)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(native_channels,'os',SimpleNamespace(name='posix')), \
                patch.object(asyncio,'create_subprocess_exec',side_effect=observed):
            result=await module.CoreBenchmarks(directory,1,1).channels()
        self.assertEqual(len(requests),1)
        self.assertEqual(result['completed'],1)
        self.assertEqual(result['errors'],0)
        self.assertEqual(result['payload_bytes_per_scope'],4096)
        self.assertFalse(result['ssh_crypto_measured'])

if __name__=='__main__': unittest.main()
