"""Native control ports: live callbacks, launch cancellation and CLI scopes."""
import asyncio
import contextlib
import io
import os
import runpy
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import Host,Options,Status
from swassh.infrastructure import process_guard,ssh
from swassh.interfaces import cli


class MemoryInput:
    def __init__(self):self.data=bytearray();self.closed=False
    def write(self,data):self.data.extend(data)
    async def drain(self):await asyncio.sleep(0)
    def close(self):self.closed=True


class NativeCallbackBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_transport_serializes_start_then_both_streams_and_revokes_input(self):
        for failure in (None,'callback','overflow'):
            events=[];inputs=[];live=[]
            process=SimpleNamespace(stdin=MemoryInput(),stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=None)
            process.stdout.feed_data(b'prompt?\n');process.stdout.feed_eof()
            process.stderr.feed_data(b'notice\n');process.stderr.feed_eof()
            async def wait():await asyncio.sleep(0);process.returncode=0;return 0
            process.wait=wait
            async def handler(event,channel):
                events.append(event);inputs.append(channel)
                if event.stream=='start':await channel.send(b'answer\n')
                if failure=='callback' and event.stream=='stdout':raise RuntimeError('synthetic-private-callback-text')
                if event.stream=='stdout' and event.eof:channel.close()
            class Live:
                dropped=0
                async def start(self):live.append('start')
                async def emit(self,host,stream,text,**flags):live.append((host,stream,text,flags))
                async def close(self):live.append('close')
            async def cleanup(native,tasks):
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                native.returncode=0
                self.assertTrue(all(task.done() for task in tasks))
                return {'admission_wait_seconds':0.25,'native_seconds':0.5}
            with patch.object(ssh.LocalPreflight,'transport',return_value='synthetic-client'),patch.object(ssh,'LiveOutput',Live),patch.object(ssh,'launch_native',new_callable=AsyncMock,return_value=process) as launch,patch.object(ssh,'_cleanup_process',side_effect=cleanup):
                # LiveOutput's constructor receives Options; the recording port
                # retains the same constructor contract without terminal I/O.
                with patch.object(Live,'__init__',lambda self,options:None,create=True):
                    transport=ssh.SSHTransport(Options(stream_output=True,max_output_bytes=4 if failure=='overflow' else 1024),interaction_factory=lambda host:handler)
                result=await transport.execute(Host('one'),'opaque')
                await transport.aclose()
            self.assertEqual(launch.await_count,1)
            self.assertEqual(events[0].stream,'start')
            self.assertEqual(process.stdin.data,b'answer\n')
            self.assertTrue(process.stdin.closed or failure is not None)
            self.assertEqual(result.status,Status.SUCCESS if failure is None else Status.ERROR)
            self.assertEqual(transport.metrics()['shared_admission_wait_seconds'],0.25)
            self.assertEqual(transport.metrics()['native_client_seconds'],0.5)
            self.assertNotIn('synthetic-private-callback-text',str(result))
            with self.assertRaises(ValueError):await inputs[0].send(b'after-scope')
            if failure is None:
                self.assertEqual((result.stdout,result.stderr),('prompt?\n','notice\n'))
                self.assertEqual({event.stream for event in events},{'start','stdout','stderr'})
                self.assertTrue(any(isinstance(value,tuple) and value[1]=='stderr' for value in live))

    async def test_cancelled_native_launch_waits_for_creation_then_stops_before_request_cleanup(self):
        for expired in (False,True):
            created,release=asyncio.Event(),asyncio.Event();events=[]
            fake_os=SimpleNamespace(**vars(os));fake_os.name='posix';fake_os.pipe=lambda:(31,32)
            fake_os.close=Mock(side_effect=lambda fd:events.append(('close-pipe',fd)))
            fake_os.killpg=Mock(side_effect=ProcessLookupError() if not expired else None)
            native=SimpleNamespace(pid=123,returncode=None,kill=Mock(),terminate=Mock())
            async def wait():
                if expired and not native.kill.called:await asyncio.Future()
                native.returncode=0;events.append('native-stopped');return 0
            native.wait=wait
            async def create(*args,**kwargs):
                self.assertEqual(kwargs['pass_fds'],(31,))
                created.set();await release.wait();return native
            real_timeout=asyncio.timeout;delays=[]
            def timeout(delay):delays.append(delay);return real_timeout(0.01)
            with patch.object(process_guard,'os',fake_os),patch.object(asyncio,'create_subprocess_exec',side_effect=create),patch.object(asyncio,'timeout',side_effect=timeout):
                task=asyncio.create_task(process_guard.launch_native('synthetic-client',options=Options()))
                await asyncio.wait_for(created.wait(),2)
                task.cancel();await asyncio.sleep(0)
                self.assertFalse(task.done());release.set()
                with self.assertRaises(asyncio.CancelledError):await task
            self.assertEqual(delays,[2]);self.assertEqual(native.kill.call_count,int(expired))
            self.assertEqual(events[-2:],[('close-pipe',31),('close-pipe',32)])
            self.assertLess(events.index('native-stopped'),len(events)-2)


class InteractiveCLIContractTests(unittest.TestCase):
    def test_shell_cli_returns_native_failure_or_controlled_timeout_and_closes_budget(self):
        for outcome in (0,7,TimeoutError('synthetic-private')):
            shell=Mock();shell.run=AsyncMock(side_effect=outcome if isinstance(outcome,Exception) else None,return_value=outcome)
            closed=[]
            @contextlib.contextmanager
            def budget(options):
                try:yield
                finally:closed.append(True)
            with patch.object(cli.LocalPreflight,'require_credentials'),patch.object(cli,'cli_invocation_budget',budget),patch('swassh.infrastructure.terminal.InteractiveShell',return_value=shell),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()) as error:
                code=cli.main(['shell','-H','one'])
            self.assertEqual(code,0 if outcome==0 else 1)
            shell.run.assert_awaited_once();self.assertEqual(closed,[True])
            self.assertNotIn('synthetic-private',error.getvalue())
            if isinstance(outcome,TimeoutError):self.assertIn('deadline exceeded',error.getvalue())


class GuardianEntryContractTests(unittest.TestCase):
    def test_expected_guardian_failures_never_dump_exception_text_or_request_path(self):
        for fault in (OSError('synthetic-private-error'),ValueError('synthetic-private-error'),
                      sqlite3.OperationalError('synthetic-private-error'),RuntimeError('synthetic-private-error')):
            with self.subTest(kind=type(fault).__name__),patch.dict(sys.modules),patch.object(sys,'argv',['guardian','synthetic-private-request']),patch('builtins.open',side_effect=fault),contextlib.redirect_stderr(io.StringIO()) as error:
                # Run the real program footer without its import-cache warning;
                # the mocked first read prevents any process/job/OS action.
                sys.modules.pop('swassh.infrastructure.process_guard',None)
                with self.assertRaises(SystemExit) as stopped:
                    runpy.run_module('swassh.infrastructure.process_guard',run_name='__main__')
                self.assertEqual(stopped.exception.code,125)
                self.assertEqual(error.getvalue(),'swassh: native guardian admission or process error\n')
