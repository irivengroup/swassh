"""Adapter contracts that remain executable without changing the host setup."""
import asyncio
from concurrent.futures import Executor,Future
import os
from pathlib import Path
import shlex
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from swassh import DesiredState,Host,Options,Result,Status
from swassh.infrastructure import installation
from swassh.infrastructure.convergence import SQLiteConvergenceJournal
from swassh.infrastructure.process_reporter import ProcessReportWriter
from swassh.infrastructure.report import TerminalColor
from swassh.infrastructure.socket_relay import GuardianRelay
from swassh.infrastructure.transfers import NativeFileTransport
from swassh.interfaces.client import ResultStream


class ProfileFileIntegrationTests(unittest.TestCase):
    def test_profile_selection_preserves_content_backs_up_and_is_idempotent_on_both_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);scripts=home/"quoted ' dollar$ directory"
            for shell in ('sh','dash','ksh','ksh93','bash','zsh'):
                for path in home.glob('.*'):
                    if path.is_file():path.unlink()
                profile=home/('.bash_login' if shell=='bash' else '.zprofile' if shell=='zsh' else '.profile')
                original=b'# synthetic profile\r\nexport SYNTHETIC=1\r\n';profile.write_bytes(original)
                profile.chmod(0o600)
                with patch.dict(os.environ,{},clear=True):
                    configurator=installation.PathConfigurator(scripts,home,shell)
                    expected=([home/'.bash_login',home/'.bashrc'] if shell=='bash' else
                              [home/'.zprofile',home/'.zshrc'] if shell=='zsh' else [home/'.profile'])
                    self.assertEqual(configurator.profiles(),expected)
                    backups=configurator.configure()
                    self.assertEqual(len(backups),1)
                    self.assertEqual(backups[0].read_bytes(),original)
                    self.assertTrue(profile.read_bytes().startswith(original))
                    self.assertEqual(configurator.configure(),[])
                    self.assertIn(shlex.quote(str(scripts.absolute())),configurator.command())
                    self.assertIn('${PATH:+${PATH}:}',configurator.command())
            with patch.dict(os.environ,{'ZDOTDIR':'synthetic-location'}),self.assertRaises(ValueError):
                installation.PathConfigurator(scripts,home,'zsh').profiles()
            with self.assertRaises(ValueError):installation.PathConfigurator(scripts,home,'unknown').profiles()
            with self.assertRaises(ValueError):installation.PathConfigurator(str(scripts)+'\n',home,'sh')
            fake_os=SimpleNamespace(name='posix')
            with patch.object(installation,'os',fake_os),self.assertRaisesRegex(ValueError,'colon'):
                installation.PathConfigurator(str(scripts)+':bad',home,'sh')

    def test_incomplete_profile_marker_refuses_publication_and_keeps_original(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);configurator=installation.PathConfigurator(home/'bin',home,'sh')
            profile=home/'.profile';original='# SWASSH PATH '+str(configurator.scripts)+'\n'
            profile.write_text(original,encoding='utf-8');profile.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'incomplete or modified'):configurator.configure()
            self.assertEqual(profile.read_text(encoding='utf-8'),original)
            self.assertEqual(list(home.glob('*.swassh-backup-*')),[])


class PureAdapterContractTests(unittest.TestCase):
    def test_terminal_stream_without_tty_capability_is_plain_and_metrics_add_both_owners(self):
        color=TerminalColor(object())
        self.assertFalse(color.enabled);self.assertEqual(color.heading('[FAILED] synthetic'),'[FAILED] synthetic')
        transfer=object.__new__(NativeFileTransport)
        transfer.ssh=SimpleNamespace(metrics=lambda:{'shared_admission_wait_seconds':2.,'native_client_seconds':3.})
        transfer._admission_wait_seconds=0.25;transfer._native_seconds=0.5
        self.assertEqual(transfer.metrics(),{'shared_admission_wait_seconds':2.25,'native_client_seconds':3.5})

    def test_relay_arguments_preserve_original_target_config_and_escape_openssh_percent(self):
        relay=object.__new__(GuardianRelay);relay.port=12345;relay.timeout=1.25
        original=['ssh','-F','synthetic config','-p','2222','original-target']
        for connector in (None,'/trusted/with % and spaces/nc'):
            relay.connector=connector
            result=relay.arguments(original)
            self.assertEqual(result[0],'ssh');self.assertEqual(result[5:],original[1:])
            self.assertEqual(result[3:5],['-o','ProxyUseFdpass=yes'])
            command=result[2].removeprefix('ProxyCommand=')
            decoded=shlex.split(command.replace('%%','%'))
            if connector:
                self.assertEqual(decoded,[connector,'-F','-I','16384','-O','16384','-w','2','127.0.0.1','12345'])
                self.assertIn('%%',command)
            else:self.assertEqual(decoded[-3:],['-m','swassh.infrastructure.relay_connect','12345'])
        self.assertEqual(original,['ssh','-F','synthetic config','-p','2222','original-target'])


class AsyncAdapterContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_blocked_durable_lease_survives_reopen_until_read_only_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            options=Options(budget_dir=directory);action=DesiredState('state','check','apply');host=Host('one')
            for operation,pending in (('blocked',False),('verified',True),('verified',False)):
                journal=SQLiteConvergenceJournal(options)
                try:
                    async with journal.scope(host,action) as lease:
                        self.assertIs(lease.pending,pending)
                        if operation=='blocked':await lease.applying();await lease.blocked()
                        else:await lease.verified()
                finally:await journal.aclose()

    async def test_result_stream_async_for_observes_completion_and_closes_the_producer(self):
        class Service:
            async def iter_results(self,hosts,command):
                self.hosts,self.command=hosts,command
                yield Result(hosts[0],Status.SUCCESS,stdout='synthetic',exit_code=0)
        service=Service();hosts=(Host('one'),);scope=ResultStream(service,hosts,'read',True)
        async with scope as stream:
            self.assertIs(aiter(stream),stream)
            results=[value async for value in stream]
        self.assertEqual([value.stdout for value in results],['synthetic'])
        self.assertEqual((service.hosts,service.command),(hosts,'read'))
        self.assertTrue(scope._producer.done());self.assertTrue(scope._closed)

    async def test_reporter_late_exception_and_cancellation_are_observed_after_forced_shutdown(self):
        class HoldingExecutor(Executor):
            def submit(self,function,*args,**kwargs):self.future=Future();return self.future
        real_timeout=asyncio.timeout
        for cancelled in (False,True):
            writer=ProcessReportWriter('.',1024,operation_timeout=0.02)
            executor=HoldingExecutor();writer._executor=executor;writer._cancelled=threading.Event()
            writer._shutdown=AsyncMock();deadlines=[];unhandled=[]
            loop=asyncio.get_running_loop();previous=loop.get_exception_handler()
            loop.set_exception_handler(lambda loop,context:unhandled.append(context))
            def timeout(seconds):deadlines.append(seconds);return real_timeout(0.01)
            try:
                with patch('swassh.infrastructure.process_reporter.asyncio.timeout',side_effect=timeout):
                    with self.assertRaises(TimeoutError):await writer._call('summary')
                self.assertEqual(deadlines,[0.02,2]);self.assertTrue(writer._cancelled.is_set())
                writer._shutdown.assert_awaited_once_with(force=True)
                if cancelled:executor.future.cancel()
                else:executor.future.set_exception(RuntimeError('synthetic late worker fault'))
                await asyncio.sleep(0);await asyncio.sleep(0)
                self.assertEqual(unhandled,[])
            finally:loop.set_exception_handler(previous)
