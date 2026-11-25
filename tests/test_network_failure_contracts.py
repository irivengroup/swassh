"""Device trust/diagnostic failures never authorize another command or replay."""
import asyncio
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock, patch

from swassh import Host,NetworkProcedure,NetworkStep,Options,Status
from swassh.infrastructure import network


class DriverIdentityTests(unittest.TestCase):
    def test_huawei_requires_initial_user_view_and_rejects_a_foreign_identity(self):
        driver=network.DeviceDriver('huawei_vrp')
        self.assertFalse(driver.prompt('[router]'));self.assertIsNone(driver.identity)
        self.assertTrue(driver.prompt('<router>'));self.assertTrue(driver.prompt('[router-interface]'))
        self.assertFalse(driver.prompt('<foreign>'));self.assertFalse(driver.prompt('[routerevil]'))
        self.assertFalse(driver.prompt('[foreign]'))


class DeviceConnectionFailureTests(unittest.IsolatedAsyncioTestCase):
    def service(self,options=None):
        plan=NetworkProcedure('cisco_ios','administration',(NetworkStep('identify','show',('version',)),))
        with patch.object(network.LocalPreflight,'transport',return_value='synthetic-ssh'),\
                patch('swassh.infrastructure.relay_connect.NativeConnector.find',return_value=None):
            return network.NetworkTransport(options or Options(),plan)

    async def cleanup(self,process,tasks):
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)

    async def test_exhausted_preparation_deadline_does_not_launch_a_connection(self):
        service=self.service(Options(command_timeout=0.001))
        def configuration(*args):time.sleep(0.02);return 'synthetic configuration'
        with patch.object(network,'_config',side_effect=configuration),patch.object(network,'launch_native',new_callable=AsyncMock) as launch,\
                patch.object(network,'_cleanup_process',side_effect=self.cleanup):
            result=await service.execute(Host('one'),'show')
        self.assertEqual(result.status,Status.TIMEOUT);launch.assert_not_awaited()

    async def test_diagnostic_budget_failure_cancels_dialogue_without_sending_commands(self):
        service=self.service();sent=[]
        class Dialogue:
            def __init__(self,*args):pass
            async def receive(self):await asyncio.Future()
            async def execute(self,step):sent.append(step.command);return 'version'
        async def launch(*args,**kwargs):
            Path(args[args.index('-E')+1]).write_bytes(b'x'*(network.DIAGNOSTIC_LIMIT+1))
            return SimpleNamespace(returncode=None)
        with patch.object(network,'launch_native',side_effect=launch) as start,patch.object(network,'DeviceDialogue',Dialogue),\
                patch.object(network,'_cleanup_process',side_effect=self.cleanup):result=await service.execute(Host('one'),'show')
        self.assertEqual(result.status,Status.ERROR);self.assertIn('diagnostic budget',result.error)
        self.assertEqual(sent,[]);self.assertEqual(start.await_count,1)

    async def test_precommand_disconnects_keep_trust_authentication_and_transport_outcomes_distinct(self):
        for code,diagnostic,expected in ((0,'',Status.ERROR),(None,'Permission denied',Status.AUTH_FAILED),
                (255,'Host key verification failed',Status.HOST_KEY_FAILED),(255,'Connection refused',Status.UNREACHABLE)):
            service=self.service();sent=[]
            class Dialogue:
                def __init__(self,*args):pass
                async def receive(self):raise network.DeviceDisconnected('no device prompt')
                async def execute(self,step):sent.append(step.command);return 'version'
            async def launch(*args,**kwargs):
                Path(args[args.index('-E')+1]).write_text(diagnostic,encoding='utf-8')
                return SimpleNamespace(returncode=code)
            with patch.object(network,'launch_native',side_effect=launch) as start,patch.object(network,'DeviceDialogue',Dialogue),\
                    patch.object(network,'_cleanup_process',side_effect=self.cleanup):result=await service.execute(Host('one'),'show')
            self.assertEqual(result.status,expected);self.assertEqual(start.await_count,1);self.assertEqual(sent,[])
            self.assertTrue(result.error.startswith('connect:'))

    async def test_arbitrary_io_messages_are_sanitized_and_controlled_dialogue_evidence_is_retained(self):
        for failure in (OSError('synthetic-private-path'),UnicodeError('synthetic-private-bytes'),
                network.NetworkDialogueError('controlled failure','synthetic device evidence')):
            service=self.service()
            class Dialogue:
                def __init__(self,process,driver,*args):self.driver=driver
                async def receive(self):self.driver.identity='router';return ''
                async def execute(self,step):raise failure
            with patch.object(network,'launch_native',new_callable=AsyncMock,return_value=SimpleNamespace(returncode=None)),\
                    patch.object(network,'DeviceDialogue',Dialogue),patch.object(network,'_cleanup_process',side_effect=self.cleanup):
                result=await service.execute(Host('one'),'show')
            self.assertEqual(result.status,Status.ERROR);self.assertNotIn('synthetic-private',result.error)
            self.assertEqual('synthetic device evidence' in result.stdout,isinstance(failure,network.NetworkDialogueError))


if __name__=='__main__':unittest.main()
