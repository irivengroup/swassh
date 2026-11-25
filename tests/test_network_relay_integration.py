"""Device dialogue shares the verified guardian relay on supported direct SSH."""
import asyncio
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from swassh import Host,NetworkProcedure,NetworkStep,Options,Status
from swassh.infrastructure import network,process_guard,relay_connect


class DeviceRelayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_posix_device_connection_uses_guardian_owned_endpoint_and_deadline(self):
        procedure=NetworkProcedure('cisco_ios','administration',(NetworkStep('identify','show',('version',)),))
        for platform,options in (('posix',Options(command_timeout=3)),
                ('posix',Options(jump_host=Host('jump'),command_timeout=3)),
                ('posix',Options(auth_method='gssapi',command_timeout=3)),('nt',Options(command_timeout=3))):
            scoped=[]
            async def launch(*args,**kwargs):
                scoped.append((process_guard._RELAY.get(),kwargs))
                return SimpleNamespace(returncode=None)
            class Dialogue:
                def __init__(self,process,driver,*args):self.driver=driver
                async def receive(self):self.driver.identity='router';return ''
                async def execute(self,step):return 'version'
            async def cleanup(process,tasks):
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
            port=SimpleNamespace(**vars(os));port.name=platform
            with patch.object(network.LocalPreflight,'transport',return_value='synthetic-ssh'),\
                    patch.object(network,'os',port,create=True),patch.object(relay_connect.NativeConnector,'find',return_value='/trusted/nc') as find,\
                    patch.object(network,'launch_native',side_effect=launch),patch.object(network,'DeviceDialogue',Dialogue),\
                    patch.object(network,'_cleanup_process',side_effect=cleanup):
                transport=network.NetworkTransport(options,procedure)
                result=await transport.execute(Host('one'),procedure.steps[0].command)
            self.assertEqual(result.status,Status.SUCCESS);self.assertEqual(len(scoped),1)
            optimized=platform=='posix' and options.jump_host is None and options.auth_method!='gssapi'
            self.assertEqual(find.call_count,int(optimized))
            relay,kwargs=scoped[0]
            if optimized:
                self.assertIsNotNone(relay)
                request,lifetime=relay
                self.assertEqual(request,{'host':'one','port':22,'connect_timeout':options.connect_timeout,'connector':'/trusted/nc'})
                self.assertEqual(lifetime,kwargs['max_native_seconds']);self.assertGreater(lifetime,0);self.assertLessEqual(lifetime,3)
            else:self.assertIsNone(relay)
            self.assertIsNone(process_guard._RELAY.get())


if __name__=='__main__':unittest.main()
