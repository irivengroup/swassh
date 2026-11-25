"""Public channel/tunnel scopes keep one task owner and restore their boundary."""
import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import ChannelCapture,LocalForward,SSHChannel,SSHTunnel,Status
from swassh.interfaces import channels


class ScopeOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_enter_delegate_wrong_task_exit_and_reopen_obey_one_scope_owner(self):
        events=[]
        @asynccontextmanager
        async def budget(options):
            events.append('budget-open')
            try:yield
            finally:events.append('budget-close')
        class Audit:
            async def __aenter__(self):return self
            async def __aexit__(self,*args):events.append('audit-close')
            async def emit(self,*args):events.append(args[0])
            async def flush(self):pass
        native=SimpleNamespace(failure=None,open=AsyncMock(),aclose=AsyncMock())
        binary=SimpleNamespace(failure=None,send=AsyncMock(),read=AsyncMock(return_value=b'\x00\xff'),
            close_input=Mock(),wait=AsyncMock(return_value=ChannelCapture(Status.SUCCESS,0,b'\x00\xff',b'')),aclose=AsyncMock())
        channel=SSHChannel('one','true')
        with self.assertRaisesRegex(RuntimeError,'context first'):await channel.send(b'before')
        with patch.object(channels,'invocation_budget',budget),patch.object(channels,'AuditTrail',return_value=Audit()),\
                patch.object(channels,'NativeSSHScope',return_value=native),patch.object(channels,'NativeChannel',return_value=binary):
            async with channel:
                await channel.send(b'input');channel.close_input()
                self.assertEqual(await channel.read('stderr'),b'\x00\xff')
                self.assertTrue((await channel.wait()).ok)
                with self.assertRaisesRegex(RuntimeError,'task which entered'):
                    await asyncio.create_task(channel.__aexit__(None,None,None))
                self.assertTrue(channels._ACTIVE.get());native.aclose.assert_not_awaited()
                with self.assertRaisesRegex(RuntimeError,'nested'):
                    async with SSHTunnel('one',LocalForward(12345,'remote',443)):self.fail('nested scope admitted')
            with self.assertRaisesRegex(RuntimeError,'single-use'):await channel.__aenter__()
        self.assertFalse(channels._ACTIVE.get());self.assertIsNone(channel.token)
        native.aclose.assert_awaited_once();binary.aclose.assert_awaited_once()
        binary.send.assert_awaited_once_with(b'input');binary.read.assert_awaited_once_with('stderr')
        self.assertEqual(events[-3:],['ssh_scope_closed','audit-close','budget-close'])

    async def test_tunnel_readiness_and_terminal_failure_never_claim_destination_verification(self):
        tunnel=SSHTunnel('one',LocalForward(12345,'remote',443))
        self.assertFalse(tunnel.is_open)
        with self.assertRaisesRegex(RuntimeError,'context first'):await tunnel.wait()
        process=SimpleNamespace(returncode=None,wait=AsyncMock())
        tunnel.native=SimpleNamespace(directory=object(),process=process,failure=None)
        self.assertTrue(tunnel.is_open)
        with self.assertRaisesRegex(OSError,'destination availability is unknown'):await tunnel.wait()
        tunnel.native.failure='synthetic deadline';self.assertFalse(tunnel.is_open)
        with self.assertRaisesRegex(OSError,'synthetic deadline'):await tunnel.wait()
        tunnel.native.failure=None;process.returncode=0;self.assertFalse(tunnel.is_open)
        tunnel.native.directory=None;self.assertFalse(tunnel.is_open)


if __name__=='__main__':unittest.main()
