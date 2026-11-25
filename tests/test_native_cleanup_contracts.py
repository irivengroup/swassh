"""Native cleanup order and escalation through memory OS/process boundaries."""
import asyncio
import os
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh.infrastructure import ssh


class NativeCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_posix_groups_are_signalled_even_when_the_leader_has_exited(self):
        for missing,expired in ((False,False),(False,True),(True,False)):
            port=SimpleNamespace(**vars(os));port.name='posix';port.killpg=Mock(side_effect=ProcessLookupError if missing else None)
            signals=SimpleNamespace(**vars(signal));signals.SIGKILL=9
            process=Mock(pid=123,returncode=0)
            process.wait=AsyncMock(side_effect=[TimeoutError,0] if expired else [0,0])
            with patch.object(ssh,'os',port),patch.object(ssh,'signal',signals):await ssh._stop(process)
            self.assertEqual(port.killpg.call_args_list[0].args,(123,signal.SIGTERM))
            self.assertEqual(port.killpg.call_args_list[1].args,(123,signals.SIGKILL))
            self.assertEqual(process.wait.await_count,2)
            process.terminate.assert_not_called();process.kill.assert_not_called()

    async def test_windows_escalates_only_for_a_live_process_and_reaps_after_kill(self):
        port=SimpleNamespace(**vars(os));port.name='nt'
        for exited,expired in ((False,False),(False,True),(True,False)):
            process=Mock(returncode=0 if exited else None)
            process.wait=AsyncMock(side_effect=[TimeoutError,0] if expired else [0])
            with patch.object(ssh,'os',port):await ssh._stop(process)
            self.assertEqual(process.terminate.call_count,int(not exited))
            self.assertEqual(process.kill.call_count,int(expired))
            self.assertEqual(process.wait.await_count,0 if exited else 2 if expired else 1)

    async def test_stop_failure_still_cancels_pipe_tasks_but_does_not_release_live_guardian(self):
        entered,finished=asyncio.Event(),asyncio.Event()
        async def reader():
            entered.set()
            try:await asyncio.Future()
            finally:finished.set()
        task=asyncio.create_task(reader());await entered.wait();process=object()
        with patch.object(ssh,'_stop',new_callable=AsyncMock,side_effect=OSError('synthetic stop failure')),\
                patch.object(ssh,'release_guardian') as release:
            with self.assertRaisesRegex(OSError,'stop failure'):await ssh._cleanup_process(process,[task])
        self.assertTrue(task.done());self.assertTrue(finished.is_set());release.assert_not_called()

    async def test_repeated_cancellation_waits_for_native_cleanup_before_releasing_guardian(self):
        entered,allow=asyncio.Event(),asyncio.Event();events=[];process=object()
        async def stop(native):
            self.assertIs(native,process);entered.set();await allow.wait();events.append('stopped')
        with patch.object(ssh,'_stop',side_effect=stop),patch.object(ssh,'native_metrics',return_value={'native_seconds':1}),\
                patch.object(ssh,'release_guardian',side_effect=lambda native:events.append('released')):
            task=asyncio.create_task(ssh._cleanup_process(process,[]));await entered.wait()
            task.cancel();await asyncio.sleep(0);task.cancel();await asyncio.sleep(0)
            self.assertFalse(task.done());self.assertEqual(events,[]);allow.set()
            with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(events,['stopped','released'])


if __name__=='__main__':unittest.main()
