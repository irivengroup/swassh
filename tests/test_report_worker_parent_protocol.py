"""Parent death and audit cancellation use memory ports, with no real exit."""
import asyncio
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import audit,spool


class ParentProtocolTests(unittest.TestCase):
    def test_parent_channel_eof_io_error_or_unexpected_data_always_stops_worker(self):
        class StopProcess(BaseException):pass
        for failure in (None,EOFError('closed'),OSError('closed')):
            parent=SimpleNamespace(recv_bytes=Mock(side_effect=failure,return_value=b'unexpected'))
            port=SimpleNamespace(_exit=Mock(side_effect=StopProcess));cancelled=threading.Event();store=Mock()
            with patch.object(spool,'os',port),patch.object(spool,'_PROCESS_STORE',None),\
                    patch.object(spool,'_PROCESS_BUDGET',None),patch.object(spool,'_PROCESS_LEASE',None),\
                    patch.object(spool,'ReportStore',return_value=store),patch.object(threading,'Thread') as thread:
                spool.initialize_store('synthetic-directory',1024,cancelled,parent=parent)
                self.assertIs(store._cancelled,cancelled)
                target=thread.call_args.kwargs['target']
                with self.assertRaises(StopProcess):target()
                port._exit.assert_called_once_with(125)
                thread.return_value.start.assert_called_once_with()

    def test_default_audit_locations_follow_only_the_selected_platform_environment(self):
        for platform,key,component in (('nt','LOCALAPPDATA','AppData/Local'),('posix','XDG_STATE_HOME','.local/state')):
            for explicit in (False,True):
                home=Path('/synthetic-home');base=Path('/synthetic-state')
                port=SimpleNamespace(name=platform,environ={key:str(base)} if explicit else {})
                with patch.object(audit,'os',port),patch.object(audit.Path,'home',return_value=home):path=audit.default_log_path()
                expected=(base if explicit else home/component)/'swassh'/'swassh.jsonl'
                self.assertEqual(path,expected)


class AuditCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_flush_finishes_the_single_writer_before_close_releases_its_lock(self):
        entered,release=threading.Event(),threading.Event();events=[];handler=Mock();owner=Mock()
        def sync():
            entered.set()
            if not release.wait(3):raise TimeoutError('synthetic test release was not delivered')
            events.append('synchronized')
        handler.synchronize.side_effect=sync;handler.close.side_effect=lambda:events.append('handler-closed')
        owner.close.side_effect=lambda:events.append('owner-closed')
        trail=audit.AuditTrail('synthetic','a'*32)
        with patch.object(audit,'private_directory'),patch.object(audit,'_WriterLock',return_value=owner),patch.object(audit,'AuditHandler',return_value=handler):
            await trail.__aenter__();await trail.emit('synthetic',{})
            task=asyncio.create_task(trail.flush())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait,3))
                task.cancel();await asyncio.sleep(0);task.cancel();await asyncio.sleep(0)
                self.assertFalse(task.done());self.assertEqual(events,[]);release.set()
                with self.assertRaises(asyncio.CancelledError):await task
                await trail.__aexit__(None,None,None)
            finally:
                release.set();await asyncio.gather(task,return_exceptions=True)
        self.assertEqual(events,['synchronized','handler-closed','owner-closed'])
        handler.handle.assert_called_once()


if __name__=='__main__':unittest.main()
