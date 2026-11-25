"""The report owner's spool outlives a worker whose death is unconfirmed."""
import asyncio
from concurrent.futures import Executor,Future
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from swassh.infrastructure.process_reporter import ProcessReportWriter


class ImmediateExecutor(Executor):
    """An in-memory worker boundary with observable process-manager ownership."""
    def __init__(self,manager=None,processes=()):
        self._executor_manager_thread=manager
        self._processes=dict(enumerate(processes));self.calls=[];self.shutdowns=[]
    def submit(self,operation,*args,**kwargs):
        self.calls.append(args);future=Future();future.set_result(None);return future
    def shutdown(self,wait=True,*,cancel_futures=False):
        self.shutdowns.append((wait,cancel_futures))
        # Match CPython ProcessPoolExecutor.shutdown(wait=False): the public
        # executor releases these references before its manager has joined.
        self._processes=None;self._executor_manager_thread=None


class ReporterShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_force_shutdown_terminates_then_kills_only_if_manager_remains_alive(self):
        for initially_alive in (False,True):
            manager=Mock();manager.is_alive.side_effect=[True,False] if initially_alive else [False,False]
            process=Mock();executor=ImmediateExecutor(manager,(process,))
            writer=ProcessReportWriter('.',1024);writer._executor=executor
            await writer._shutdown(force=True)
            process.terminate.assert_called_once_with()
            self.assertEqual(process.kill.call_count,int(initially_alive))
            self.assertEqual(manager.join.call_count,1+int(initially_alive))
            self.assertEqual(executor.shutdowns,[(False,True)]);self.assertIsNone(writer._executor)
        process=Mock();process.terminate.side_effect=ProcessLookupError;process.kill.side_effect=ProcessLookupError
        manager=Mock();manager.is_alive.side_effect=[True,False]
        writer=ProcessReportWriter('.',1024);writer._executor=ImmediateExecutor(manager,(process,))
        await writer._shutdown(force=True)
        self.assertEqual(process.kill.call_count,1);self.assertIsNone(writer._executor)

    async def test_repeated_close_retains_spool_and_owner_when_worker_cannot_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=ProcessReportWriter(directory,1024)
            writer._directory=tempfile.TemporaryDirectory(dir=directory)
            spool=Path(writer._directory.name);receipt=spool/'synthetic-evidence';receipt.write_bytes(b'keep')
            manager=Mock();manager.is_alive.return_value=True
            process=Mock();executor=ImmediateExecutor(manager,(process,));writer._executor=executor
            try:
                for attempt in range(2):
                    with self.assertRaisesRegex(RuntimeError,'retain its private spool'):await writer._close()
                    self.assertTrue(receipt.exists(),'an unconfirmed worker may still use this spool')
                    self.assertIs(writer._executor,executor,'retain ownership so cleanup cannot mistake it for stopped')
                    with self.assertRaisesRegex(RuntimeError,'open or shutdown'):await writer.__aenter__()
                manager.is_alive.return_value=False
                await writer._close()
                self.assertFalse(spool.exists());self.assertIsNone(writer._executor)
            finally:
                manager.is_alive.return_value=False
                await writer._close()

    async def test_close_removes_database_sidecars_and_closes_both_parent_channels(self):
        with tempfile.TemporaryDirectory() as directory:
            writer=ProcessReportWriter(directory,1024);writer._directory=tempfile.TemporaryDirectory(dir=directory)
            root=Path(writer._directory.name);writer._store_path=str(root/'store.sqlite')
            for suffix in ('','-journal','-wal','-shm'):Path(writer._store_path+suffix).write_bytes(b'synthetic')
            sender,receiver=Mock(),Mock();writer._parent_sender,writer._parent_receiver=sender,receiver
            executor=ImmediateExecutor();writer._executor=executor
            await writer._close()
            self.assertEqual(executor.calls,[('close',)])
            sender.close.assert_called_once_with();receiver.close.assert_called_once_with()
            self.assertFalse(root.exists());self.assertIsNone(writer._store_path)
            await writer._close()
            sender.close.assert_called_once_with();receiver.close.assert_called_once_with()

    async def test_prepare_refuses_missing_parent_or_directory_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);writer=ProcessReportWriter(root,1024)
            for path in (root,root/'missing'/'report'):
                with self.assertRaises(ValueError):await writer.prepare(path)
            output=root/'report';await writer.prepare(output);self.assertFalse(output.exists())
            with self.assertRaisesRegex(RuntimeError,'not open'):await writer.summary()

    async def test_shutdown_and_close_cancellation_join_manager_before_releasing_ownership(self):
        for operation in ('_shutdown','_close'):
            entered,release=threading.Event(),threading.Event()
            class Manager:
                def join(self,timeout):entered.set();release.wait(timeout)
                def is_alive(self):return not release.is_set()
            writer=ProcessReportWriter('.',1024);executor=ImmediateExecutor(Manager());writer._executor=executor
            directory=Mock();writer._directory=directory
            task=asyncio.create_task(writer._shutdown(force=False) if operation=='_shutdown' else writer._close())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait,3))
                with self.assertRaisesRegex(RuntimeError, 'report writer is not open'):
                    await writer.summary()
                self.assertEqual(executor.calls, [], 'shutdown must refuse a new worker RPC')
                task.cancel();await asyncio.sleep(0);task.cancel();await asyncio.sleep(0)
                self.assertFalse(task.done());self.assertIs(writer._executor,executor)
                directory.cleanup.assert_not_called();release.set()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertIsNone(writer._executor);self.assertIsNone(writer._shutdown_owner)
                self.assertEqual(directory.cleanup.call_count,int(operation=='_close'))
            finally:
                release.set();await asyncio.gather(task,return_exceptions=True)


if __name__=='__main__':unittest.main()
