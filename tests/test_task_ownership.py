"""Owned future results, repeated cancellation and late errors on all runtimes."""
import asyncio
import threading
import unittest

from swassh.application.durable import DurableOutbox
from swassh.application.task_ownership import wait_owned
from swassh.infrastructure.lifecycle import finish_task


class OwnedFutureTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_result_error_and_cancellation_are_returned_without_reinterpretation(self):
        loop=asyncio.get_running_loop()
        future=loop.create_future();future.set_result(17)
        self.assertEqual(await wait_owned(future),17)
        future=loop.create_future();future.set_exception(ValueError('synthetic result'))
        with self.assertRaisesRegex(ValueError,'synthetic result'):await wait_owned(future)
        future=loop.create_future();future.cancel()
        with self.assertRaises(asyncio.CancelledError):await wait_owned(future)

    async def test_caller_cancellation_does_not_cancel_owned_future_or_log_its_late_error(self):
        loop=asyncio.get_running_loop();previous=loop.get_exception_handler();unhandled=[]
        loop.set_exception_handler(lambda loop,context:unhandled.append(context))
        try:
            for failure in (False,True):
                future=loop.create_future()
                waiter=asyncio.create_task(wait_owned(future));await asyncio.sleep(0)
                waiter.cancel()
                with self.assertRaises(asyncio.CancelledError):await waiter
                self.assertFalse(future.cancelled());self.assertFalse(future.done())
                if failure:
                    future.set_exception(RuntimeError('synthetic late result'))
                    with self.assertRaisesRegex(RuntimeError,'synthetic late result'):await wait_owned(future)
                else:future.set_result(19);self.assertEqual(await wait_owned(future),19)
                await asyncio.sleep(0)
                self.assertEqual(unhandled,[])
        finally:loop.set_exception_handler(previous)

    async def test_finish_task_preserves_ownership_across_repeated_cancellation_and_late_failure(self):
        release=asyncio.Event();entered=asyncio.Event();unhandled=[]
        async def operation():entered.set();await release.wait();raise RuntimeError('synthetic cleanup failure')
        loop=asyncio.get_running_loop();previous=loop.get_exception_handler()
        loop.set_exception_handler(lambda loop,context:unhandled.append(context))
        operation_task=asyncio.create_task(operation());await entered.wait()
        finishing=asyncio.create_task(finish_task(operation_task));await asyncio.sleep(0)
        try:
            finishing.cancel();await asyncio.sleep(0);finishing.cancel();await asyncio.sleep(0)
            self.assertFalse(operation_task.cancelled());self.assertFalse(finishing.done())
            release.set()
            with self.assertRaisesRegex(RuntimeError,'synthetic cleanup failure'):await finishing
            await asyncio.sleep(0);self.assertEqual(unhandled,[])
        finally:loop.set_exception_handler(previous)

    async def test_durable_worker_failure_after_cancellation_is_retrieved_after_join(self):
        # The memory thread represents a durable storage port. It must finish
        # before its caller can close/reuse that port; no database is opened.
        entered=threading.Event();release=threading.Event();finished=threading.Event();unhandled=[]
        def operation():
            entered.set()
            try:
                if not release.wait(3):raise AssertionError('test release missing')
                raise RuntimeError('synthetic durable error')
            finally:finished.set()
        service=DurableOutbox(None,audit_factory=None,audit_path='unused',audit_scope='test')
        loop=asyncio.get_running_loop();previous=loop.get_exception_handler()
        loop.set_exception_handler(lambda loop,context:unhandled.append(context))
        task=asyncio.create_task(service._io(operation))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait,2))
            task.cancel();await asyncio.sleep(0);task.cancel();await asyncio.sleep(0)
            self.assertFalse(task.done());release.set()
            with self.assertRaisesRegex(RuntimeError,'synthetic durable error'):await task
            self.assertTrue(finished.is_set());await asyncio.sleep(0);self.assertEqual(unhandled,[])
        finally:release.set();loop.set_exception_handler(previous)
