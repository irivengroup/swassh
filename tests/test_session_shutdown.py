"""Resource ownership regressions: exit cannot outrun active native work."""
import asyncio
from contextlib import asynccontextmanager
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import Session
from swassh.infrastructure.session import PersistentSSHTransport


class SessionShutdown(unittest.IsolatedAsyncioTestCase):
    async def test_exit_drains_active_run_and_rejects_queued_run_before_release(self):
        started, stopped = asyncio.Event(), asyncio.Event()
        events = []
        transport = Mock(closed=False)
        transport.open = AsyncMock()
        async def close():
            transport.closed = True
            events.append('transport_closed')
        transport.aclose = close
        async def run(*args):
            events.append('run_started')
            started.set()
            try:
                await asyncio.Future()
            finally:
                stopped.set()
                events.append('run_stopped')
        @asynccontextmanager
        async def budget(options):
            yield
            self.assertTrue(stopped.is_set())
            self.assertTrue(transport.closed)
            events.append('budget_released')
        with patch('swassh.interfaces.session.PersistentSSHTransport', return_value=transport), \
                patch('swassh.interfaces.session.invocation_budget', budget), \
                patch('swassh.interfaces.session.Swarm.run', side_effect=run):
            async with Session('host') as session:
                active = asyncio.create_task(session.run('first'))
                await started.wait()
                queued = asyncio.create_task(session.run('second'))
                # Let the second caller reach the lock while the first owns it.
                await asyncio.sleep(0)
            with self.assertRaises(asyncio.CancelledError):
                await active
            with self.assertRaises(RuntimeError):
                await queued
            self.assertEqual(events.count('run_started'), 1)
            self.assertLess(events.index('run_stopped'), events.index('budget_released'))

    async def test_wrong_task_cannot_close_owner_context(self):
        transport = Mock(closed=False, open=AsyncMock(), aclose=AsyncMock())
        @asynccontextmanager
        async def budget(options):
            yield
        with patch('swassh.interfaces.session.PersistentSSHTransport', return_value=transport), \
                patch('swassh.interfaces.session.invocation_budget', budget):
            async with Session('host') as session:
                with self.assertRaisesRegex(RuntimeError, 'entering task'):
                    await asyncio.create_task(session.__aexit__(None, None, None))
                self.assertFalse(session.closing)
                transport.aclose.assert_not_awaited()
            transport.aclose.assert_awaited_once()

    async def test_concurrent_close_and_repeated_cancellation_share_one_cleanup(self):
        transport = object.__new__(PersistentSSHTransport)
        transport.closed, transport._close_task = False, None
        transport.watch = None
        transport.master = Mock()
        transport.directory = Mock()
        directory = transport.directory
        transport.live = None
        entered, release = asyncio.Event(), asyncio.Event()
        async def cleanup(*args):
            entered.set()
            await release.wait()
        with patch('swassh.infrastructure.session._cleanup_process', side_effect=cleanup) as clean:
            first = asyncio.create_task(transport.aclose())
            await entered.wait()
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()
            second = asyncio.create_task(transport.aclose())
            await asyncio.sleep(0)
            self.assertFalse(first.done())
            self.assertFalse(second.done())
            directory.cleanup.assert_not_called()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await first
            await second
            await transport.aclose()
            clean.assert_awaited_once()
            directory.cleanup.assert_called_once()
            self.assertIsNone(transport.master)
            self.assertTrue(transport.closed)

    async def test_cancellation_during_exit_is_propagated_after_budget_release(self):
        entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        transport = Mock(closed=False, open=AsyncMock(), aclose=AsyncMock())
        @asynccontextmanager
        async def budget(options):
            yield
            finished.set()
        async def run(*args):
            entered.set()
            try:
                await asyncio.Future()
            finally:
                await release.wait()
        async def owner():
            async with Session('host') as session:
                child = asyncio.create_task(session.run('first'))
                await entered.wait()
            await child
        with patch('swassh.interfaces.session.PersistentSSHTransport', return_value=transport), \
                patch('swassh.interfaces.session.invocation_budget', budget), \
                patch('swassh.interfaces.session.Swarm.run', side_effect=run):
            task = asyncio.create_task(owner())
            try:
                await asyncio.wait_for(entered.wait(), 3)
            except TimeoutError:
                if task.done():
                    task.result()
                raise
            # Owner exits and cancels its child; child's cleanup is held open.
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(finished.is_set())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(finished.is_set())
