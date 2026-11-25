"""Reservation cleanup remains complete after storage errors and cancellation."""
import asyncio
from contextlib import asynccontextmanager
import os
import sqlite3
import threading
import unittest
from unittest.mock import Mock, patch

from swassh import Options
from swassh.infrastructure.bastion import invocation_budget, current_reservation
from swassh.infrastructure.native_budget import native_invocation_budget
from swassh.infrastructure.audit import AuditTrail
from swassh.infrastructure.filesystem import AtomicOutput
from swassh.infrastructure.bastion import FileLock


class BudgetCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_byte_owner_construction_releases_memory_without_entering_native_work(self):
        released = []
        @asynccontextmanager
        async def admission(options):
            try:
                yield
            finally:
                released.append(True)
        with patch('swassh.infrastructure.native_budget.invocation_budget', admission), \
                patch('swassh.infrastructure.native_budget.SQLiteByteBudget', side_effect=OSError('synthetic byte store construction')):
            with self.assertRaisesRegex(OSError, 'byte store construction'):
                async with native_invocation_budget(Options()):
                    self.fail('failed byte accounting reached native work')
        self.assertEqual(released, [True])

    async def test_nested_different_budget_restores_parent_and_cli_waits_for_real_admission(self):
        from swassh.infrastructure import bastion
        token = bastion._HELD.set(('parent-budget', 'parent-owner'))
        try:
            for mode in ('async', 'cli'):
                pool = Mock()
                lease = pool.ticket.return_value
                lease.identity = 'child-owner'
                lease.poll.side_effect = [False, True]
                with patch.object(bastion, 'specification', return_value={'directory': 'different-budget'}), \
                        patch.object(bastion, 'SharedBudget', return_value=pool), patch.object(bastion.time, 'sleep') as sleep:
                    if mode == 'async':
                        async with bastion.invocation_budget(Options()):
                            self.assertEqual(current_reservation(), 'child-owner')
                    else:
                        with bastion.cli_invocation_budget(Options()):
                            self.assertEqual(current_reservation(), 'child-owner')
                        sleep.assert_called_once_with(.05)
                self.assertEqual(current_reservation(), 'parent-owner')
                lease.close.assert_called_once()
                pool.close.assert_called_once()
                self.assertEqual(lease.poll.call_count, 2)
        finally:
            bastion._HELD.reset(token)

    async def test_native_preflight_retains_and_closes_the_byte_owner_before_memory_release(self):
        events=[]
        @asynccontextmanager
        async def admission(options):
            events.append('memory-acquired')
            try:yield
            finally:events.append('memory-released')
        budget=Mock()
        from unittest.mock import MagicMock
        budget._serialized=MagicMock()
        budget.close.side_effect=lambda:events.append('bytes-closed')
        with patch('swassh.infrastructure.native_budget.invocation_budget',admission), \
                patch('swassh.infrastructure.native_budget.SQLiteByteBudget',return_value=budget):
            async with native_invocation_budget(Options()):
                self.assertEqual(events,['memory-acquired'])
                budget.close.assert_not_called()
                budget._checkpoint.assert_called_once_with(force=True)
        self.assertEqual(events,['memory-acquired','bytes-closed','memory-released'])

    async def test_failed_native_preflight_closes_its_owner_and_never_enters_operation(self):
        events=[]
        @asynccontextmanager
        async def admission(options):
            try:yield
            finally:events.append('released')
        from unittest.mock import MagicMock
        budget=MagicMock()
        budget._checkpoint.side_effect=OSError('synthetic disk error')
        with patch('swassh.infrastructure.native_budget.invocation_budget',admission), \
                patch('swassh.infrastructure.native_budget.SQLiteByteBudget',return_value=budget):
            with self.assertRaisesRegex(OSError,'synthetic disk error'):
                async with native_invocation_budget(Options()):
                    self.fail('failed preparation must not reach SSH')
        budget.close.assert_called_once_with()
        self.assertEqual(events,['released'])

    def test_startup_busy_retry_is_bounded_and_does_not_hide_other_errors(self):
        from swassh.infrastructure.bastion import SharedBudget
        pool = object.__new__(SharedBudget)
        pool.db = Mock()
        busy = sqlite3.OperationalError('busy')
        busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
        with patch.object(pool, '_initialize', side_effect=[busy, None]) as initialize, patch(
            'swassh.infrastructure.bastion.time.sleep'
        ) as sleep:
            pool._retry_busy(pool._initialize)
            self.assertEqual(initialize.call_count, 2)
            sleep.assert_called_once_with(0.01)
        with patch.object(pool, '_initialize', side_effect=busy) as initialize, patch(
            'swassh.infrastructure.bastion.time.monotonic', side_effect=[0, 10]
        ), self.assertRaises(sqlite3.OperationalError):
            pool._retry_busy(pool._initialize)
        self.assertEqual(initialize.call_count, 1)
        with patch.object(pool, '_initialize', side_effect=sqlite3.OperationalError('disk failure')) as initialize:
            with self.assertRaisesRegex(sqlite3.OperationalError, 'disk failure'):
                pool._retry_busy(pool._initialize)
            self.assertEqual(initialize.call_count, 1)
        self.assertEqual(pool.db.execute.call_args.args, ('PRAGMA busy_timeout=5000',))

    def test_atomic_output_closes_directory_even_when_unlink_fails(self):
        output = object.__new__(AtomicOutput)
        output.stream, output.directory = Mock(closed=True), Mock()
        output.temporary = '.test.tmp'
        output.directory.unlink.side_effect = OSError('unlink failed')
        with self.assertRaisesRegex(OSError, 'unlink failed'):
            output.__exit__(ValueError, ValueError('abort'), None)
        output.directory.close.assert_called_once_with()

    def test_file_lock_closes_descriptor_even_when_unlock_fails(self):
        with patch('swassh.infrastructure.bastion.open_private_append') as opening:
            lock = FileLock('cleanup.lock')
        lock.locked = True
        opening.return_value.closed = False
        unlocking = 'msvcrt.locking' if os.name == 'nt' else 'fcntl.flock'
        with patch(unlocking, side_effect=OSError('unlock failed')):
            with self.assertRaisesRegex(OSError, 'unlock failed'):
                lock.close()
        opening.return_value.close.assert_called_once_with()
        self.assertFalse(lock.locked)

    async def test_audit_writer_lock_released_when_handler_close_fails(self):
        audit = AuditTrail(None, 'cleanup-test')
        audit.handler, audit.lock = Mock(), Mock()
        audit.handler.close.side_effect = OSError('flush failed')
        with self.assertRaisesRegex(OSError, 'flush failed'):
            await audit.__aexit__(None, None, None)
        audit.lock.close.assert_called_once_with()

    async def test_pool_closes_when_lease_release_fails(self):
        pool = Mock()
        pool.ticket.return_value.close.side_effect = OSError('storage unavailable')
        with patch('swassh.infrastructure.bastion.specification', return_value={'directory': 'test'}), patch(
            'swassh.infrastructure.bastion.SharedBudget', return_value=pool
        ):
            with self.assertRaisesRegex(OSError, 'storage unavailable'):
                async with invocation_budget(Options()):
                    self.assertIsNotNone(current_reservation())
        pool.close.assert_called_once_with()
        self.assertIsNone(current_reservation())

    async def test_repeated_cancel_waits_for_reservation_cleanup(self):
        loop = asyncio.get_running_loop()
        reserving, closing = asyncio.Event(), asyncio.Event()
        reserve_release, close_release = threading.Event(), threading.Event()
        pool = Mock()
        lease = pool.ticket.return_value

        def reserve(**kwargs):
            loop.call_soon_threadsafe(reserving.set)
            if not reserve_release.wait(5):
                raise TimeoutError('test reservation barrier')
            return lease

        def close():
            loop.call_soon_threadsafe(closing.set)
            if not close_release.wait(5):
                raise TimeoutError('test cleanup barrier')

        pool.ticket.side_effect = reserve
        lease.close.side_effect = close

        async def invoke():
            async with invocation_budget(Options()):
                self.fail('cancelled reservation must not enter the body')

        with patch('swassh.infrastructure.bastion.specification', return_value={'directory': 'test'}), patch(
            'swassh.infrastructure.bastion.SharedBudget', return_value=pool
        ):
            task = asyncio.create_task(invoke())
            try:
                await asyncio.wait_for(reserving.wait(), 5)
                task.cancel()
                reserve_release.set()
                await asyncio.wait_for(closing.wait(), 5)
                task.cancel()
                # Drain ready callbacks without a timing-dependent sleep.
                for _ in range(10):
                    await asyncio.sleep(0)
                self.assertFalse(task.done(), 'cleanup was abandoned on repeated cancellation')
            finally:
                reserve_release.set()
                close_release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await asyncio.to_thread(lambda: None)
        pool.close.assert_called_once_with()

    async def test_cancel_after_real_reservation_before_admission_preserves_parent_and_releases_lease(self):
        """Cancellation of a queued lease must not reset an unset context token."""
        import tempfile
        from swassh.infrastructure import bastion

        with tempfile.TemporaryDirectory() as directory:
            options = Options(budget_dir=directory)
            spec = bastion.specification(options)
            observer = bastion.SharedBudget(spec)
            blocker = observer.ticket(memory=observer.policy[2])
            self.assertTrue(blocker.poll())
            owned = set(bastion._OWNED)
            polled, never_admit = asyncio.Event(), asyncio.Event()
            child_pools, child_leases, restored = [], [], []
            real_pool, real_io = bastion.SharedBudget, bastion._io

            def open_child(configuration):
                pool = real_pool(configuration)
                child_pools.append(pool)
                real_ticket = pool.ticket

                def ticket(**amounts):
                    lease = real_ticket(**amounts)
                    child_leases.append(lease)
                    return lease

                pool.ticket = ticket
                return pool

            async def observe_io(call):
                result = await real_io(call)
                if getattr(call, '__name__', None) == 'poll':
                    self.assertFalse(result, 'the full real memory reservation must keep the child queued')
                    polled.set()
                    # Hold exactly after the real SQLite poll, before admission.
                    await never_admit.wait()
                return result

            async def invoke():
                try:
                    async with invocation_budget(options):
                        self.fail('a cancelled queued invocation must not enter the body')
                finally:
                    restored.append(current_reservation())

            parent = bastion._HELD.set(('different-parent-budget', 'parent-owner'))
            task = None
            try:
                with patch.object(bastion, 'SharedBudget', side_effect=open_child), \
                        patch.object(bastion, '_io', side_effect=observe_io):
                    task = asyncio.create_task(invoke())
                    try:
                        await asyncio.wait_for(polled.wait(), 5)
                        self.assertEqual(observer.db.execute('SELECT count(*) FROM leases').fetchone()[0], 2)
                    finally:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await asyncio.wait_for(task, 5)
                self.assertEqual(restored, ['parent-owner'])
                self.assertEqual(current_reservation(), 'parent-owner')
                self.assertEqual(observer.db.execute('SELECT id FROM leases').fetchall(), [(blocker.identity,)])
                self.assertEqual(bastion._OWNED, owned)
                self.assertEqual(len(child_pools), 1)
                with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed database'):
                    child_pools[0].db.execute('SELECT 1')
            finally:
                bastion._HELD.reset(parent)
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                for lease in child_leases:
                    if lease.lock.locked:
                        lease.close()
                for pool in child_pools:
                    pool.close()
                blocker.close()
                observer.close()
