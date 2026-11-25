"""Durable desired-state intents fail closed on corruption and cancellation."""
import asyncio
from pathlib import Path
import threading
import tempfile
import unittest
from unittest.mock import Mock,patch

from swassh import DesiredState,Host,Options
from swassh.infrastructure import convergence


class ConvergenceStorageFailureIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_capacity_types_and_limits_fail_before_creating_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for value in (True,1.0,'1',None,0,100001):
                destination=root/'never-created'
                with self.subTest(value=value),self.assertRaisesRegex(ValueError,'capacity'):
                    convergence.SQLiteConvergenceJournal(Options(),directory=destination,max_records=value)
                self.assertFalse(destination.exists())

    async def test_oversize_existing_database_is_refused_before_sqlite_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'intents.sqlite'
            with path.open('wb') as stream:stream.truncate(32*1024**2+1)
            journal=convergence.SQLiteConvergenceJournal(Options(),directory=root)
            try:
                with patch.object(convergence.sqlite3,'connect',side_effect=AssertionError('oversize database opened')) as connect,\
                        self.assertRaisesRegex(ValueError,'exceeds its capacity'):
                    await journal._call(lambda:None)
                connect.assert_not_called();self.assertIsNone(journal.db)
                self.assertEqual(path.stat().st_size,32*1024**2+1)
            finally:await journal.aclose()

    async def test_persisted_counter_types_bounds_and_malformed_identity_refuse_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('text-counter','negative-counter','malformed-identity'):
                folder=Path(directory)/failure
                journal=convergence.SQLiteConvergenceJournal(Options(),directory=folder)
                await journal._call(lambda:None)
                if failure=='text-counter':journal.db.execute("UPDATE capacity SET records='invalid'")
                elif failure=='negative-counter':
                    # Deliberately damaged data in this private fixture only;
                    # production constraints remain enabled and unchanged.
                    journal.db.execute('PRAGMA ignore_check_constraints=ON')
                    journal.db.execute('UPDATE capacity SET records=-1')
                    journal.db.execute('PRAGMA ignore_check_constraints=OFF')
                else:
                    journal.db.execute("INSERT INTO records VALUES ('invalid-id','checking')")
                    journal.db.execute('UPDATE capacity SET records=1')
                before=list(journal.db.iterdump());await journal.aclose()
                reopened=convergence.SQLiteConvergenceJournal(Options(),directory=folder)
                try:
                    with self.subTest(failure=failure),self.assertRaisesRegex(ValueError,'counters or records'):
                        await reopened._call(lambda:None)
                    self.assertIsNone(reopened.db)
                    # Check a separate real connection: refusal must not repair
                    # damaged evidence or silently start an empty journal.
                    db=convergence.sqlite3.connect(folder/'intents.sqlite')
                    try:self.assertEqual(list(db.iterdump()),before)
                    finally:db.close()
                finally:await reopened.aclose()

    async def test_live_corruption_and_schema_changes_roll_back_without_creating_an_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('missing-capacity','text-counter','negative-counter','schema','invalid-state'):
                journal=convergence.SQLiteConvergenceJournal(Options(),directory=Path(directory)/failure)
                try:
                    await journal._call(lambda:None)
                    if failure=='missing-capacity':journal.db.execute('DELETE FROM capacity')
                    elif failure=='text-counter':journal.db.execute("UPDATE capacity SET records='invalid'")
                    elif failure=='negative-counter':
                        journal.db.execute('PRAGMA ignore_check_constraints=ON')
                        journal.db.execute('UPDATE capacity SET records=-1')
                        journal.db.execute('PRAGMA ignore_check_constraints=OFF')
                    elif failure=='schema':journal.db.execute('CREATE TABLE unexpected (value)')
                    else:
                        journal.db.execute('PRAGMA ignore_check_constraints=ON')
                        journal.db.execute("INSERT INTO records VALUES (?, 'invalid')",('a'*64,))
                        journal.db.execute('PRAGMA ignore_check_constraints=OFF')
                        journal.db.execute('UPDATE capacity SET records=1')
                    before=list(journal.db.iterdump())
                    with self.subTest(failure=failure),self.assertRaisesRegex(ValueError,'schema changed|full or invalid|invalid desired-state intent'):
                        await journal._call(journal._transaction,'a'*64)
                    self.assertEqual(list(journal.db.iterdump()),before)
                    self.assertFalse(journal.db.in_transaction);self.assertEqual(journal.active,0)
                finally:await journal.aclose()

    async def test_missing_capacity_and_mismatched_counter_refuse_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for failure in ('missing-capacity','mismatched-count','reduced-limit'):
                folder=root/failure;first=convergence.SQLiteConvergenceJournal(Options(),directory=folder)
                async with first.scope(Host('one'),DesiredState('state','check','apply')):pass
                if failure=='missing-capacity':first.db.execute('DELETE FROM capacity')
                elif failure=='mismatched-count':first.db.execute('UPDATE capacity SET records=2')
                else:
                    async with first.scope(Host('two'),DesiredState('state','check','apply')):pass
                await first.aclose()
                second=convergence.SQLiteConvergenceJournal(Options(),directory=folder,max_records=1 if failure=='reduced-limit' else 100000)
                try:
                    with self.assertRaisesRegex(ValueError,'counters or records'):
                        async with second.scope(Host('one'),DesiredState('state','check','apply')):self.fail('corrupt journal admitted')
                    self.assertIsNone(second.db)
                finally:await second.aclose()

    async def test_disappeared_owned_intent_and_changed_schema_preserve_failed_state(self):
        with tempfile.TemporaryDirectory() as directory:
            journal=convergence.SQLiteConvergenceJournal(Options(),directory=directory)
            action=DesiredState('state','check','apply');host=Host('one')
            try:
                async with journal.scope(host,action) as lease:
                    with self.assertRaisesRegex(RuntimeError,'active operations'):await journal.aclose()
                    await lease.applying();await lease.blocked()
                    for pragma,value in (('user_version',2),('application_id',0)):
                        original=journal.db.execute('PRAGMA '+pragma).fetchone()[0]
                        journal.db.execute('PRAGMA '+pragma+'='+str(value))
                        with self.assertRaisesRegex(ValueError,'schema changed'):await lease.verified()
                        journal.db.execute('PRAGMA '+pragma+'='+str(original))
                    self.assertEqual(journal.db.execute('SELECT state FROM records').fetchone()[0],'blocked')
                    journal.db.execute('DELETE FROM records')
                    with self.assertRaisesRegex(ValueError,'intent disappeared'):await lease.verified()
                self.assertEqual(journal.active,0)
            finally:await journal.aclose()
            with self.assertRaisesRegex(RuntimeError,'closed'):await journal._state('a'*64,'verified')
            await journal.aclose()

    async def test_cancelled_lock_creation_waits_for_owner_and_closes_it_before_returning(self):
        with tempfile.TemporaryDirectory() as directory:
            journal=convergence.SQLiteConvergenceJournal(Options(),directory=directory)
            entered,release=threading.Event(),threading.Event();owner=Mock()
            def create(path):
                entered.set()
                if not release.wait(3):raise TimeoutError('synthetic test release was not delivered')
                return owner
            context=journal.scope(Host('one'),DesiredState('state','check','apply'))
            try:
                with patch.object(convergence,'_WriterLock',side_effect=create):
                    opening=asyncio.create_task(context.__aenter__())
                    self.assertTrue(await asyncio.to_thread(entered.wait,3))
                    opening.cancel();await asyncio.sleep(0);self.assertFalse(opening.done())
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):await opening
                owner.close.assert_called_once_with();self.assertEqual(journal.active,0)
            finally:
                release.set();await journal.aclose()


if __name__=='__main__':unittest.main()
