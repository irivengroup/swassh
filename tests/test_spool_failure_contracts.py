"""Real SQLite rollback and capacity errors never inflate report counters."""
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from swassh import Host,Result,Status,TransferReceipt
from swassh.infrastructure.spool import ReportStore


class SpoolFailureIntegrationTests(unittest.TestCase):
    def test_worker_without_invocation_does_not_create_an_unowned_dependent_lease(self):
        from swassh.infrastructure import spool
        from swassh.infrastructure.bastion import specification
        from swassh import Options
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(spool, '_PROCESS_STORE', None), patch.object(spool, '_PROCESS_BUDGET', None), \
                patch.object(spool, '_PROCESS_LEASE', None), patch('swassh.infrastructure.bastion.SharedBudget') as budget:
            spec = specification(Options(budget_dir=directory))
            spool.initialize_store(directory, 1024**2, threading.Event(), budget=spec, invocation=None)
            try:
                path, pid = spool.store_operation('identity')
                self.assertTrue(Path(path).is_file())
                self.assertGreater(pid, 0)
                self.assertEqual(sum(spool.store_operation('summary').values()), 0)
                budget.assert_not_called()
                self.assertIsNone(spool._PROCESS_BUDGET)
                self.assertIsNone(spool._PROCESS_LEASE)
            finally:
                spool.store_operation('close')
            self.assertFalse(Path(path).exists())

    def test_default_private_spool_is_removed_and_failed_connection_leaves_no_file(self):
        store = ReportStore(None, 1024**2)
        path = store.path
        self.assertTrue(path.is_file())
        store.close()
        self.assertFalse(path.exists())
        with tempfile.TemporaryDirectory() as directory:
            with patch('swassh.infrastructure.spool.sqlite3.connect', side_effect=OSError('synthetic open failure')):
                with self.assertRaisesRegex(OSError, 'synthetic open failure'):
                    ReportStore(directory, 1024**2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_duplicate_target_or_interrupted_batch_rolls_back_rows_and_all_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('duplicate','generator'):
                store=ReportStore(directory,1024**2)
                try:
                    original=Result(Host('one'),Status.SUCCESS,stdout='synthetic')
                    store.append([original]);before=store.bytes,dict(store.counts)
                    def batch():
                        yield Result(Host('two'),Status.FAILED,stderr='synthetic different response')
                        if failure=='duplicate':yield original
                        else:raise OSError('synthetic interrupted producer')
                    with self.assertRaises(sqlite3.IntegrityError if failure=='duplicate' else OSError):store.append(batch())
                    self.assertEqual((store.bytes,store.counts),before)
                    self.assertEqual(list(store._results()),[original])
                    self.assertEqual(store.db.execute('SELECT count(*) FROM responses').fetchone()[0],1)
                finally:store.close()

    def test_sqlite_full_and_logical_budget_refuse_without_partial_records(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('physical','logical'):
                store=ReportStore(directory,1024**2)
                try:
                    if failure=='physical':
                        pages=store.db.execute('PRAGMA page_count').fetchone()[0]
                        store.db.execute('PRAGMA max_page_count='+str(pages))
                    else:store.max_bytes=store.path.stat().st_size+1
                    with self.assertRaisesRegex(ValueError,'budget'):
                        store.append([Result(Host('one'),Status.SUCCESS,stdout='x'*(256*1024))])
                    self.assertEqual(store.bytes,0);self.assertEqual(sum(store.counts.values()),0)
                    self.assertEqual(list(store._results()),[])
                finally:store.close()

    def test_transfer_receipts_round_trip_and_status_filter_never_merges_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            store=ReportStore(directory,1024**2)
            try:
                receipt=TransferReceipt('pull','synthetic-local','/synthetic-remote',backend='sftp',bytes_transferred=7)
                results=[Result(Host('one'),Status.SUCCESS,transfer=receipt),Result(Host('two'),Status.FAILED,stderr='synthetic')]
                store.append(results)
                self.assertEqual(list(store._results()),results)
                self.assertEqual(list(store._results('success')),[results[0]])
                self.assertEqual(list(store._results('failed')),[results[1]])
            finally:store.close()
            self.assertEqual(list(Path(directory).glob('*.sqlite*')),[])


if __name__=='__main__':unittest.main()
