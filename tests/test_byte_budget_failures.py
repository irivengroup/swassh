"""Private SQLite byte-accounting corruption and ambiguous-commit regressions."""
import contextlib
import concurrent.futures
from dataclasses import replace
import json
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh import Options
from swassh.infrastructure import bandwidth
from swassh.infrastructure.bastion import SharedBudget,specification


class ConnectionFault:
    """Delegate to real SQLite; fail at a specified durability boundary once."""
    def __init__(self,connection,*,after_commit=False,rollback_error=False):
        self.connection=connection;self.after_commit=after_commit;self.rollback_error=rollback_error
        self.failed=False;self.closed=False
    def __getattr__(self,name):return getattr(self.connection,name)
    def commit(self):
        if not self.failed:
            self.failed=True
            if self.after_commit:self.connection.commit()
            raise sqlite3.OperationalError('synthetic commit fault')
        return self.connection.commit()
    def rollback(self):
        self.connection.rollback()
        if self.rollback_error:raise sqlite3.OperationalError('synthetic rollback fault')
    def close(self):self.closed=True;return self.connection.close()


class ByteBudgetFailureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.clock=patch.object(bandwidth.time,'monotonic_ns',return_value=0);self.clock.start();self.addCleanup(self.clock.stop)
        self.options=Options(budget_dir=self.temporary.name,bastion_bandwidth_kib=1)
        self.spec=specification(self.options)
        self.budget=bandwidth.SQLiteByteBudget(self.spec);self.addCleanup(self.budget.close)

    def test_zero_settlement_and_repeated_idle_preserve_pending_and_consumed_rights(self):
        before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
        self.assertEqual(self.budget._settle(0), 0)
        self.assertIsNone(self.budget.credit_owner)
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)
        self.budget.idle()
        pending = self.budget.chunks(b'x', threading.Event())
        self.assertEqual(next(pending), b'x')
        try:
            self.budget.idle()
            self.assertEqual((self.budget.remaining, self.budget.pending, self.budget.spent), (0, 1, 0))
            snapshot = self.budget.db.execute('SELECT * FROM bucket').fetchall()
            self.budget.idle()
            self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), snapshot)
            self.assertEqual(self.budget.db.execute('SELECT amount FROM byte_leases').fetchall(), [(1,)])
        finally:
            pending.close()
        self.assertEqual((self.budget.pending, self.budget.spent), (0, 1))
        self.budget.idle()
        self.assertEqual((self.budget.remaining, self.budget.pending, self.budget.spent), (0, 0, 0))
        self.assertEqual(self.budget.db.execute('SELECT amount FROM byte_leases').fetchall(), [(0,)])
        self.assertEqual(self.budget.db.execute('SELECT credits FROM bucket').fetchone()[0], 1023 * 10**9)

    def test_real_sqlite_without_wal_support_is_refused_and_closed(self):
        memory = sqlite3.connect(':memory:', isolation_level=None)
        self.assertEqual(memory.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'memory')
        before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
        with contextlib.closing(SharedBudget(self.spec)) as coordinator:
            with patch.object(bandwidth.sqlite3, 'connect', return_value=memory):
                with self.assertRaisesRegex(ValueError, '^encrypted-byte durable WAL unavailable$'):
                    bandwidth.SQLiteByteBudget(None, coordinator=coordinator)
        with self.assertRaises(sqlite3.ProgrammingError):
            memory.execute('SELECT 1')
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)

    def test_live_local_byte_owner_prevents_a_rate_change_without_losing_its_lock(self):
        self.assertEqual(list(self.budget.chunks(b'x', threading.Event())), [b'x'])
        identity, owner = self.budget.credit_owner
        before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
        amounts = self.budget.db.execute('SELECT * FROM byte_leases').fetchall()
        changed = specification(replace(self.options, bastion_bandwidth_kib=2))
        try:
            with self.assertRaisesRegex(ValueError, '^encrypted-byte policy changed with outstanding owners$'):
                bandwidth.SQLiteByteBudget(changed)
            self.assertTrue(owner.locked)
            self.assertIn(owner.path, bandwidth._OWNED)
            self.assertEqual(self.budget.credit_owner[0], identity)
            self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)
            self.assertEqual(self.budget.db.execute('SELECT * FROM byte_leases').fetchall(), amounts)
        finally:
            with contextlib.closing(SharedBudget(self.spec)):
                pass

    def test_cold_rate_change_forfeits_real_crashed_owner_rights_without_a_new_burst(self):
        code = '''import json,os,sys,threading
from swassh.infrastructure import bandwidth
bandwidth.time.monotonic_ns=lambda:0
budget=bandwidth.SQLiteByteBudget(json.loads(sys.argv[1]))
assert list(budget.chunks(b"uncertain",threading.Event()))==[b"uncertain"]
os._exit(37)
'''
        child = subprocess.run([sys.executable, '-c', code, json.dumps(self.spec)], capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 37, child.stderr.decode(errors='replace'))
        rows = self.budget.db.execute('SELECT id,amount FROM byte_leases').fetchall()
        self.assertEqual(len(rows), 1)
        marker = self.budget.path.parent / ('credit-' + rows[0][0] + '.mutex')
        self.assertTrue(marker.exists())
        changed = specification(replace(self.options, bastion_bandwidth_kib=2))
        with contextlib.closing(bandwidth.SQLiteByteBudget(changed)) as other:
            self.assertEqual(other.db.execute('SELECT rate,credits FROM bucket').fetchone(), (2048, 0))
            self.assertEqual(other.db.execute('SELECT * FROM byte_leases').fetchall(), [])
            self.assertFalse(marker.exists())
            self.assertGreater(other.reserve(1, now=0), 0)

    def test_owned_orphan_marker_is_retained_until_its_real_lock_is_released(self):
        path = self.budget.path.parent / ('credit-' + 'e' * 32 + '.mutex')
        owner = bandwidth.FileLock(path)
        self.assertTrue(owner.acquire())
        try:
            with contextlib.closing(bandwidth.SQLiteByteBudget(self.spec)):
                self.assertTrue(path.exists())
                self.assertTrue(owner.locked)
        finally:
            owner.close()
        with contextlib.closing(bandwidth.SQLiteByteBudget(self.spec)):
            self.assertFalse(path.exists())

    def test_orphan_scan_refuses_the_real_public_limit_without_issuing_credit(self):
        limit = bandwidth.MAX_LEASES * 2
        before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
        for index in range(limit + 1):
            (self.budget.path.parent / ('credit-' + f'{index:032x}' + '.mutex')).touch(mode=0o600, exist_ok=False)
        self.assertEqual(len(list(self.budget.path.parent.glob('credit-*.mutex'))), limit + 1)
        with self.assertRaisesRegex(ValueError, '^too many encrypted-byte orphan locks$'):
            bandwidth.SQLiteByteBudget(self.spec)
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)
        self.assertEqual(self.budget.db.execute('SELECT * FROM byte_leases').fetchall(), [])

    def test_dangling_sidecar_link_report_is_rejected_before_sqlite_open(self):
        target = Path(str(self.budget.path) + '-wal')
        real_path = bandwidth.Path
        class DanglingLink:
            def exists(self):
                return False
            def is_symlink(self):
                return True
            def lstat(self):
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o600, st_size=0)
        def filesystem_path(value):
            path = real_path(value)
            return DanglingLink() if path == target else path
        before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
        with contextlib.closing(SharedBudget(self.spec)) as coordinator:
            with patch.object(bandwidth, 'Path', side_effect=filesystem_path), \
                    patch.object(bandwidth.sqlite3, 'connect', side_effect=AssertionError('must not open SQLite')) as connect:
                with self.assertRaisesRegex(ValueError, '^invalid encrypted-byte sidecar$'):
                    bandwidth.SQLiteByteBudget(None, coordinator=coordinator)
            connect.assert_not_called()
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)

    def test_foreign_live_owner_and_orphan_are_retained_until_the_peer_exits(self):
        code = '''import json,sys,threading
from swassh.infrastructure import bandwidth
bandwidth.time.monotonic_ns=lambda:0
budget=bandwidth.SQLiteByteBudget(json.loads(sys.argv[1]))
assert list(budget.chunks(b"x",threading.Event()))==[b"x"]
identity="0"*32 if budget.credit_owner[0]!="0"*32 else "1"*32
orphan=bandwidth.FileLock(budget.path.parent/("credit-"+identity+".mutex"))
assert orphan.acquire()
print(json.dumps({"orphan":identity}),flush=True)
sys.stdin.buffer.read(1)
orphan.close()
budget.close()
'''
        child = subprocess.Popen([sys.executable, '-c', code, json.dumps(self.spec)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as reader:
                ready = reader.submit(child.stdout.readline)
                try:
                    metadata = json.loads(ready.result(timeout=15))
                except BaseException:
                    child.kill()
                    raise
            self.assertIn(metadata['orphan'], ('0' * 32, '1' * 32))
            orphan = self.budget.path.parent / ('credit-' + metadata['orphan'] + '.mutex')
            with contextlib.closing(bandwidth.SQLiteByteBudget(self.spec)):
                self.assertTrue(orphan.exists())
            before = self.budget.db.execute('SELECT * FROM bucket').fetchall()
            self.assertGreater(self.budget.reserve(1, now=0), 0)
            changed = specification(replace(self.options, bastion_bandwidth_kib=2))
            with self.assertRaisesRegex(ValueError, '^encrypted-byte policy changed with outstanding owners$'):
                bandwidth.SQLiteByteBudget(changed)
            self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(), before)
        finally:
            try:
                _, error = child.communicate(b'x', timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=15)
                raise
        self.assertEqual(child.returncode, 0, error.decode(errors='replace'))
        with contextlib.closing(bandwidth.SQLiteByteBudget(changed)) as other:
            self.assertFalse(orphan.exists())
            self.assertEqual(other.db.execute('SELECT credits FROM bucket').fetchone()[0], 0)

    def test_checkpoint_without_any_wal_is_a_noop_even_after_connection_close(self):
        self.budget.close()
        self.assertFalse(Path(str(self.budget.path) + '-wal').exists())
        self.assertIsNone(self.budget._checkpoint(force=True))

    def test_invalid_owner_identity_count_and_amount_never_grant_bytes(self):
        db=self.budget.db;db.execute('PRAGMA ignore_check_constraints=ON')
        for identity,amount in (('short',0),('A'*32,0),(b'a'*32,0),('a'*32,-1),('a'*32,16385),('a'*32,1.5),('a'*32,'invalid')):
            with self.subTest(identity=identity,amount=amount):
                db.execute('INSERT INTO byte_leases VALUES (?,?)',(identity,amount))
                before=db.execute('SELECT * FROM bucket').fetchall()
                with self.assertRaisesRegex(ValueError,'owners'):self.budget.reserve(1)
                self.assertEqual(db.execute('SELECT * FROM bucket').fetchall(),before)
                self.assertFalse(db.in_transaction)
                db.execute('DELETE FROM byte_leases')
        with patch.object(bandwidth,'MAX_LEASES',2):
            db.executemany('INSERT INTO byte_leases VALUES (?,0)',((f'{i:032x}',) for i in range(3)))
            with self.assertRaisesRegex(ValueError,'owners'):self.budget.reserve(1)
            db.execute('DELETE FROM byte_leases')

    def test_changed_bucket_and_schema_refuse_accounting_and_keep_committed_values(self):
        db=self.budget.db;original=db.execute('SELECT rate,credits,observed FROM bucket WHERE id=1').fetchone()
        for field,value in (('rate',2048),('credits',-1),('credits',1024*10**9+1),('credits','bad'),('observed',-1),('observed','bad')):
            with self.subTest(field=field,value=value):
                db.execute('UPDATE bucket SET '+field+'=? WHERE id=1',(value,))
                with self.assertRaises(ValueError):self.budget.reserve(1)
                self.assertEqual(db.execute('SELECT '+field+' FROM bucket WHERE id=1').fetchone()[0],value)
                db.execute('UPDATE bucket SET rate=?,credits=?,observed=? WHERE id=1',original)
        for pragma,value,restore in (('user_version',3,2),('application_id',0,bandwidth.APPLICATION_ID)):
            db.execute('PRAGMA '+pragma+'='+str(value))
            with self.assertRaisesRegex(ValueError,'schema changed'):self.budget.reserve(1)
            db.execute('PRAGMA '+pragma+'='+str(restore))
        db.execute('DELETE FROM bucket')
        with self.assertRaisesRegex(ValueError,'policy or counters'):self.budget.reserve(1)
        db.execute('INSERT INTO bucket VALUES (1,?,?,?)',original)
        self.assertEqual(self.budget.reserve(1),0)

    def test_commit_failure_before_and_after_commit_disables_every_cached_right(self):
        for after in (False,True):
            with self.subTest(after_commit=after),tempfile.TemporaryDirectory() as directory:
                spec=specification(Options(budget_dir=directory,bastion_bandwidth_kib=1))
                budget=bandwidth.SQLiteByteBudget(spec)
                budget.db=ConnectionFault(budget.db,after_commit=after)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError,'commit fault'):
                        next(budget.chunks(b'x',threading.Event()))
                    self.assertTrue(budget.credit_failed)
                    with self.assertRaisesRegex(ValueError,'owner unavailable'):
                        next(budget.chunks(b'x',threading.Event()))
                    with self.assertRaisesRegex(ValueError,'owner unavailable'):budget.idle()
                finally:budget.close()
                # An ambiguous committed reservation is forfeited after owner
                # death, never treated as an unused refundable burst.
                other=bandwidth.SQLiteByteBudget(spec)
                try:
                    self.assertEqual(other.reserve(1),976563/10**9 if after else 0)
                finally:other.close()

    def test_close_failure_closes_connection_and_owner_without_refunding_uncertain_bytes(self):
        budget=self.budget
        self.assertEqual(list(budget.chunks(b'written',threading.Event())),[b'written'])
        owner=budget.credit_owner[1]
        real=budget.db
        proxy=ConnectionFault(real,rollback_error=True);budget.db=proxy
        with self.assertRaisesRegex(sqlite3.OperationalError,'rollback fault'):budget.close()
        self.assertTrue(proxy.closed);self.assertTrue(budget.closed)
        self.assertIsNone(budget.credit_owner)
        self.assertTrue(owner.stream.closed)
        budget.close()
        with self.assertRaisesRegex(ValueError,'owner unavailable'):next(budget.chunks(b'x',threading.Event()))

    def test_owner_lock_refusal_rolls_back_publication_and_cannot_be_reused(self):
        original=bandwidth.FileLock
        refused=Mock();refused.acquire.return_value=False
        def owner(path):return refused if Path(path).name.startswith('credit-') else original(path)
        before=self.budget.db.execute('SELECT * FROM bucket').fetchall()
        with patch.object(bandwidth,'FileLock',side_effect=owner),self.assertRaisesRegex(ValueError,'cannot own'):
            next(self.budget.chunks(b'x',threading.Event()))
        refused.close.assert_called_once()
        self.assertEqual(self.budget.db.execute('SELECT COUNT(*) FROM byte_leases').fetchone()[0],0)
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(),before)

    def test_missing_known_counters_cannot_be_reinitialized_as_a_free_burst(self):
        self.budget.db.execute('DELETE FROM bucket');self.budget.close()
        with self.assertRaisesRegex(ValueError,'counters missing'):bandwidth.SQLiteByteBudget(self.spec)
        db=sqlite3.connect(self.budget.path)
        try:self.assertEqual(db.execute('SELECT COUNT(*) FROM bucket').fetchone()[0],0)
        finally:db.close()

    def test_database_and_sidecar_ceiling_or_wrong_coordinator_refuse_before_opening_sqlite(self):
        with self.assertRaisesRegex(ValueError,'coordinator'):bandwidth.SQLiteByteBudget(None,coordinator=object())
        self.budget.close()
        with self.budget.path.open('r+b') as stream:stream.truncate(1024**2+1)
        with self.assertRaisesRegex(ValueError,'1 MiB'):bandwidth.SQLiteByteBudget(self.spec)
        self.budget.path.unlink()
        sidecar=Path(str(self.budget.path)+'-wal');sidecar.mkdir()
        with self.assertRaisesRegex(ValueError,'sidecar'):bandwidth.SQLiteByteBudget(self.spec)
        sidecar.rmdir()
        with sidecar.open('wb') as stream:stream.truncate(2*1024**2+1)
        with self.assertRaisesRegex(ValueError,'sidecar'):bandwidth.SQLiteByteBudget(self.spec)
        sidecar.unlink()

    def test_mutex_timeout_and_exception_both_close_the_owner(self):
        owner=Mock();owner.acquire.return_value=False
        with patch.object(bandwidth,'FileLock',return_value=owner),patch.object(bandwidth.time,'monotonic',side_effect=(0,4)),self.assertRaises(TimeoutError):
            with self.budget._serialized():self.fail('mutex acquired despite refusal')
        owner.close.assert_called_once()
        owner.reset_mock();owner.acquire.return_value=True
        with patch.object(bandwidth,'FileLock',return_value=owner),self.assertRaisesRegex(RuntimeError,'body'):
            with self.budget._serialized():raise RuntimeError('body')
        owner.close.assert_called_once()

    def test_full_owner_capacity_refuses_without_changing_durable_credit(self):
        db=self.budget.db
        identities=[f'{index:032x}' for index in range(1024)]
        db.executemany('INSERT INTO byte_leases VALUES (?,0)',((identity,) for identity in identities))
        paths={self.budget.path.parent/('credit-'+identity+'.mutex') for identity in identities}
        original=db.execute('SELECT * FROM bucket').fetchall()
        # In-memory kernel ownership models all 1024 live peers. The actual
        # schema and public capacity remain unchanged; no credit can be issued.
        try:
            with patch.object(bandwidth,'_OWNED',paths),self.assertRaisesRegex(ValueError,'capacity exceeded'):
                next(self.budget.chunks(b'x',threading.Event()))
            self.assertEqual(db.execute('SELECT * FROM bucket').fetchall(),original)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM byte_leases').fetchone()[0],1024)
            self.assertIsNone(self.budget.credit_owner)
            self.assertTrue(self.budget.credit_failed)
            self.assertFalse(db.in_transaction)
        finally:db.execute('DELETE FROM byte_leases')

    def test_changed_owned_amount_cannot_settle_or_refund_cached_credit(self):
        # Two relay directions can own slices concurrently: one is still in
        # flight while the other has consumed the remainder of the grant.
        pending=self.budget.chunks(b'x',threading.Event())
        self.assertEqual(next(pending),b'x')
        self.assertEqual(list(self.budget.chunks(b'y'*1023,threading.Event())),[b'y'*1023])
        identity,_=self.budget.credit_owner
        db=self.budget.db
        original=db.execute('SELECT * FROM bucket').fetchall()
        amount=db.execute('SELECT amount FROM byte_leases WHERE id=?',(identity,)).fetchone()[0]
        db.execute('UPDATE byte_leases SET amount=? WHERE id=?',(amount-1,identity))
        try:
            with self.assertRaisesRegex(ValueError,'counters changed'):
                next(self.budget.chunks(b'z',threading.Event()))
            self.assertEqual(db.execute('SELECT * FROM bucket').fetchall(),original)
            self.assertTrue(self.budget.credit_failed)
            self.assertFalse(db.in_transaction)
        finally:
            db.execute('UPDATE byte_leases SET amount=? WHERE id=?',(amount,identity))
            pending.close()

    def test_vanished_owner_refuses_close_commit_but_releases_all_local_handles(self):
        self.assertEqual(list(self.budget.chunks(b'abc',threading.Event())),[b'abc'])
        _,owner=self.budget.credit_owner
        self.budget.db.execute('DELETE FROM byte_leases')
        with self.assertRaisesRegex(ValueError,'owner vanished'):self.budget.close()
        self.assertTrue(self.budget.closed)
        self.assertTrue(owner.stream.closed)
        self.assertIsNone(self.budget.credit_owner)
        # A second close is safe, but the failed settlement never turns into
        # a refund or a permission to transmit more bytes.
        self.budget.close()
        with self.assertRaises(ValueError):next(self.budget.chunks(b'x',threading.Event()))

    def test_stop_before_first_debit_does_not_touch_the_database(self):
        stop=threading.Event();stop.set()
        original=self.budget.db.execute('SELECT * FROM bucket').fetchall()
        self.assertFalse(self.budget.take(1,stop))
        self.assertEqual(list(self.budget.chunks(b'x',stop)),[])
        self.assertEqual(self.budget.db.execute('SELECT * FROM bucket').fetchall(),original)
