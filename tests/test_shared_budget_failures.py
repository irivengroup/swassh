"""Shared admission: policy bounds, corrupt durable leases and lock failures."""
import json
import os
from pathlib import Path
import sqlite3
import sys
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from swassh import Options
from swassh.infrastructure import bastion


class SharedPolicyBoundaryTests(unittest.TestCase):
    def test_invalid_specification_and_each_policy_bound_refuse_before_storage(self):
        spec={'directory':'synthetic','policy':[2,10,72*1024**2,1]}
        invalid=[None,[],{}, {**spec,'extra':1},{**spec,'directory':1},{**spec,'policy':()},
                 {**spec,'policy':[]},{**spec,'policy':[1]}]
        for index,values in enumerate(((True,'2',0,10001),(True,'10',0.09,1001,float('nan'),float('inf')),
                                       (True,'memory',72*1024**2-1,1048576*1024**2+1),
                                       (True,'1',0,2147483648))):
            for value in values:
                policy=list(spec['policy']);policy[index]=value;invalid.append({**spec,'policy':policy})
        with patch.object(bastion,'private_directory') as storage:
            for value in invalid:
                with self.subTest(value=value),self.assertRaises(ValueError):bastion.SharedBudget(value)
            storage.assert_not_called()

    def test_posix_and_windows_lock_protocols_and_unlock_failure_keep_ownership_honest(self):
        for platform in ('posix','nt'):
            for refused in (False,True):
                lock=object.__new__(bastion.FileLock)
                lock.path=Mock();lock.path.stat.return_value=SimpleNamespace(st_size=0)
                lock.stream=Mock(closed=False);lock.stream.fileno.return_value=10;lock.locked=False
                fake_os=SimpleNamespace(name=platform)
                flock=Mock(side_effect=BlockingIOError() if refused else None)
                fcntl=SimpleNamespace(flock=flock,LOCK_EX=2,LOCK_NB=4,LOCK_UN=8)
                windows=SimpleNamespace(locking=flock,LK_NBLCK=1,LK_UNLCK=2)
                with patch.object(bastion,'os',fake_os),patch.dict(sys.modules,{'fcntl':fcntl,'msvcrt':windows}):
                    self.assertIs(lock.acquire(),not refused)
                    self.assertEqual(lock.path in bastion._OWNED,not refused)
                    if platform=='nt':self.assertTrue(lock.stream.seek.called)
                    if not refused:
                        flock.side_effect=OSError('synthetic unlock error')
                        with self.assertRaisesRegex(OSError,'unlock'):lock.close()
                        self.assertNotIn(lock.path,bastion._OWNED)
                    else:lock.close()
                    lock.stream.close.assert_called_once()
                bastion._OWNED.discard(lock.path)


class SharedLeaseCorruptionIntegrationTests(unittest.TestCase):
    def test_full_live_queue_refuses_without_lowering_capacity_or_deleting_peers(self):
        identities = [format(index, '032x') for index in range(bastion.MAX_LEASES)]
        records = [(identity, 'client', 0, 0, 0, 0, None) for identity in identities]
        self.pool.db.executemany('INSERT INTO leases(id,kind,active,connections,memory,bandwidth,parent_id) VALUES (?,?,?,?,?,?,?)', records)
        owned = {self.pool.directory / (identity + '.lock') for identity in identities}
        # Model the OS locks of 1024 live peers. Durable rows and the actual
        # public capacity are unchanged; no peer may be evicted for admission.
        with patch.object(bastion, '_OWNED', owned), self.assertRaisesRegex(ValueError, 'queue is full'):
            self.pool.ticket(connections=1)
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 1024)
        self.assertFalse(self.pool.db.in_transaction)
        self.assertEqual(list(self.pool.directory.glob('*.lock')), [])
        self.pool.db.execute('DELETE FROM leases')

    def test_memory_parent_remains_charged_until_its_dependent_owner_closes(self):
        parent = self.pool.ticket(memory=1)
        self.assertTrue(parent.poll())
        child = self.pool.ticket(parent=parent.identity)
        try:
            parent.close()
            self.assertEqual(self.pool.db.execute('SELECT memory FROM leases WHERE id=?', (parent.identity,)).fetchone(), (1,))
            child.close()
            probe = self.pool.ticket(connections=1)
            try:
                self.assertIsNone(self.pool.db.execute('SELECT id FROM leases WHERE id=?', (parent.identity,)).fetchone())
            finally:
                probe.close()
        finally:
            child.close()

    def test_real_sqlite_faults_before_and_after_commit_remain_fatal_and_release_locks(self):
        real = self.pool.db
        class Fault:
            def __init__(self, query, after=False):
                self.query, self.after, self.failed = query, after, False
            def __getattr__(self, name):
                return getattr(real, name)
            def execute(self, query, *args):
                if query == self.query and not self.failed:
                    self.failed = True
                    if self.after:
                        real.execute(query, *args)
                    raise sqlite3.OperationalError('synthetic fatal storage fault')
                return real.execute(query, *args)
        self.pool.db = Fault('BEGIN IMMEDIATE')
        with self.assertRaisesRegex(sqlite3.OperationalError, 'fatal storage'):
            self.pool.ticket(connections=1)
        self.pool.db = real
        self.assertEqual(real.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)
        for phase, after in (('BEGIN IMMEDIATE', False), ('COMMIT', False), ('COMMIT', True)):
            lease = self.pool.ticket(connections=1)
            self.pool.db = Fault(phase, after)
            try:
                with self.subTest(operation='poll', phase=phase, after=after), \
                        self.assertRaisesRegex(sqlite3.OperationalError, 'fatal storage'):
                    lease.poll()
                self.assertFalse(real.in_transaction)
                self.assertEqual(real.execute('SELECT active FROM leases WHERE id=?', (lease.identity,)).fetchone()[0], int(after))
            finally:
                self.pool.db = real
                lease.close()
        for phase, after in (('BEGIN IMMEDIATE', False), ('COMMIT', False), ('COMMIT', True)):
            lease = self.pool.ticket(connections=1)
            self.pool.db = Fault(phase, after)
            try:
                with self.subTest(operation='close', phase=phase, after=after), \
                        self.assertRaisesRegex(sqlite3.OperationalError, 'fatal storage'):
                    lease.close()
                self.assertFalse(real.in_transaction)
                self.assertFalse(lease.lock.locked)
            finally:
                self.pool.db = real
            # A new real admission recovers only the now-unowned failed close.
            probe = self.pool.ticket(connections=1)
            probe.close()
        self.assertEqual(real.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.spec=bastion.specification(Options(budget_dir=self.temporary.name,bastion_concurrency=2,bastion_bandwidth_kib=1))
        self.pool=bastion.SharedBudget(self.spec);self.addCleanup(self.pool.close)

    def test_bad_durable_lease_fields_never_publish_a_new_reservation(self):
        columns=('id','kind','active','connections','memory','bandwidth','parent_id')
        original=('a'*32,'client',0,0,0,0,None)
        fields={'id':('short','A'*32,b'a'*32),'kind':('unknown',),'active':(2,-1),
                'connections':(-1,10001,1.5),'memory':(-1,1048576*1024**2+1,1.5),
                'bandwidth':(-1,2147483648,1.5),'parent_id':('short','A'*32,b'b'*32)}
        for field,values in fields.items():
            for value in values:
                with self.subTest(field=field,value=value):
                    record=list(original);record[columns.index(field)]=value
                    self.pool.db.execute('INSERT INTO leases('+','.join(columns)+') VALUES (?,?,?,?,?,?,?)',record)
                    with self.assertRaisesRegex(ValueError,'lease counters or identity'):self.pool.ticket(connections=1)
                    self.assertFalse(self.pool.db.in_transaction)
                    self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],1)
                    self.assertEqual(list(self.pool.directory.glob('*.lock')),[])
                    self.pool.db.execute('DELETE FROM leases')

    def test_ticket_amounts_limits_parent_and_vanished_lease_are_explicit_failures(self):
        for field in ('connections','memory','bandwidth'):
            for value in (True,1.5,'1',-1):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):self.pool.ticket(**{field:value})
        for values in ({},{'connections':3},{'memory':self.pool.policy[2]+1},{'bandwidth':2},
                       {'parent':'missing'},{'connections':1,'parent':'missing'},{'activate':1,'connections':1}):
            with self.subTest(values=values),self.assertRaises(ValueError):self.pool.ticket(**values)
        lease=self.pool.ticket(connections=1)
        try:
            with self.assertRaisesRegex(RuntimeError,'active transaction'):lease._admit()
            self.pool.db.execute('DELETE FROM leases WHERE id=?',(lease.identity,))
            with self.assertRaisesRegex(RuntimeError,'vanished'):lease.poll()
        finally:lease.close()
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],0)

    def test_policy_disappearance_and_replacement_leave_old_handles_unusable(self):
        row=self.pool.db.execute('SELECT value,next FROM policy WHERE id=1').fetchone()
        self.pool.db.execute('DELETE FROM policy')
        with self.assertRaisesRegex(ValueError,'policy changed'):self.pool.ticket(connections=1)
        self.pool.db.execute('INSERT INTO policy VALUES (1,?,?)',row)
        self.pool.db.execute("UPDATE policy SET value='[2,10,75497472,999]' WHERE id=1")
        with self.assertRaisesRegex(ValueError,'policy changed'):self.pool.ticket(connections=1)
        self.pool.db.execute('UPDATE policy SET value=? WHERE id=1',(row[0],))
        lease=self.pool.ticket(connections=1)
        try:self.assertTrue(lease.poll())
        finally:lease.close()

    def test_kernel_lock_refusal_removes_its_marker_and_rolls_back_the_queue(self):
        real=bastion.FileLock
        def denied(path):
            value=real(path);value.acquire=Mock(return_value=False);return value
        with patch.object(bastion,'FileLock',side_effect=denied),self.assertRaisesRegex(RuntimeError,'cannot own'):
            self.pool.ticket(connections=1)
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],0)
        self.assertEqual(list(self.pool.directory.glob('*.lock')),[])
        self.assertFalse(self.pool.db.in_transaction)

    def test_orphan_markers_are_retained_while_owned_and_removed_only_after_owner_exit(self):
        orphan=self.pool.directory/'orphan.lock'
        code=('import sys;from swassh.infrastructure.bastion import FileLock;'
              'lock=FileLock(sys.argv[1]);assert lock.acquire();sys.stdout.buffer.write(b"ready\\n");sys.stdout.buffer.flush();'
              'sys.stdin.buffer.read(1);lock.close()')
        child=subprocess.Popen([sys.executable,'-c',code,str(orphan)],stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            # communicate has a bounded deadline; do not block on readline if
            # child initialization fails before publishing readiness.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as reader:
                ready=reader.submit(child.stdout.readline)
                try:self.assertEqual(ready.result(timeout=5),b'ready\n')
                except BaseException:child.kill();raise
            lease=self.pool.ticket(connections=1)
            try:self.assertTrue(orphan.exists())
            finally:lease.close()
            _,error=child.communicate(b'x',timeout=5);self.assertEqual(child.returncode,0,error)
            lease=self.pool.ticket(connections=1)
            try:self.assertFalse(orphan.exists())
            finally:lease.close()
        finally:
            if child.poll() is None:child.kill();child.communicate(timeout=5)

    def test_excess_durable_leases_and_orphan_scan_are_bounded_before_publication(self):
        records=[(format(index,'032x'),'client',0,0,0,0,None) for index in range(bastion.MAX_LEASES+1)]
        self.pool.db.executemany('INSERT INTO leases(id,kind,active,connections,memory,bandwidth,parent_id) VALUES (?,?,?,?,?,?,?)',records)
        with self.assertRaisesRegex(ValueError,'too many leases'):self.pool.ticket(connections=1)
        self.assertEqual(self.pool.db.execute('SELECT count(*) FROM leases').fetchone()[0],bastion.MAX_LEASES+1)
        self.assertFalse(self.pool.db.in_transaction)
        self.pool.db.execute('DELETE FROM leases')
        original_glob=Path.glob;real_lock=bastion.FileLock;opened=[]
        def glob(path,pattern):
            if path==self.pool.directory and pattern=='*.lock':
                return (path/('synthetic-orphan-'+str(index)+'.lock') for index in range(bastion.MAX_LEASES*2+1))
            return original_glob(path,pattern)
        def lock(path):
            if Path(path).name.startswith('synthetic-orphan-'):
                opened.append(path);return Mock(acquire=Mock(return_value=False))
            return real_lock(path)
        with patch.object(Path,'glob',glob),patch.object(bastion,'FileLock',side_effect=lock):
            with self.assertRaisesRegex(ValueError,'too many orphan'):self.pool.ticket(connections=1)
        self.assertEqual(len(opened),bastion.MAX_LEASES*2)
        self.assertEqual(self.pool.db.execute('SELECT count(*) FROM leases').fetchone()[0],0)
        self.assertEqual(list(self.pool.directory.glob('*.lock')),[])

    def test_oversized_database_is_refused_before_sqlite_recovery(self):
        path=self.pool.directory/'budget.sqlite3';self.pool.close()
        with path.open('r+b') as stream:stream.truncate(8*1024**2+1)
        with patch.object(bastion.sqlite3,'connect') as connect:
            with self.assertRaisesRegex(ValueError,'disk ceiling'):bastion.SharedBudget(self.spec)
        connect.assert_not_called()


class LegacyBudgetMigrationIntegrationTests(unittest.TestCase):
    def test_legacy_parent_column_and_clock_migrate_without_releasing_reserved_pacing(self):
        with tempfile.TemporaryDirectory() as directory:
            spec=bastion.specification(Options(budget_dir=directory));folder=Path(spec['directory']);folder.mkdir(mode=0o700)
            db=sqlite3.connect(folder/'budget.sqlite3')
            # A legal legacy reservation is at most concurrency/rate ahead.
            # Freeze the adapter clock so file-system speed cannot cross it.
            future=101.0
            try:
                db.executescript('CREATE TABLE policy(id INTEGER PRIMARY KEY,value TEXT NOT NULL,next REAL NOT NULL);'
                    'CREATE TABLE leases(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,'
                    'active INTEGER NOT NULL,connections INTEGER NOT NULL,memory INTEGER NOT NULL,bandwidth INTEGER NOT NULL);')
                db.execute('INSERT INTO policy VALUES (1,?,?)',(json.dumps(spec['policy']),future));db.commit()
            finally:db.close()
            clock=SimpleNamespace(monotonic=lambda:100.0,sleep=Mock(side_effect=AssertionError('unexpected private database contention')))
            with patch.object(bastion,'time',clock):
                pool=bastion.SharedBudget(spec)
                try:
                    self.assertIn('parent_id',{row[1] for row in pool.db.execute('PRAGMA table_info(leases)')})
                    self.assertEqual(pool.db.execute('SELECT next FROM policy').fetchone()[0],future)
                    expected=max(0,future-spec['policy'][0]/spec['policy'][1])
                    self.assertEqual(pool.db.execute('SELECT observed FROM clock').fetchone()[0],expected)
                    lease=pool.ticket(connections=1)
                    try:self.assertFalse(lease.poll())
                    finally:lease.close()
                finally:pool.close()



class ClosedLeaseRecoveryTests(unittest.TestCase):
    """Real files and SQLite distinguish a closed lease from an open failure."""

    class CloseFault:
        def __init__(self, stream, error, *, after):
            self.stream, self.error, self.after, self.calls = stream, error, after, 0

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def close(self):
            self.calls += 1
            if self.after:
                self.stream.close()
            raise self.error

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='swassh-close-state-')
        self.addCleanup(temporary.cleanup)
        self.pool = bastion.SharedBudget({'directory': temporary.name,
            'policy': [1, 1000, 72 * 1024**2, 1]})
        self.addCleanup(self.pool.close)

    def peer_can_lock(self, path):
        # A distinct process checks the OS lock without changing this process's
        # ownership registry. It uses the same source installation as the test.
        code = ('import json,sys;from swassh.infrastructure.bastion import FileLock;'
                'lock=FileLock(sys.argv[1]);acquired=lock.acquire();lock.close();'
                'print(json.dumps(acquired))')
        result = subprocess.run([sys.executable, '-B', '-c', code, str(path)],
            capture_output=True, timeout=10, check=True)
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def test_error_after_real_close_reclaims_only_the_released_capacity(self):
        first = self.pool.ticket(connections=1)
        self.assertTrue(first.poll())
        error = OSError('close reported failure after releasing the descriptor')
        fault = self.CloseFault(first.lock.stream, error, after=True)
        first.lock.stream = fault
        self.addCleanup(first.close)
        with self.assertRaises(OSError) as raised:
            first.close()
        self.assertIs(raised.exception, error)
        self.assertTrue(fault.closed)
        self.assertEqual(fault.calls, 1)
        self.assertTrue(self.peer_can_lock(first.lock.path))
        self.assertFalse(self.pool.db.in_transaction)
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases WHERE id=?',
            (first.identity,)).fetchone()[0], 1, 'failed transaction must still roll back')
        self.assertNotIn(first.lock.path, bastion._OWNED)
        self.assertFalse(first.lock.locked)
        second = self.pool.ticket(connections=1)
        self.addCleanup(second.close)
        self.assertTrue(second.poll(), 'a closed failed lease must not consume the only slot')
        self.assertIsNone(self.pool.db.execute('SELECT id FROM leases WHERE id=?',
            (first.identity,)).fetchone())
        self.assertEqual(self.pool.policy, [1, 1000.0, 72 * 1024**2, 1])

    def test_error_with_stream_still_open_preserves_the_reservation_and_error(self):
        first = self.pool.ticket(connections=1)
        self.assertTrue(first.poll())
        real = first.lock.stream
        error = OSError('close refused before releasing the descriptor')
        fault = self.CloseFault(real, error, after=False)
        first.lock.stream = fault
        try:
            with self.assertRaises(OSError) as raised:
                first.close()
            self.assertIs(raised.exception, error)
            self.assertFalse(real.closed)
            self.assertEqual(fault.calls, 2, 'the existing finally cleanup is preserved')
            self.assertIn(first.lock.path, bastion._OWNED)
            self.assertTrue(first.lock.locked)
            self.assertFalse(self.pool.db.in_transaction)
            second = self.pool.ticket(connections=1)
            try:
                self.assertFalse(second.poll(), 'an open failed close must retain its slot')
                # A peer observation also lets the unmodified rate budget elapse.
                self.assertTrue(self.peer_can_lock(first.lock.path))
                self.assertFalse(second.poll(), 'local ownership must remain authoritative')
                first.lock.stream = real
                # Windows rejects a second explicit unlock; reacquire the real
                # lock before normal cleanup, without changing the close code.
                self.assertTrue(first.lock.acquire())
                first.close()
                self.assertTrue(second.poll())
            finally:
                second.close()
        finally:
            first.lock.stream = real
            if not real.closed:
                self.assertTrue(first.lock.acquire())
            first.close()

    def test_repeated_close_after_error_cannot_close_a_different_live_lock(self):
        first = bastion.FileLock(self.pool.directory / 'first.lock')
        self.assertTrue(first.acquire())
        error = OSError('closed descriptor error')
        fault = self.CloseFault(first.stream, error, after=True)
        first.stream = fault
        with self.assertRaises(OSError) as raised:
            first.close()
        self.assertIs(raised.exception, error)
        second = bastion.FileLock(self.pool.directory / 'second.lock')
        try:
            self.assertTrue(second.acquire())
            first.close()
            self.assertEqual(fault.calls, 1)
            self.assertNotIn(first.path, bastion._OWNED)
            self.assertIn(second.path, bastion._OWNED)
            self.assertFalse(second.stream.closed)
            self.assertFalse(self.peer_can_lock(second.path))
        finally:
            # The discard also isolates the failing before-correction run.
            bastion._OWNED.discard(first.path)
            second.close()
