"""Security boundaries and durable admission without changing SSH fleet semantics."""
import contextlib
import errno
import gzip
import json
import os
import shutil
import subprocess
import sqlite3
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Options, Result, Status, Swarm, Report, ScheduleError, JobState
from swassh.application.pacing import ConnectionPacer
from swassh.application.schedule_contracts import ScheduledInvocation
from swassh.application.scheduling import SchedulingService
from swassh.application.transfer_settings import TransferSettings
from swassh.domain.transfers import FileTransfer, TransferDirection
from swassh.infrastructure.audit import AuditTrail, _compress
from swassh.infrastructure.filesystem import private_directory, open_private_append, trusted_parents, sync_directory
from swassh.infrastructure.process_reporter import ProcessReportWriter
from swassh.infrastructure.schedule_store import SQLiteScheduleStore, encode_invocation, decode_invocation
from swassh.infrastructure.spool import ReportStore
from swassh.infrastructure.ssh import _config
from swassh.infrastructure.transfers import NativeFileTransport


class AdmissionInputTests(unittest.TestCase):
    def test_pacer_and_jump_reject_unrepresentable_intervals(self):
        for value in (0, -1, True, float('nan'), float('inf'), '20', 1e-320, 10**1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ConnectionPacer(value)
        for value in (1e-320, 1e-308):
            with self.assertRaises(ValueError):
                Options(connect_rate=value, jump_host=Host('gateway'))
        for name in ('connect_timeout', 'command_timeout', 'connect_rate', 'report_timeout', 'retry_delay'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                Options(**{name: 10**1000})
        ConnectionPacer(20)
        Options(connect_rate=1e-308)

    def test_native_config_does_not_mutate_hostkeys_or_agent(self):
        for jump in (None, Host('gateway')):
            config = _config(Host('node'), Options(jump_host=jump))
            for option in ('UpdateHostKeys no', 'VerifyHostKeyDNS no', 'AddKeysToAgent no',
                           'Tunnel no', 'EscapeChar none', 'StrictHostKeyChecking yes'):
                self.assertIn(option, config)


    @unittest.skipUnless(shutil.which('ssh'), 'native OpenSSH config parser required')
    def test_security_config_accepted_by_native_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config'
            path.write_text(_config(Host('example'), Options(jump_host=Host('gateway'))))
            completed = subprocess.run([shutil.which('ssh'), '-G', '-F', str(path), 'swassh-target'],
                                       capture_output=True, text=True, timeout=5)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            fields = dict(line.split(' ', 1) for line in completed.stdout.splitlines())
            for key in ('updatehostkeys', 'verifyhostkeydns', 'addkeystoagent'):
                self.assertIn(fields[key], {'no', 'false'})
            self.assertIn(fields['tunnel'], {'false', 'no'})

@unittest.skipUnless(os.name == 'posix', 'POSIX ancestry and filesystem semantics')
class AncestryTests(unittest.TestCase):
    def test_shared_parent_rejected_before_creation_or_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / 'shared'
            shared.mkdir()
            shared.chmod(0o777)
            child = shared / 'new' / 'private'
            with self.assertRaisesRegex(ValueError, 'shared writable'):
                private_directory(child)
            self.assertFalse((shared / 'new').exists())
            report = Report('x', (Result(Host('a'), Status.SUCCESS),), datetime.now(UTC), datetime.now(UTC))
            final = shared / 'report.json'
            final.write_text('preserve')
            with self.assertRaises(ValueError):
                report.write(final)
            self.assertEqual(final.read_text(), 'preserve')
            with self.assertRaises(ValueError):
                ReportStore(shared, 1024**2)
            self.assertEqual(list(shared.iterdir()), [final])
            with self.assertRaises(ValueError):
                open_private_append(shared / 'audit')

    def test_trusted_alias_supported_and_alias_to_shared_parent_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted = root / 'trusted'
            trusted.mkdir(mode=0o700)
            alias = root / 'alias'
            alias.symlink_to(trusted, target_is_directory=True)
            self.assertEqual(private_directory(alias / 'child'), (trusted / 'child').resolve())
            with self.assertRaises(ValueError):
                private_directory(alias)
            trusted.chmod(0o777)
            with self.assertRaises(ValueError):
                trusted_parents(alias / 'audit')

    def test_untrusted_owner_and_non_directory_parent_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = Path.lstat
            def altered(path):
                info = original(path)
                if path == root:
                    fields = list(info)
                    fields[4] = 987654
                    return os.stat_result(fields)
                return info
            with patch.object(Path, 'lstat', altered), self.assertRaisesRegex(ValueError, 'owned'):
                trusted_parents(root / 'file')
            regular = root / 'regular'
            regular.write_text('data')
            with self.assertRaises(ValueError):
                trusted_parents(regular / 'file')

    def test_directory_sync_supported_errors_are_distinguished(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsInstance(sync_directory(directory), bool)
            with patch('os.fsync', side_effect=OSError(errno.EINVAL, 'unsupported')):
                self.assertFalse(sync_directory(directory))
            with patch('os.fsync', side_effect=OSError(errno.EIO, 'failure')), self.assertRaises(OSError):
                sync_directory(directory)

    def test_gzip_archive_is_synced_after_trailer_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / 'audit', root / 'audit.1.gz'
            source.write_bytes(b'record\n' * 100)
            original = os.fsync
            saw_synced_archive = []
            def sync(fd):
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    temporary = next(root.glob('.swassh-gzip-*'))
                    saw_synced_archive.append(gzip.decompress(temporary.read_bytes()))
                    self.assertFalse(target.exists())
                return original(fd)
            with patch('os.fsync', sync):
                _compress(str(source), str(target))
            self.assertEqual(saw_synced_archive, [b'record\n' * 100])
            self.assertFalse(source.exists())
            self.assertEqual(gzip.decompress(target.read_bytes()), b'record\n' * 100)


class SchedulerSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime.now(UTC)
        self.due = self.now + timedelta(seconds=10)
        self.id = 'a' * 32
        self.addCleanup(self.temp.cleanup)
        self.store = SQLiteScheduleStore(self.root / 'state')
        self.addCleanup(self.store.close)
        self.invocation = ScheduledInvocation('secret', (Host('a'),), Options(), str(self.root / 'report.json'))

    def create(self):
        return self.store.create(self.id, self.invocation, self.due, self.now, 300)

    def test_valid_version_one_reopens_without_migration_or_data_loss(self):
        job = self.create()
        with contextlib.closing(SQLiteScheduleStore(self.root / 'state')) as store:
            self.assertEqual(store.get(job.id), job)
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], 1)
            if sqlite3.sqlite_version_info >= (3, 31, 0):
                self.assertEqual(store.db.execute('PRAGMA trusted_schema').fetchone()[0], 0)

    def test_claim_refuses_corrupt_calendar_and_continues_without_dispatch(self):
        self.create()
        self.store.db.execute('UPDATE jobs SET created_at=? WHERE id=?', (self.due.isoformat(timespec='microseconds'), self.id))
        self.assertIsNone(self.store.claim_due(self.due))
        row = self.store.db.execute('SELECT state,reason FROM jobs WHERE id=?', (self.id,)).fetchone()
        self.assertEqual(tuple(row), ('failed', 'invalid_job_snapshot'))

    def test_canonical_timestamp_required(self):
        self.create()
        self.store.db.execute('UPDATE jobs SET due_at=? WHERE id=?', (self.due.replace(tzinfo=None).isoformat(), self.id))
        with self.assertRaises(ScheduleError):
            self.store.get(self.id)
        self.assertIsNone(self.store.claim_due(self.due))

    def test_schema_mutation_blocked_before_trigger_can_fire(self):
        self.create()
        self.store.db.execute("CREATE TRIGGER change_state AFTER UPDATE ON jobs BEGIN DELETE FROM events; END")
        with self.assertRaisesRegex(ScheduleError, 'schema changed'):
            self.store.claim_due(self.due)
        with self.assertRaises(ScheduleError):
            self.store.get(self.id)
        with self.assertRaises(ScheduleError):
            self.store.list()
        with self.assertRaises(ScheduleError):
            self.store.events()
        self.assertEqual(self.store.db.execute('SELECT state FROM jobs').fetchone()[0], 'pending')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
        with self.assertRaisesRegex(ScheduleError, 'executable objects'):
            SQLiteScheduleStore(self.root / 'state')

    def test_missing_columns_rejected_despite_valid_header(self):
        with contextlib.closing(SQLiteScheduleStore(self.root / 'wrong')) as store:
            store.db.execute('ALTER TABLE events RENAME TO original_events')
            store.db.execute('CREATE TABLE events(seq INTEGER PRIMARY KEY)')
        with self.assertRaisesRegex(ScheduleError, 'table schema'):
            SQLiteScheduleStore(self.root / 'wrong')

    def test_jump_schema_and_job_counters_are_strict(self):
        raw = json.loads(encode_invocation(self.invocation))
        raw['options']['jump_host'] = {'hostname': 'gateway'}
        with self.assertRaises(ScheduleError):
            decode_invocation(json.dumps(raw))
        job = self.create()
        for changes in ({'command_sha256': 'bad'}, {'counts': {'success': True}},
                        {'started_at': datetime.now()}, {'run_id': 'bad'}):
            with self.subTest(changes=changes), self.assertRaises(ScheduleError):
                replace(job, **changes)
        counts = {status.value: 0 for status in Status}
        counts['success'] = 1
        replace(job, counts=counts, started_at=self.due, finished_at=self.due, run_id='b' * 32)


class DurableAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_and_phase_markers_synced_before_ssh_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit'
            synced = []
            original = os.fsync
            def sync(fd):
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    synced[:] = [json.loads(line)['event'] for line in path.read_text().splitlines()]
                return original(fd)
            calls = []
            class Transport:
                async def execute(self, host, command):
                    calls.append(host.hostname)
                    required = 'canary_started' if host.hostname == 'a' else 'fleet_started'
                    if required not in synced:
                        raise AssertionError('SSH admitted before durable audit checkpoint')
                    return Result(host, Status.SUCCESS)
            with patch('os.fsync', sync):
                report = await Swarm(Options(log_file=str(path)), transport=Transport()).run(['a', 'b'], 'x')
            self.assertTrue(report.ok)
            self.assertEqual(calls, ['a', 'b'])
            self.assertIn('run_started', synced)
            self.assertNotIn('\"command\":', path.read_text().splitlines()[0])

    async def test_audit_sync_failure_blocks_all_connections(self):
        class Transport:
            calls = 0
            async def execute(self, host, command):
                self.calls += 1
                return Result(host, Status.SUCCESS)
        with tempfile.TemporaryDirectory() as directory:
            transport = Transport()
            with patch('os.fsync', side_effect=OSError(errno.ENOSPC, 'full')), self.assertRaises(OSError):
                await Swarm(Options(log_file=str(Path(directory) / 'audit')), transport=transport).run(['a', 'b'], 'x')
            self.assertEqual(transport.calls, 0)

    async def test_outbox_kept_when_fsync_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.closing(SQLiteScheduleStore(root / 'state')) as store:
                now = datetime.now(UTC)
                store.create('a' * 32, ScheduledInvocation('secret', (Host('a'),), Options(), str(root / 'report.json')),
                             now + timedelta(seconds=5), now, 300)
                calls = []
                async def execute(job):
                    calls.append(job.info.id)
                service = SchedulingService(store, execute, audit_factory=AuditTrail,
                    audit_path=str(root / 'scheduler.jsonl'))
                with patch('os.fsync', side_effect=OSError(errno.EIO, 'failure')), self.assertRaises(OSError):
                    await service.serve(once=True)
                self.assertTrue(store.events())
                self.assertEqual(store.get('a' * 32).state, JobState.PENDING)
                self.assertEqual(calls, [])

    async def test_sync_is_batched_outside_asyncio_loop(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit'
            original = os.fsync
            calls = []
            def sync(fd):
                calls.append(threading.get_ident())
                return original(fd)
            with patch('os.fsync', sync):
                async with AuditTrail(str(path), 'run') as audit:
                    for i in range(130):
                        await audit.emit('event', {'i': i})
            self.assertTrue(calls)
            self.assertTrue(all(thread != threading.get_ident() for thread in calls))
            regular_calls = len(calls) - (1 if os.name == 'posix' else 0)
            self.assertEqual(regular_calls, 3)
            self.assertEqual(len(path.read_text().splitlines()), 130)

    async def test_unsafe_report_with_safe_spool_rejected_before_ssh(self):
        if os.name != 'posix':
            self.skipTest('POSIX permission checks')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / 'shared'
            shared.mkdir()
            shared.chmod(0o777)
            calls = []
            class Transport:
                async def execute(self, host, command):
                    calls.append(host.hostname)
                    return Result(host, Status.SUCCESS)
            for output in (shared / 'report.json', root / 'missing' / 'report.json', root):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    await Swarm(transport=Transport()).run_to_file(['a'], 'x', output, spool_dir=root)
            self.assertEqual(calls, [])
            self.assertEqual(list(shared.iterdir()), [])
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['shared'])

    async def test_unsafe_spool_rejected_before_worker_or_transport(self):
        if os.name != 'posix':
            self.skipTest('POSIX permission checks')
        with tempfile.TemporaryDirectory() as directory:
            shared = Path(directory) / 'shared'
            shared.mkdir()
            shared.chmod(0o777)
            writer = ProcessReportWriter(shared, 1024**2)
            with self.assertRaises(ValueError):
                await writer.__aenter__()
            self.assertIsNone(writer.worker_pid)
            self.assertEqual(list(shared.iterdir()), [])

    async def test_source_changed_between_stat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'original')
            initial = source.stat()
            original = os.open
            changed = []
            def open_source(path, *args, **kwargs):
                if Path(path) == source and not changed:
                    changed.append(True)
                    source.write_bytes(b'modified')
                    os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1000000))
                return original(path, *args, **kwargs)
            client = NativeFileTransport(Options(ssh_executable=sys.executable),
                TransferSettings(rsync_executable='absent-rsync'),
                FileTransfer(TransferDirection.PUSH, str(source), '/srv/file'), 100)
            with patch('os.open', open_source), self.assertRaisesRegex(ValueError, 'before snapshot'):
                await client.__aenter__()
            self.assertIsNone(client._directory)
            self.assertEqual(changed, [True])

    async def test_native_staging_links_are_rejected_while_download_runs(self):
        if os.name != 'posix':
            self.skipTest('POSIX link creation')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'data'
            stage.touch()
            code = ('import os,time; os.symlink("/etc/passwd",' + repr(str(root / 'linked')) + '); time.sleep(30)')
            client = NativeFileTransport(Options(ssh_executable=sys.executable), TransferSettings(timeout=2),
                FileTransfer(TransferDirection.PULL, str(root), '/remote'), 100)
            result = await client._run([sys.executable, '-c', code], Host('node'), watched=stage)
            self.assertEqual(result.status, Status.ERROR)
            self.assertLess(result.duration, 2)
