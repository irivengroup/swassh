"""Scheduling invariants: UTC, snapshots, private storage and no replay."""
import asyncio
import contextlib
import copy
import hashlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock,Mock,patch
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from swassh import Host, Options, JobState, ScheduleError, Scheduler, parse_schedule_time
from swassh.application.contracts import RunSummary
from swassh.application.schedule_contracts import ScheduledInvocation
from swassh.application.schedule_contracts import ExecutionFailure
from swassh.application.scheduling import SchedulingService
from swassh.infrastructure.audit import AuditTrail
from swassh.infrastructure.resources import resource_plan
from swassh.infrastructure.schedule_store import SQLiteScheduleStore, decode_invocation, encode_invocation
from swassh.infrastructure.scheduled_execution import prepare_invocation, SwarmScheduledExecutor
from swassh.interfaces import cli
from swassh.interfaces import scheduling as scheduling_api
from swassh.interfaces.scheduling import run_worker

NOW = datetime(2030, 1, 1, tzinfo=UTC)
DUE = NOW + timedelta(seconds=10)
FIRST, SECOND = 'a' * 32, 'b' * 32


def invocation(root, hosts=1, command='opaque-secret-command', **options):
    return ScheduledInvocation(command, tuple(Host(f'srv-{i}') for i in range(hosts)),
        Options(**options), str(Path(root) / 'report.json'))


def summary(job, success=True):
    from swassh.domain.models import Status
    counts = {status.value: 0 for status in Status}
    counts['success' if success else 'failed'] = job.info.host_count
    return RunSummary(job.info.host_count, counts, NOW, DUE, resource_plan(job.invocation.options),
                      run_id='c' * 32)


class TimeTests(unittest.TestCase):
    def test_utc_offsets_and_precision(self):
        self.assertEqual(parse_schedule_time('2030-01-01 00:00'), NOW)
        for date, zone in [('2030-01-01T02:00+02:00', None), ('2030-01-01 02:00', '+02:00'),
                           ('2029-12-31 20:00', '-04:00'), ('2030-01-01T00:00Z', None)]:
            self.assertEqual(parse_schedule_time(date, zone), NOW)
        self.assertEqual(parse_schedule_time('2030-01-01 00:00:00.123456', 'UTC').microsecond, 123456)
        self.assertEqual(parse_schedule_time('2030-01-01 00:00', 'Z'), NOW)

    def test_invalid_dates_zones_and_fold(self):
        cases = [('2030-02-30 12:00', None, None), ('2030-01-01', None, None),
                 ('2030-01-01 12:00Z', 'UTC', None), ('2030-01-01 12:00Z', None, 1),
                 ('2030-01-01 12:00', 'UTC', 0), ('2030-01-01 12:00', '+01:00', 0),
                 ('2030-01-01 12:00', '+24:00', None), ('2030-01-01 12:00', '+01:99', None),
                 ('2030-01-01T12:00+01:99', None, None), ('2030-01-01 12:00', 'Nonexistent/Zone', None),
                 ('2030-01-01 12:00', [], None), ('2030-01-01 12:00', None, True),
                 ('2030-01-01 12:00', None, 2), ('0001-01-01T00:00+02:00', None, None)]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ScheduleError):
                parse_schedule_time(*values)

    def test_iana_dst_and_nonexistent_time(self):
        try:
            ZoneInfo('Europe/Paris')
        except ZoneInfoNotFoundError:
            self.skipTest('system IANA timezone database unavailable')
        self.assertEqual(parse_schedule_time('2030-01-01 01:00', 'Europe/Paris'), NOW)
        self.assertEqual(parse_schedule_time('2026-07-01 02:00', 'Europe/Paris').hour, 0)
        with self.assertRaisesRegex(ScheduleError, 'ambiguous'):
            parse_schedule_time('2026-10-25 02:30', 'Europe/Paris')
        first = parse_schedule_time('2026-10-25 02:30', 'Europe/Paris', 0)
        second = parse_schedule_time('2026-10-25 02:30', 'Europe/Paris', 1)
        self.assertEqual(second - first, timedelta(hours=1))
        with self.assertRaisesRegex(ScheduleError, 'does not exist'):
            parse_schedule_time('2026-03-29 02:30', 'Europe/Paris', 0)


class SnapshotBoundaryTests(unittest.TestCase):
    """Pure persisted-input contracts; no database, path creation or SSH."""

    def setUp(self):
        self.value = invocation(Path.cwd(), command='read')
        self.data = json.loads(encode_invocation(self.value))

    def test_required_snapshot_fields_and_excessive_host_count_are_rejected(self):
        malformed = []
        missing = copy.deepcopy(self.data)
        missing.pop('spool_dir')
        malformed.append(missing)
        malformed.append({**self.data, 'unexpected': 1})
        malformed.append({**self.data, 'hosts': [self.data['hosts'][0]] * 100001})
        for index, data in enumerate(malformed):
            with self.subTest(case=index), self.assertRaises(ScheduleError):
                decode_invocation(json.dumps(data))
        self.assertEqual(decode_invocation(encode_invocation(self.value)), self.value)

    def test_non_mapping_hosts_and_incomplete_or_extended_options_are_rejected(self):
        for host in (None, False, 1, 'node', []):
            data = {**self.data, 'hosts': [host]}
            with self.subTest(host=type(host).__name__), self.assertRaises(ScheduleError):
                decode_invocation(json.dumps(data))
        for mutation in ('missing-required', 'unknown-option', 'null-keys', 'text-keys', 'mapping-keys'):
            data = copy.deepcopy(self.data)
            options = data['options']
            if mutation == 'missing-required':
                options.pop('concurrency')
            elif mutation == 'unknown-option':
                options['unexpected'] = 1
            else:
                options['client_keys'] = {'null-keys': None, 'text-keys': 'key', 'mapping-keys': {}}[mutation]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ScheduleError, '^invalid scheduled option schema$'):
                decode_invocation(json.dumps(data))

    def test_jump_host_schema_is_checked_before_constructing_options(self):
        for jump in ('gateway', [], False, {'hostname': 'gateway'}):
            data = copy.deepcopy(self.data)
            data['options']['jump_host'] = jump
            with self.subTest(jump=type(jump).__name__), self.assertRaisesRegex(ScheduleError, '^invalid scheduled jump host schema$'):
                decode_invocation(json.dumps(data))

    def test_real_payload_byte_limit_accepts_the_boundary_and_refuses_one_extra_byte(self):
        from swassh.infrastructure import schedule_store as storage
        self.assertEqual(storage.MAX_PAYLOAD_BYTES, 10 * 1024**2)
        overhead = len(encode_invocation(self.value).encode('utf-8'))
        # The executable text is constructor-valid and never resolved here.
        # Exercise the real 10 MiB serialization limit, without lowering it or
        # allocating a huge host fleet just to produce the same bounded input.
        options = replace(self.value.options,
                          ssh_executable=self.value.options.ssh_executable + 'x' * (storage.MAX_PAYLOAD_BYTES - overhead))
        boundary = replace(self.value, options=options)
        self.assertEqual(len(encode_invocation(boundary).encode('utf-8')), storage.MAX_PAYLOAD_BYTES)
        with self.assertRaisesRegex(ScheduleError, '^scheduled inventory/options snapshot exceeds 10 MiB$'):
            encode_invocation(replace(boundary, command=boundary.command + 'x'))

    def test_invalid_store_capacity_is_rejected_before_any_storage_access(self):
        from swassh.infrastructure import schedule_store as storage
        invalid = [{'max_jobs': value} for value in (None, False, True, 1.0, storage.MAX_JOBS + 1)]
        invalid += [{'max_bytes': value} for value in (None, '65536', 65536.0, storage.MAX_STORE_BYTES + 1)]
        with patch.object(storage, 'private_directory', side_effect=AssertionError('storage must not open')) as directory:
            for values in invalid:
                with self.subTest(values=values), self.assertRaisesRegex(ScheduleError, '^invalid scheduler store capacity$'):
                    SQLiteScheduleStore('memory-only', **values)
        directory.assert_not_called()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SQLiteScheduleStore(self.root / 'state')
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.store.close)

    def create(self, id=FIRST, **kwargs):
        return self.store.create(id, invocation(self.root, **kwargs), DUE, NOW, 300)

    def test_snapshot_schema_roundtrip_and_bounds(self):
        value = invocation(self.root, hosts=10001, canary=5, username='admin',
                           client_keys=('/absolute/key',), jump_host=Host('gateway'))
        self.assertEqual(decode_invocation(encode_invocation(value)), value)
        for changes in ({'hosts': []}, {'hosts': [{}]}, {'options': []}, {'format': 'pickle'},
                        {'report_path': None}, {'report_path': 'relative'}, {'schema_version': 2}, {'schema_version': True}):
            data = json.loads(encode_invocation(value))
            data.update(changes)
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                decode_invocation(json.dumps(data))
        for payload in ('{"x":1,"x":2}', '{"x":NaN}', '[]', 'x' * (10 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                decode_invocation(payload)
        with self.assertRaises(ScheduleError):
            ScheduledInvocation('x', (Host('a'), Host('a')), Options(), str(self.root / 'report'))
        with self.assertRaises(ScheduleError):
            replace(value, options=None)
        with self.assertRaises(ScheduleError):
            replace(value, report_path=str(self.root / 'a\n'))

    def test_persistent_claim_finish_and_no_replay(self):
        self.create(hosts=2, canary=5)
        with contextlib.closing(SQLiteScheduleStore(self.root / 'state')) as second:
            self.assertEqual(second.get(FIRST).host_count, 2)
            self.assertIsNone(second.claim_due(NOW))
            job = second.claim_due(DUE)
            self.assertEqual(job.info.state, JobState.RUNNING)
            self.assertIsNone(self.store.claim_due(DUE))
            finished = second.finish(FIRST, JobState.SUCCEEDED, DUE, summary=summary(job))
            self.assertEqual(finished.counts['success'], 2)
            self.assertEqual(finished.run_id, 'c' * 32)
        self.assertIsNone(self.store.claim_due(DUE))
        with self.assertRaises(ScheduleError):
            self.store.finish(FIRST, JobState.FAILED, DUE)

    def test_cancel_purge_and_metadata_listing(self):
        self.create()
        self.create(SECOND)
        self.assertEqual(len(self.store.list(1, 1)), 1)
        self.assertEqual(self.store.cancel(FIRST, NOW).state, JobState.CANCELLED)
        self.store.purge(FIRST, NOW)
        with self.assertRaises(ScheduleError):
            self.store.get(FIRST)
        with self.assertRaises(ScheduleError):
            self.store.purge(SECOND, NOW)
        job = self.store.claim_due(DUE)
        self.assertEqual(job.info.id, SECOND)
        with self.assertRaises(ScheduleError):
            self.store.cancel(SECOND, DUE)
        self.store.finish(SECOND, JobState.FAILED, DUE, reason='test')
        self.assertEqual(len(self.store.list()), 1)
        for limit, offset in [(0, 0), (201, 0), (True, 0), (1, -1), (1, True)]:
            with self.assertRaises(ScheduleError):
                self.store.list(limit, offset)
        with self.assertRaises(ScheduleError):
            self.store.get('../escape')

    def test_recovery_and_misfire_never_replay(self):
        self.create()
        self.store.claim_due(DUE)
        self.assertEqual(self.store.recover_running(DUE), 1)
        self.assertEqual(self.store.recover_running(DUE), 0)
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)
        self.assertIsNone(self.store.claim_due(DUE))
        self.create(SECOND)
        self.assertIsNone(self.store.claim_due(DUE + timedelta(seconds=301)))
        self.assertEqual(self.store.get(SECOND).state, JobState.MISSED)

    def test_invalid_scalar_types_do_not_create_jobs_or_consume_events(self):
        before = self.store.events()
        for grace in (None, '300', 300.0):
            with self.subTest(grace=grace), self.assertRaises(ScheduleError):
                self.store.create(FIRST, invocation(self.root), DUE, NOW, grace)
        for field in ('limit', 'offset'):
            for value in (None, '1', 1.0):
                with self.subTest(field=field, value=value), self.assertRaises(ScheduleError):
                    self.store.list(**{field: value})
        for limit in (None, '1', 1.0):
            with self.subTest(limit=limit), self.assertRaises(ScheduleError):
                self.store.events(limit)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(self.store.events(), before)

    def test_invalid_finish_diagnostics_cannot_change_a_pending_job(self):
        self.create()
        before = self.store.events()
        diagnostic = ExecutionFailure.capture(ValueError('synthetic private detail'))
        for value, state in (('private-detail', JobState.FAILED), (diagnostic, JobState.SUCCEEDED)):
            with self.subTest(state=state), self.assertRaisesRegex(ScheduleError, '^invalid execution diagnostic$'):
                self.store.finish(FIRST, state, DUE, diagnostic=value)
        self.assertEqual(self.store.get(FIRST).state, JobState.PENDING)
        self.assertEqual(self.store.events(), before)

    def test_invalid_counter_values_roll_back_before_a_valid_finish_without_run_id(self):
        self.create()
        job = self.store.claim_due(DUE)
        valid = summary(job)
        before = self.store.events()
        for value in ('1', True, -1, 2):
            counts = {**valid.counts, 'success': value}
            with self.subTest(value=value), self.assertRaisesRegex(ScheduleError, '^invalid execution counters$'):
                self.store.finish(FIRST, JobState.SUCCEEDED, DUE, summary=replace(valid, counts=counts))
            current = self.store.get(FIRST)
            self.assertEqual(current.state, JobState.RUNNING)
            self.assertIsNone(current.counts)
            self.assertIsNone(current.run_id)
            self.assertEqual(self.store.events(), before)
        finished = self.store.finish(FIRST, JobState.SUCCEEDED, DUE, summary=replace(valid, run_id=None))
        self.assertEqual(finished.state, JobState.SUCCEEDED)
        self.assertIsNone(finished.run_id)
        self.assertEqual(finished.counts, valid.counts)

    def test_metadata_mismatches_fail_closed_and_allow_the_next_valid_job(self):
        for field, value in (('canary', 2), ('report_path', str(self.root / 'different.json')),
                             ('command_sha256', 'f' * 64)):
            with self.subTest(field=field), contextlib.closing(SQLiteScheduleStore(self.root / field)) as store:
                store.create(FIRST, invocation(self.root), DUE, NOW, 300)
                store.create(SECOND, invocation(self.root), DUE, NOW, 300)
                # Corrupt only independent metadata; the original payload and
                # its digest still agree, so that comparison cannot mask this.
                store.db.execute('UPDATE jobs SET ' + field + '=? WHERE id=?', (value, FIRST))
                claimed = store.claim_due(DUE)
                self.assertEqual(claimed.info.id, SECOND)
                rejected = store.get(FIRST)
                self.assertEqual(rejected.state, JobState.FAILED)
                self.assertEqual(rejected.reason, 'invalid_job_snapshot')
                self.assertIsNone(rejected.started_at)
                self.assertIsNone(store.claim_due(DUE))
                self.assertNotIn('opaque-secret-command', json.dumps(store.events()))

    def test_noncanonical_stored_timestamps_are_not_silently_normalized(self):
        self.create()
        for field in ('due_at', 'created_at', 'deadline', 'started_at', 'finished_at'):
            original = self.store.db.execute('SELECT ' + field + ' FROM jobs WHERE id=?', (FIRST,)).fetchone()[0]
            corrupted = '2030-01-01T00:00:00Z'
            self.store.db.execute('UPDATE jobs SET ' + field + '=? WHERE id=?', (corrupted, FIRST))
            with self.subTest(field=field), self.assertRaisesRegex(ScheduleError, '^stored scheduling timestamp is not canonical UTC$'):
                self.store.get(FIRST)
            self.assertEqual(self.store.db.execute('SELECT ' + field + ' FROM jobs WHERE id=?', (FIRST,)).fetchone()[0], corrupted)
            self.store.db.execute('UPDATE jobs SET ' + field + '=? WHERE id=?', (original, FIRST))

    def test_runtime_version_and_application_changes_are_detected_without_repair(self):
        for pragma, wrong in (('user_version', 2), ('application_id', 0)):
            with self.subTest(pragma=pragma), contextlib.closing(SQLiteScheduleStore(self.root / pragma)) as store:
                store.create(FIRST, invocation(self.root), DUE, NOW, 300)
                store.db.execute('PRAGMA ' + pragma + '=' + str(wrong))
                before = list(store.db.iterdump())
                with self.assertRaisesRegex(ScheduleError, 'schema changed while open'):
                    store.list()
                self.assertEqual(list(store.db.iterdump()), before)
                self.assertEqual(store.db.execute('PRAGMA ' + pragma).fetchone()[0], wrong)

    def test_existing_wrong_application_markers_are_not_adopted(self):
        from swassh.infrastructure.schedule_store import APPLICATION_ID
        for version, application in ((0, APPLICATION_ID), (1, 0)):
            directory = self.root / ('markers-' + str(version))
            directory.mkdir(mode=0o700)
            path = directory / 'schedule.sqlite'
            with contextlib.closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA user_version=' + str(version))
                db.execute('PRAGMA application_id=' + str(application))
                before = list(db.iterdump())
            path.chmod(0o600)
            with self.subTest(version=version), self.assertRaisesRegex(ScheduleError, 'schema/version is unsupported'):
                SQLiteScheduleStore(directory)
            with contextlib.closing(sqlite3.connect(path)) as db:
                self.assertEqual(list(db.iterdump()), before)
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], version)
                self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], application)

    def test_oversized_existing_store_is_rejected_before_sqlite_parsing(self):
        directory = self.root / 'oversized'
        directory.mkdir(mode=0o700)
        path = directory / 'schedule.sqlite'
        original = b'\0' * 65537
        path.write_bytes(original)
        path.chmod(0o600)
        with self.assertRaisesRegex(ScheduleError, '^scheduler database exceeds its configured capacity$'):
            SQLiteScheduleStore(directory, max_bytes=65536)
        self.assertEqual(path.read_bytes(), original)

    def test_non_capacity_sqlite_failure_preserves_cause_and_rolls_back_the_outbox(self):
        before = self.store.events()
        with self.assertRaises(sqlite3.OperationalError) as captured:
            with self.store._transaction():
                self.store.db.execute('INSERT INTO events(payload) VALUES (?)', ('{"synthetic":true}',))
                self.store.db.execute('SELECT missing_synthetic_column FROM jobs')
        self.assertEqual(captured.exception.sqlite_errorcode, sqlite3.SQLITE_ERROR)
        self.assertFalse(self.store.db.in_transaction)
        self.assertEqual(self.store.events(), before)

    def test_invalid_create_arguments_and_terminal_states(self):
        self.create()
        for id, date, grace in [(FIRST, DUE, 300), (SECOND, NOW, 300), (SECOND, DUE, 0),
                                 (SECOND, DUE, True), (SECOND, DUE, 86401),
                                 (SECOND, datetime.max.replace(tzinfo=UTC), 300)]:
            with self.assertRaises(ScheduleError):
                self.store.create(id, invocation(self.root), date, NOW, grace)
        for state in (JobState.PENDING, 'failed'):
            with self.assertRaises(ScheduleError):
                self.store.finish(FIRST, state, DUE)
        job = self.store.claim_due(DUE)
        with self.assertRaises(ScheduleError):
            self.store.finish(FIRST, JobState.SUCCEEDED, DUE,
                summary=replace(summary(job), counts={'success': 9}))
        with self.assertRaises(ScheduleError):
            self.store.finish(FIRST, JobState.SUCCEEDED, DUE,
                summary=replace(summary(job), run_id='invalid'))
        for limit in (0, True, 201):
            with self.assertRaises(ScheduleError):
                self.store.events(limit)

    def test_capacity_reused_after_purge(self):
        with contextlib.closing(SQLiteScheduleStore(self.root / 'small', max_jobs=1)) as store:
            store.create(FIRST, invocation(self.root), DUE, NOW, 300)
            with self.assertRaisesRegex(ScheduleError, 'capacity'):
                store.create(SECOND, invocation(self.root), DUE, NOW, 300)
            store.cancel(FIRST, NOW)
            store.purge(FIRST, NOW)
            store.create(SECOND, invocation(self.root), DUE, NOW, 300)
        for values in ({'max_jobs': 0}, {'max_bytes': 10}, {'max_bytes': True}):
            with self.assertRaises(ScheduleError):
                SQLiteScheduleStore(self.root / 'invalid', **values)

    def test_sqlite_disk_cap_and_unknown_schema(self):
        with contextlib.closing(SQLiteScheduleStore(self.root / 'tiny', max_bytes=65536)) as store:
            with self.assertRaisesRegex(ScheduleError, 'capacity'):
                store.create(FIRST, invocation(self.root, hosts=10001), DUE, NOW, 300)
            self.assertEqual(store.list(), [])
        unknown = self.root / 'unknown'
        unknown.mkdir(mode=0o700)
        with contextlib.closing(sqlite3.connect(unknown / 'schedule.sqlite')) as db:
            db.execute('CREATE TABLE unrelated(value TEXT)')
        with self.assertRaisesRegex(ScheduleError, 'unknown schema'):
            SQLiteScheduleStore(unknown)
        with contextlib.closing(SQLiteScheduleStore(self.root / 'wrong-version')) as store:
            store.db.execute('PRAGMA user_version=99')
        with self.assertRaisesRegex(ScheduleError, 'unsupported'):
            SQLiteScheduleStore(self.root / 'wrong-version')

    def test_corrupt_snapshots_fail_closed_then_next_runs(self):
        self.create()
        self.create(SECOND)
        self.store.db.execute('UPDATE jobs SET payload=? WHERE id=?', ('corrupt', FIRST))
        job = self.store.claim_due(DUE)
        self.assertEqual(job.info.id, SECOND)
        self.assertEqual(self.store.get(FIRST).reason, 'invalid_job_snapshot')
        self.store.finish(SECOND, JobState.FAILED, DUE)
        self.store.purge(FIRST, NOW)
        self.create()
        data = json.loads(encode_invocation(invocation(self.root)))
        data['hosts'] = 4
        payload = json.dumps(data)
        self.store.db.execute('UPDATE jobs SET payload=?,payload_sha256=? WHERE id=?',
                             (payload, hashlib.sha256(payload.encode()).hexdigest(), FIRST))
        self.assertIsNone(self.store.claim_due(DUE))
        self.assertEqual(self.store.get(FIRST).state, JobState.FAILED)
        self.store.purge(FIRST, NOW)
        self.create()
        self.store.db.execute('UPDATE jobs SET host_count=3 WHERE id=?', (FIRST,))
        self.assertIsNone(self.store.claim_due(DUE))

    def test_private_files_links_and_worker_exclusion(self):
        if os.name == 'posix':
            self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        with self.store.worker_lock():
            with contextlib.closing(SQLiteScheduleStore(self.root / 'state')) as second:
                with self.assertRaises((OSError, RuntimeError, ScheduleError)):
                    with second.worker_lock():
                        self.fail('a second worker acquired the lock')
        with self.store.worker_lock():
            pass
        if os.name == 'posix':
            bad = self.root / 'linked'
            bad.mkdir(mode=0o700)
            (bad / 'schedule.sqlite').symlink_to(self.store.path)
            with self.assertRaises((OSError, ValueError)):
                SQLiteScheduleStore(bad)

    def test_cancel_racing_claim_has_one_atomic_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        self.create()
        barrier = threading.Barrier(2)
        with contextlib.closing(SQLiteScheduleStore(self.root / 'state')) as second:
            def cancel():
                barrier.wait(2)
                try:
                    return second.cancel(FIRST, DUE)
                except ScheduleError:
                    return None
            def claim():
                barrier.wait(2)
                return self.store.claim_due(DUE)
            with ThreadPoolExecutor(max_workers=2) as pool:
                cancelled = pool.submit(cancel)
                claimed = pool.submit(claim)
                outcomes = cancelled.result(5), claimed.result(5)
            self.assertEqual(sum(value is not None for value in outcomes), 1)
            self.assertIn(self.store.get(FIRST).state, {JobState.CANCELLED, JobState.RUNNING})

    def test_audit_outbox_omits_command_and_persists_until_ack(self):
        self.create()
        events = self.store.events()
        self.assertNotIn('opaque-secret-command', json.dumps(events))
        self.assertEqual(events[0][1]['event'], 'schedule_created')
        self.store.acknowledge_events(events[-1][0])
        self.assertEqual(self.store.events(), [])

    def test_registration_pins_paths_and_applies_user_dedup(self):
        key = self.root / 'key'
        key.write_text('local readability fixture')
        key.chmod(0o600)
        value = prepare_invocation(FIRST, self.root, ['a', 'admin@a'], 'x',
            Options(username='admin', ssh_executable=sys.executable, client_keys=(str(key),)))
        self.assertEqual(len(value.hosts), 1)
        self.assertTrue(Path(value.options.client_keys[0]).is_absolute())
        self.assertTrue(Path(value.options.known_hosts).is_absolute())
        self.assertIn(FIRST, value.options.log_file)
        for kwargs in ({'report_path': self.root / 'missing/report'}, {'spool_dir': self.root / 'missing'}):
            with self.assertRaises(ScheduleError):
                prepare_invocation(FIRST, self.root, ['a'], 'x', Options(ssh_executable=sys.executable), **kwargs)
        with self.assertRaises(ScheduleError):
            prepare_invocation(FIRST, self.root, ['a'], 'x', Options(ssh_executable='no-such-ssh-binary'))


class SchedulerFacadePolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_store_location_is_passed_to_the_dependency_factory(self):
        directory=Path('/synthetic/scheduler').absolute();store=SimpleNamespace(directory=directory,close=Mock())
        with patch.object(scheduling_api,'default_schedule_directory',return_value=directory),\
                patch.object(scheduling_api,'scheduler_dependencies',return_value=(store,object(),Mock())) as create:
            with Scheduler() as scheduler:self.assertEqual(scheduler.state_dir,directory)
        create.assert_called_once_with(directory);store.close.assert_called_once_with()

    async def test_installed_worker_signal_handlers_are_removed_after_success_and_failure(self):
        for failure in (None,RuntimeError('synthetic worker failure')):
            loop=SimpleNamespace(add_signal_handler=Mock(),remove_signal_handler=Mock())
            port=SimpleNamespace(**vars(asyncio));port.get_running_loop=lambda:loop
            scheduler=SimpleNamespace(serve=AsyncMock(return_value=4,side_effect=failure))
            with self.subTest(failure=failure),patch.object(scheduling_api,'asyncio',port):
                if failure is None:self.assertEqual(await run_worker(scheduler,once=True,poll_interval=1),4)
                else:
                    with self.assertRaisesRegex(RuntimeError,'synthetic worker failure'):await run_worker(scheduler,once=True,poll_interval=1)
            numbers=[scheduling_api.signal.SIGINT,scheduling_api.signal.SIGTERM]
            self.assertEqual([call.args[0] for call in loop.add_signal_handler.call_args_list],numbers)
            self.assertEqual([call.args[0] for call in loop.remove_signal_handler.call_args_list],numbers)
            fields=scheduler.serve.await_args.kwargs
            self.assertTrue(fields['once']);self.assertEqual(fields['poll_interval'],1)
            self.assertIsInstance(fields['stop_event'],asyncio.Event)


class IdlePollingUnitTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_idle_timeout_precedes_stop_and_never_dispatches_a_job(self):
        # Observe the genuine timeout, then request stop. A fixed sleep can stop
        # a busy worker before its first idle poll even begins.
        stop = asyncio.Event()
        expired = []
        original_timeout = asyncio.timeout
        @contextlib.asynccontextmanager
        async def observed_timeout(seconds):
            self.assertEqual(seconds, .1)
            deadline = original_timeout(seconds)
            try:
                async with deadline:
                    yield
            except TimeoutError:
                self.assertTrue(deadline.expired())
                expired.append(True)
                stop.set()
                raise
        store = SimpleNamespace(worker_lock=Mock(return_value=contextlib.nullcontext()),
            recover_running=Mock(), events=Mock(return_value=[]), claim_due=Mock(return_value=None))
        executor = AsyncMock()
        audit = Mock(side_effect=AssertionError('an empty outbox must not open an audit sink'))
        service = SchedulingService(store, executor, audit_factory=audit,
                                    audit_path='unused-memory-port', clock=lambda: NOW)
        with patch('swassh.application.scheduling.asyncio.timeout', observed_timeout):
            try:
                processed = await asyncio.wait_for(service.serve(stop_event=stop, poll_interval=.1), 2)
            except TimeoutError:
                self.fail('a handled idle timeout must not escape or leave the worker waiting')
        self.assertEqual(processed, 0)
        self.assertEqual(expired, [True])
        self.assertTrue(stop.is_set())
        executor.assert_not_awaited()
        store.claim_due.assert_called_once()
        self.assertEqual(store.recover_running.call_count, 2)
        store.worker_lock.assert_called_once()
        audit.assert_not_called()


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SQLiteScheduleStore(self.root / 'state')
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.store.close)
        self.calls = []
        async def execute(job):
            self.calls.append(job.info.id)
            await asyncio.sleep(0)
            return summary(job)
        self.service = SchedulingService(self.store, execute, audit_factory=AuditTrail,
            audit_path=str(self.root / 'scheduler.jsonl'), clock=lambda: DUE)

    def create(self, id=FIRST):
        return self.store.create(id, invocation(self.root), DUE, NOW, 300)

    async def test_once_serial_no_replay_and_audit_flush(self):
        self.create()
        self.create(SECOND)
        self.assertEqual(await self.service.serve(once=True), 1)
        self.assertEqual(self.calls, [FIRST])
        self.assertEqual(self.store.get(SECOND).state, JobState.PENDING)
        self.assertEqual(await self.service.serve(once=True), 1)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.calls, [FIRST, SECOND])
        self.assertEqual(self.store.events(), [])
        audit = (self.root / 'scheduler.jsonl').read_text()
        self.assertNotIn('opaque-secret-command', audit)
        self.assertIn('schedule_succeeded', audit)

    async def test_failed_summary_and_executor_exception(self):
        self.create()
        async def failed(job):
            return summary(job, False)
        self.service.executor = failed
        await self.service.serve(once=True)
        self.assertEqual(self.store.get(FIRST).reason, 'host_or_canary_failed')
        self.create(SECOND)
        async def broken(job):
            raise OSError('sensitive-command must never appear')
        self.service.executor = broken
        await self.service.serve(once=True)
        self.assertEqual(self.store.get(SECOND).reason, 'execution_or_report_error')
        self.assertNotIn('sensitive-command', (self.root / 'scheduler.jsonl').read_text())

    async def test_invalid_summary(self):
        self.create()
        async def invalid(job):
            return object()
        self.service.executor = invalid
        await self.service.serve(once=True)
        self.assertEqual(self.store.get(FIRST).state, JobState.FAILED)

    async def test_wrong_host_total_never_commits_a_success_or_replays_execution(self):
        self.create();calls=[]
        async def invalid(job):
            calls.append(job.info.id);return replace(summary(job),total=job.info.host_count+1)
        self.service.executor=invalid
        self.assertEqual(await self.service.serve(once=True),1)
        info=self.store.get(FIRST)
        self.assertEqual(info.state,JobState.FAILED);self.assertEqual(info.reason,'execution_or_report_error')
        self.assertEqual(await self.service.serve(once=True),0);self.assertEqual(calls,[FIRST])

    async def test_terminal_storage_failure_is_visible_and_never_replayed(self):
        self.create()
        original = self.store.finish
        def failing(id, state, now, **kwargs):
            if state == JobState.SUCCEEDED:
                raise OSError('terminal storage unavailable')
            return original(id, state, now, **kwargs)
        with patch.object(self.store, 'finish', failing):
            with self.assertRaisesRegex(OSError, 'terminal storage unavailable'):
                await self.service.serve(once=True)
        self.assertEqual(self.calls, [FIRST])
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.calls, [FIRST])

    async def test_execution_failure_has_safe_durable_diagnostic(self):
        self.create()
        async def denied(job):
            raise PermissionError(13, 'SECRET command and credentials')
        self.service.executor = denied
        await self.service.serve(once=True)
        self.assertEqual(self.store.get(FIRST).reason, 'execution_or_report_error')
        records = [json.loads(line) for line in (self.root/'scheduler.jsonl').read_text().splitlines()]
        failure = next(record for record in records if record['event'] == 'schedule_failed')
        self.assertEqual(failure['diagnostic'], {
            'category': 'permission', 'error_type': 'PermissionError', 'errno': 13})
        self.assertNotIn('SECRET', json.dumps(records))

    async def test_completion_error_after_commit_keeps_success(self):
        self.create()
        original = self.store.finish
        def committed(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError('response lost after commit')
        with patch.object(self.store, 'finish', committed):
            with self.assertRaises(OSError):
                await self.service.serve(once=True)
        self.assertEqual(self.store.get(FIRST).state, JobState.SUCCEEDED)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.calls, [FIRST])

    async def test_diagnostic_and_terminal_state_commit_together(self):
        self.create()
        self.store.claim_due(DUE)
        diagnostic = ExecutionFailure.capture(TimeoutError('SECRET'))
        with patch.object(self.store, '_event', side_effect=OSError('outbox unavailable')):
            with self.assertRaises(OSError):
                self.store.finish_failure(FIRST, DUE, diagnostic)
        self.assertEqual(self.store.get(FIRST).state, JobState.RUNNING)
        self.store.finish_failure(FIRST, DUE, diagnostic)
        record = self.store.events()[-1][1]
        self.assertEqual(record['fields']['diagnostic']['category'], 'timeout')
        with self.assertRaises(ScheduleError):
            self.store.finish_failure(FIRST, DUE, {'secret': 'not accepted'})

    async def test_legacy_store_without_diagnostic_capability_still_works(self):
        self.create()
        async def broken(job):
            raise RuntimeError('SECRET')
        self.service.executor = broken
        with patch.object(self.store, 'finish_failure', None):
            await self.service.serve(once=True)
        self.assertEqual(self.store.get(FIRST).reason, 'execution_or_report_error')

    def test_diagnostic_categories_never_include_exception_messages(self):
        cases = [(TimeoutError(), 'timeout'), (PermissionError(), 'permission'),
                 (FileNotFoundError(), 'missing_file'), (OSError(), 'io'),
                 (ScheduleError('SECRET'), 'invalid_summary'), (ValueError('SECRET'), 'invalid_input'),
                 (RuntimeError('SECRET'), 'runtime'), (Exception('SECRET'), 'unexpected')]
        for error, category in cases:
            self.assertEqual(ExecutionFailure.capture(error).category, category)
        for arguments in [('SECRET', 'Exception'), ('io', 'OSError', True), ('io', 'OSError', -1)]:
            with self.assertRaises(ValueError):
                ExecutionFailure(*arguments)
        with self.assertRaises(TypeError):
            ExecutionFailure.capture(None)

    async def test_stop_during_run_and_cancelled_service(self):
        for id, cancel_task in ((FIRST, False), (SECOND, True)):
            self.create(id)
            stop, started = asyncio.Event(), asyncio.Event()
            async def blocked(job):
                started.set()
                await asyncio.sleep(30)
            self.service.executor = blocked
            task = asyncio.create_task(self.service.serve(stop_event=stop))
            try:
                await asyncio.wait_for(started.wait(), 2)
                if cancel_task:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                else:
                    stop.set()
                    await asyncio.wait_for(task, 2)
                self.assertEqual(self.store.get(id).state, JobState.INTERRUPTED)
                self.assertIsNone(self.store.claim_due(DUE))
            finally:
                # An assertion or readiness timeout must still retire the owned
                # service before fixture storage and audit paths are removed.
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


    async def test_readiness_timeout_still_joins_the_service_before_fixture_cleanup(self):
        tasks = []
        create = asyncio.create_task
        async def expired(awaitable, timeout):
            awaitable.close()
            await asyncio.sleep(0)
            raise TimeoutError('controlled readiness refusal')
        def own(coroutine, *args, **kwargs):
            task = create(coroutine, *args, **kwargs)
            tasks.append(task)
            return task
        try:
            with patch.object(asyncio, 'create_task', side_effect=own), \
                    patch.object(asyncio, 'wait_for', side_effect=expired):
                with self.assertRaisesRegex(TimeoutError, 'controlled readiness refusal'):
                    await self.test_stop_during_run_and_cancelled_service()
            self.assertTrue(tasks)
            self.assertTrue(all(task.done() for task in tasks), 'service survived its failed readiness assertion')
            with self.store.worker_lock():
                pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_storage_dispatch_does_not_wait_for_an_unrelated_default_executor(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        self.create()
        occupied, release = threading.Event(), threading.Event()
        executor = ThreadPoolExecutor(max_workers=1)
        asyncio.get_running_loop().set_default_executor(executor)
        def unrelated():
            occupied.set()
            release.wait()
        pending = executor.submit(unrelated)
        self.assertTrue(occupied.wait(2))
        # Release is a fail-safe for a refused implementation that must join
        # its blocked native operation after the original two-second deadline.
        guard = threading.Timer(3, release.set)
        guard.start()
        self.service.audit_factory = lambda *args: AuditTrail(None, 'disabled-file-audit')
        try:
            self.assertEqual(await asyncio.wait_for(self.service.serve(once=True), 2), 1)
            self.assertEqual(self.calls, [FIRST])
            self.assertEqual(self.store.get(FIRST).state, JobState.SUCCEEDED)
            self.assertFalse(release.is_set(), 'dispatch waited for unrelated executor capacity')
        finally:
            release.set()
            guard.cancel()
            guard.join(2)
            pending.result(2)

    async def test_poll_stop_and_pre_stopped_worker(self):
        stop = asyncio.Event()
        task = asyncio.create_task(self.service.serve(stop_event=stop, poll_interval=.1))
        await asyncio.sleep(.15)
        stop.set()
        self.assertEqual(await task, 0)
        self.create()
        self.assertEqual(await self.service.serve(stop_event=stop), 0)
        self.assertEqual(self.calls, [])
        for interval in (0, True, float('nan'), 61, '1', None):
            with self.assertRaises(ScheduleError):
                await self.service.serve(poll_interval=interval)

    async def test_worker_recovers_crashed_job_before_dispatching_next(self):
        self.create()
        self.create(SECOND)
        self.store.claim_due(DUE)
        await self.service.serve(once=True)
        self.assertEqual(self.calls, [SECOND])
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)

    async def test_audit_failure_keeps_outbox_and_prevents_execution(self):
        self.create()
        class BrokenAudit:
            async def __aenter__(self):
                raise OSError('log unavailable')
            async def __aexit__(self, *args):
                pass
        self.service.audit_factory = lambda *args: BrokenAudit()
        with self.assertRaises(OSError):
            await self.service.serve(once=True)
        self.assertEqual(self.calls, [])
        self.assertTrue(self.store.events())
        self.assertEqual(self.store.get(FIRST).state, JobState.PENDING)

    async def test_cancellation_waits_for_durable_sqlite_thread(self):
        import threading
        ready, release = threading.Event(), threading.Event()
        def io_task():
            ready.set()
            release.wait(2)
            return 17
        task = asyncio.create_task(self.service._io(io_task))
        await asyncio.to_thread(ready.wait, 2)
        task.cancel()
        await asyncio.sleep(.01)
        task.cancel()
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_continuous_worker_runs_fleets_serially(self):
        self.create()
        self.create(SECOND)
        stop = asyncio.Event()
        active = peak = 0
        async def execute(job):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            self.calls.append(job.info.id)
            await asyncio.sleep(.02)
            active -= 1
            if job.info.id == SECOND:
                stop.set()
            return summary(job)
        self.service.executor = execute
        self.assertEqual(await self.service.serve(stop_event=stop), 2)
        self.assertEqual(peak, 1)
        self.assertEqual(self.calls, [FIRST, SECOND])

    async def test_stop_after_claim_never_starts_executor(self):
        self.create()
        stop = asyncio.Event()
        original = self.store.claim_due
        def claim(now):
            job = original(now)
            # Event.set is run on the loop thread, while claim is the I/O thread.
            loop.call_soon_threadsafe(stop.set)
            return job
        loop = asyncio.get_running_loop()
        with patch.object(self.store, 'claim_due', claim):
            await self.service.serve(stop_event=stop)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)

    async def test_stop_observed_during_claim_audit_interrupts_before_dispatch(self):
        self.create()
        stop = asyncio.Event()
        @contextlib.asynccontextmanager
        async def audit(path, scope):
            class Sink:
                async def emit(inner, event, fields):
                    if event == 'schedule_started':
                        stop.set()
            yield Sink()
        self.service.audit_factory = audit
        self.assertEqual(await self.service.serve(once=True, stop_event=stop), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)
        self.assertEqual(self.store.events(), [])
        self.assertEqual(await self.service.serve(once=True), 0)

    async def test_executor_cleanup_error_during_cancellation_cannot_replay_the_claim(self):
        from swassh.application import scheduling as worker
        self.create()
        started, cleaning, release, waiting = (asyncio.Event() for _ in range(4))
        async def execute(job):
            self.calls.append(job.info.id)
            started.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                raise OSError('synthetic executor cleanup error')
        from swassh.application.task_ownership import wait_owned
        async def observing_wait(task):
            waiting.set()
            return await wait_owned(task)
        self.service.executor = execute
        with patch.object(worker, 'wait_owned', observing_wait):
            task = asyncio.create_task(self.service.serve(once=True))
            try:
                async with asyncio.timeout(3):
                    await started.wait()
                    task.cancel()
                    await cleaning.wait()
                    await waiting.wait()
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.calls, [FIRST])

    @unittest.skipUnless(os.name == 'posix', 'SIGKILL recovery fixture requires POSIX')
    async def test_process_crash_after_durable_claim_is_not_replayed(self):
        import subprocess
        self.create()
        code = ('import os,signal,sys; from datetime import datetime; '
                'from swassh.infrastructure.schedule_store import SQLiteScheduleStore; '
                'store=SQLiteScheduleStore(sys.argv[1]); '
                'lock=store.worker_lock(); lock.__enter__(); '
                'assert store.claim_due(datetime.fromisoformat(sys.argv[2])); '
                'os.kill(os.getpid(),signal.SIGKILL)')
        completed = await asyncio.to_thread(subprocess.run, [sys.executable, '-c', code,
            str(self.store.directory), DUE.isoformat()], capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, -9, completed.stderr)
        self.assertEqual(self.store.get(FIRST).state, JobState.RUNNING)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.store.get(FIRST).state, JobState.INTERRUPTED)
        self.assertEqual(self.calls, [])

    async def test_cancellation_after_terminal_commit_preserves_success(self):
        self.create()
        original = self.store.finish
        committed, release = asyncio.Event(), asyncio.Event()
        async def io(function, *args, **kwargs):
            result = await SchedulingService._io(self.service, function, *args, **kwargs)
            if function == self.service._finish_if_running and args[1] == JobState.SUCCEEDED:
                committed.set()
                await release.wait()
            return result
        with patch.object(self.service, '_io', io):
            task = asyncio.create_task(self.service.serve(once=True))
            await asyncio.wait_for(committed.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(self.store.get(FIRST).state, JobState.SUCCEEDED)
        self.assertEqual(original.__self__, self.store)

    async def test_signal_worker_wrapper_and_executor_adapter(self):
        class Worker:
            async def serve(self, **kwargs):
                return 4
        self.assertEqual(await run_worker(Worker(), once=True, poll_interval=1), 4)
        with patch('asyncio.unix_events._UnixSelectorEventLoop.add_signal_handler', side_effect=NotImplementedError) if os.name == 'posix' else contextlib.nullcontext():
            self.assertEqual(await run_worker(Worker(), once=True, poll_interval=1), 4)
        self.create()
        job = self.store.claim_due(DUE)
        observed = []
        class Swarm:
            async def run_to_file(self, *args, **kwargs):
                observed.append((args, kwargs))
                return summary(job)
        adapter = SwarmScheduledExecutor(self.store.directory, lambda options: Swarm())
        self.assertTrue((await adapter(job)).ok)
        self.assertEqual(observed[0][0][1], 'opaque-secret-command')
        self.assertTrue((self.store.directory / 'runs' / FIRST).is_dir())


class ScheduleCLITests(unittest.TestCase):
    def call(self, argv, expected=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = cli.main(['schedule', *argv])
        self.assertEqual(result, expected, stderr.getvalue())
        return stdout.getvalue()

    def test_plan_only_creates_no_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'absent'
            value = json.loads(self.call(['complex-command --option "a b"', '-H', 'a', 'b', '--at',
                '2099-01-01 00:00', '--canary', '5', '--state-dir', str(state), '--ssh-executable', 'absent', '--plan-only']))
            self.assertEqual(value['canary_count'], 2)
            self.assertEqual(value['host_count'], 2)
            self.assertFalse(state.exists())

    def test_register_list_show_cancel_purge_with_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            inventory = root / 'hosts.txt'
            inventory.write_text('a\nb\n')
            extra = ['--state-dir', str(state), '--format', 'json']
            jobs = json.loads(self.call(['true', '-i', str(inventory), '--at', '2099-01-01 00:00',
                                       '--ssh-executable', sys.executable, *extra]))
            id = jobs[0]['id']
            inventory.write_text('different\n')
            jobs = json.loads(self.call(['--list', '--limit', '1', '--offset', '0', *extra]))
            self.assertEqual(jobs[0]['host_count'], 2)
            self.assertEqual(json.loads(self.call(['--show', id, *extra]))[0]['id'], id)
            csv = self.call(['--list', '--format', 'csv', '--state-dir', str(state)])
            self.assertIn('pending', csv)
            self.assertIn('pending', self.call(['--list', '--state-dir', str(state)]))
            self.call(['--worker', '--once', *extra])
            self.assertEqual(json.loads(self.call(['--cancel', id, *extra]))[0]['state'], 'cancelled')
            self.call(['--purge', id, *extra])
            self.assertEqual(json.loads(self.call(['--list', *extra])), [])
            self.assertIn('No scheduled jobs', self.call(['--list', '--state-dir', str(state)]))

    def test_text_registration_worker_notice_and_scheduler_api(self):
        with tempfile.TemporaryDirectory() as directory:
            extra = ['--state-dir', str(Path(directory) / 'state')]
            text = self.call(['true', '-H', 'a', '--at', '2099-01-01 00:00', '--ssh-executable', sys.executable, *extra])
            self.assertIn('supervised', text)
            with Scheduler(Path(directory) / 'api') as scheduler:
                job = scheduler.schedule(['a'], 'x', '2099-01-01 00:00', options=Options(ssh_executable=sys.executable))
                self.assertEqual(job.state, JobState.PENDING)
                with self.assertRaises(ScheduleError):
                    scheduler.schedule(['a'], 'x', '2000-01-01 00:00')

    def test_invalid_registration_and_management_flags(self):
        cases = [[], ['true'], ['true', '-H', 'a', '--at', '2000-01-01 00:00'],
                 ['true', '-H', 'a', '--at', '2099-01-01 00:00', '--misfire-grace', '0'],
                 ['true', '-H', 'a', '--at', '2099-01-01 00:00', '--once'],
                 ['--list', '--canary', '5'], ['--list', '--once'], ['--worker', '--limit', '1'],
                 ['--list', 'true'], ['--show', 'x', '--poll-interval', '1']]
        for argv in cases:
            with self.subTest(argv=argv):
                self.call(argv, 2)
        for option in ('-c', '--command', '--commande'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(['schedule', 'true', option, 'x', '-H', 'a'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX worker signal handling')
    def test_worker_sigterm_leaves_future_job_pending(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            extra = ['--state-dir', str(state), '--format', 'json']
            id = json.loads(self.call(['true', '-H', 'a', '--at', '2099-01-01 00:00',
                                      '--ssh-executable', sys.executable, *extra]))[0]['id']
            with subprocess.Popen([sys.executable, '-m', 'swassh', 'schedule', '--worker', *extra],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as worker:
                try:
                    deadline = time.monotonic() + 5
                    while not (state / 'worker.lock').exists() and worker.poll() is None and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((state / 'worker.lock').exists())
                    worker.terminate()
                    stdout, stderr = worker.communicate(timeout=5)
                    self.assertEqual(worker.returncode, 0, stderr)
                finally:
                    if worker.poll() is None:
                        worker.kill()
                        worker.communicate(timeout=5)
            with contextlib.closing(SQLiteScheduleStore(state)) as store:
                self.assertEqual(store.get(id).state, JobState.PENDING)

    @unittest.skipUnless(os.name == 'posix', 'executable shebang process fixture requires POSIX')
    def test_functional_scheduled_process_report_canary_and_no_replay(self):
        import subprocess
        import time
        # A future-date fixture must remain future throughout the existing
        # ten-second registration allowance. The application's rejection of
        # expired input, ten/fifteen-second process caps and canary checks stay.
        for startup_delay in (0., 2.25):
            with self.subTest(startup_delay=startup_delay):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    fixture = root / 'ssh-fixture'
                    fixture.write_text('#!' + sys.executable + '\n' + Path(__file__).with_name('fake_ssh.py').read_text())
                    fixture.chmod(0o700)
                    state, calls = root / 'state', root / 'calls'
                    env = dict(os.environ, SWASSH_TEST_CALLS=str(calls))
                    due = datetime.now(UTC) + timedelta(seconds=11)
                    arguments = [sys.executable, '-m', 'swassh', 'schedule']
                    extra = ['--state-dir', str(state), '--format', 'json']
                    submission = arguments
                    if startup_delay:
                        # The delay is inside the same ten-second subprocess budget.
                        bootstrap = ("import runpy,sys,time;time.sleep(2.25);"
                            "sys.argv=['swassh',*sys.argv[1:]];runpy.run_module('swassh',run_name='__main__')")
                        submission = [sys.executable, '-c', bootstrap, 'schedule']
                    result = subprocess.run([*submission, 'failed', '-H', 'a', 'b', '--at', due.isoformat(),
                                            '--ssh-executable', str(fixture), *extra], env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    id = json.loads(result.stdout)[0]['id']
                    delay = (due - datetime.now(UTC)).total_seconds()
                    if delay > 0:
                        time.sleep(delay)
                    for _ in range(2):
                        result = subprocess.run([*arguments, '--worker', '--once', *extra], env=env, capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stderr)
                    with contextlib.closing(SQLiteScheduleStore(state)) as store:
                        job = store.get(id)
                    self.assertEqual(job.state, JobState.FAILED)
                    self.assertEqual(job.counts['skipped'], 1)
                    self.assertEqual(calls.read_text(), 'failed\n')
                    report = json.loads(Path(job.report_path).read_text())
                    self.assertEqual(report['canary'], {'requested': 1, 'selected': 1, 'passed': False})
                    self.assertNotIn('opaque-secret-command', (state / 'scheduler.jsonl').read_text())
