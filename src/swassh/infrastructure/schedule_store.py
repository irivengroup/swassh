"""Private, bounded SQLite schedules and a transactional lifecycle audit outbox."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from ..application.options import Options
from ..application.schedule_contracts import ClaimedJob, ScheduledInvocation, ExecutionFailure
from ..domain.models import Host, Status
from ..domain.scheduling import JobInfo, JobState, ScheduleError, TERMINAL_STATES, timestamp, utc_time, validate_job_id
from .audit import _WriterLock, default_log_path
from .filesystem import open_private_append, private_directory
from .inventory import _unique_object, _invalid_constant

MAX_PAYLOAD_BYTES = 10 * 1024 * 1024
MAX_JOBS = 1000
MAX_STORE_BYTES = 128 * 1024 * 1024
APPLICATION_ID = 0x53574153


def default_schedule_directory():
    return default_log_path().parent / 'schedules'


def encode_invocation(invocation):
    payload = json.dumps({'schema_version': 1, **asdict(invocation)}, ensure_ascii=False, allow_nan=False)
    if len(payload.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise ScheduleError('scheduled inventory/options snapshot exceeds 10 MiB')
    return payload


def decode_invocation(payload):
    # Persisted workflow entries are untrusted JSON values. Reject a non-text
    # entry before encoding rather than leaking AttributeError at the CLI.
    if not isinstance(payload, str):
        raise ScheduleError('scheduled snapshot must be text')
    if len(payload.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise ScheduleError('scheduled snapshot exceeds 10 MiB')
    data = json.loads(payload, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(data, dict) or set(data) != {'schema_version', 'command', 'hosts', 'options', 'report_path', 'format', 'spool_dir'}:
        raise ScheduleError('unsupported scheduled snapshot schema')
    version = data.pop('schema_version')
    if type(version) is not int or version != 1:
        raise ScheduleError('unsupported scheduled snapshot schema')
    if not isinstance(data['hosts'], list) or not 1 <= len(data['hosts']) <= 100_000 or not isinstance(data['options'], dict):
        raise ScheduleError('invalid scheduled host/options snapshot')
    if any(not isinstance(host, dict) or set(host) != set(Host.__dataclass_fields__) for host in data['hosts']):
        raise ScheduleError('invalid scheduled host schema')
    data['hosts'] = tuple(Host(**host) for host in data['hosts'])
    options = data['options']
    legacy = {'concurrency', 'connect_timeout', 'command_timeout', 'retries', 'retry_delay',
        'max_output_bytes', 'connect_rate', 'memory_budget_mib', 'max_report_mib', 'username',
        'client_keys', 'known_hosts', 'jump_host', 'log_file', 'ssh_executable', 'report_timeout', 'canary'}
    if not legacy <= set(options) <= set(Options.__dataclass_fields__) or not isinstance(options.get('client_keys'), list):
        raise ScheduleError('invalid scheduled option schema')
    # Snapshots predating this option retain their original compact display.
    options.setdefault('show_output', False)
    options['client_keys'] = tuple(options['client_keys'])
    from .execution_input import decode_profiles
    options['host_profiles'] = decode_profiles(options.get('host_profiles', []))
    if options['jump_host'] is not None:
        if not isinstance(options['jump_host'], dict) or set(options['jump_host']) != set(Host.__dataclass_fields__):
            raise ScheduleError('invalid scheduled jump host schema')
        options['jump_host'] = Host(**options['jump_host'])
    data['options'] = Options(**options)
    return ScheduledInvocation(**data)


class SQLiteScheduleStore:
    def __init__(self, directory, *, max_jobs=MAX_JOBS, max_bytes=MAX_STORE_BYTES):
        if (not isinstance(max_jobs, int) or isinstance(max_jobs, bool) or not 1 <= max_jobs <= MAX_JOBS
                or not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 65536 <= max_bytes <= MAX_STORE_BYTES):
            raise ScheduleError('invalid scheduler store capacity')
        self.directory = private_directory(Path(directory).expanduser().absolute(), tighten=True)
        self.path = self.directory / 'schedule.sqlite'
        self.max_jobs = max_jobs
        self._lock = threading.RLock()
        # Last component must be private, regular and unlinked before SQLite opens it.
        with open_private_append(self.path):
            pass
        if self.path.stat().st_size > max_bytes:
            raise ScheduleError("scheduler database exceeds its configured capacity")
        self.db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=3, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA cache_size=-2048')
            page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
            self.db.execute(f'PRAGMA max_page_count={max_bytes // page_size}')
            with self._transaction():
                version = self.db.execute('PRAGMA user_version').fetchone()[0]
                application = self.db.execute('PRAGMA application_id').fetchone()[0]
                if version == 0 and application == 0:
                    if self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]:
                        raise ScheduleError('scheduler database has an unknown schema')
                    self.db.execute('''CREATE TABLE jobs (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                        state TEXT NOT NULL, due_at TEXT NOT NULL, deadline TEXT NOT NULL,
                        created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                        host_count INTEGER NOT NULL, command_sha256 TEXT NOT NULL,
                        report_path TEXT NOT NULL, canary INTEGER NOT NULL,
                        payload TEXT NOT NULL CHECK(length(payload)<=10485760), payload_sha256 TEXT NOT NULL,
                        run_id TEXT, counts TEXT, reason TEXT)''')
                    self.db.execute('CREATE INDEX jobs_due ON jobs(state,due_at,seq)')
                    self.db.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)')
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('PRAGMA user_version=1')
                elif version != 1 or application != APPLICATION_ID:
                    raise ScheduleError('scheduler database schema/version is unsupported; do not overwrite it')
                expected = {'jobs': set(JobInfo.__dataclass_fields__) | {'seq', 'payload', 'payload_sha256'},
                            'events': {'seq', 'payload'}}
                for table, fields in expected.items():
                    actual = {row['name'] for row in self.db.execute('PRAGMA table_info(' + table + ')')}
                    if actual != fields:
                        raise ScheduleError('scheduler table schema is invalid; keep the database for inspection')
                if self.db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
                    raise ScheduleError('scheduler schema contains unexpected executable objects')
            self._schema_version = self.db.execute('PRAGMA schema_version').fetchone()[0]
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def _transaction(self):
        with self._lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self._check_schema()
                yield
                self.db.commit()
            except BaseException as exc:
                self.db.rollback()
                if isinstance(exc, sqlite3.Error) and getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL:
                    raise ScheduleError('scheduler database capacity or disk space exhausted') from exc
                raise

    def _check_schema(self):
        if hasattr(self, '_schema_version') and (
                self.db.execute('PRAGMA schema_version').fetchone()[0] != self._schema_version
                or self.db.execute('PRAGMA user_version').fetchone()[0] != 1
                or self.db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID):
            raise ScheduleError('scheduler schema changed while open; restart after inspection')

    def close(self):
        with self._lock:
            self.db.close()

    def worker_lock(self):
        try:
            lock = _WriterLock(self.directory / 'worker')
        except OSError as exc:
            raise ScheduleError('another worker is active, or its lock file is unavailable') from exc
        @contextmanager
        def holding():
            try:
                yield
            finally:
                lock.close()
        return holding()

    def _event(self, event, id, now, **fields):
        record = {'event': event, 'fields': {'job_id': id, 'occurred_at': timestamp(now), **fields}}
        self.db.execute('INSERT INTO events(payload) VALUES (?)', (json.dumps(record, ensure_ascii=True),))

    def _row(self, id):
        validate_job_id(id)
        row = self.db.execute('SELECT * FROM jobs WHERE id=?', (id,)).fetchone()
        if row is None:
            raise ScheduleError('scheduled job not found')
        return row

    @staticmethod
    def _info(row):
        fields = {name: row[name] for name in JobInfo.__dataclass_fields__}
        fields['state'] = JobState(fields['state'])
        for name in ('due_at', 'created_at', 'deadline', 'started_at', 'finished_at'):
            if fields[name] is not None:
                value = datetime.fromisoformat(fields[name])
                if timestamp(value) != fields[name]:
                    raise ScheduleError('stored scheduling timestamp is not canonical UTC')
                fields[name] = value
        if fields['counts'] is not None:
            fields['counts'] = json.loads(fields['counts'])
        return JobInfo(**fields)

    def create(self, id, invocation, due_at, now, misfire_grace):
        validate_job_id(id)
        due_at, now = utc_time(due_at), utc_time(now)
        if due_at <= now:
            raise ScheduleError('scheduled date and time must be in the future')
        if not isinstance(misfire_grace, int) or isinstance(misfire_grace, bool) or not 1 <= misfire_grace <= 86400:
            raise ScheduleError('misfire grace must be an integer between 1 and 86400 seconds')
        try:
            deadline = due_at + timedelta(seconds=misfire_grace)
        except OverflowError as exc:
            raise ScheduleError('scheduled date is outside the supported calendar') from exc
        payload = encode_invocation(invocation)
        command_hash = hashlib.sha256(invocation.command.encode('utf-8')).hexdigest()
        with self._transaction():
            if self.db.execute('SELECT count(*) FROM jobs').fetchone()[0] >= self.max_jobs:
                raise ScheduleError('scheduler capacity reached; purge a terminal job before adding another')
            try:
                self.db.execute('''INSERT INTO jobs(id,state,due_at,deadline,created_at,host_count,command_sha256,
                    report_path,canary,payload,payload_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                    (id, JobState.PENDING, timestamp(due_at), timestamp(deadline), timestamp(now),
                     len(invocation.hosts), command_hash, invocation.report_path, invocation.options.canary,
                     payload, hashlib.sha256(payload.encode('utf-8')).hexdigest()))
            except sqlite3.IntegrityError as exc:
                raise ScheduleError('job ID already exists') from exc
            self._event('schedule_created', id, now, due_at=timestamp(due_at),
                        host_count=len(invocation.hosts), command_sha256=command_hash, canary=invocation.options.canary)
            return self._info(self._row(id))

    def get(self, id):
        with self._lock:
            self._check_schema()
            return self._info(self._row(id))

    def list(self, limit=20, offset=0):
        if (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200
                or not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
            raise ScheduleError('list limit must be 1..200 and offset nonnegative')
        with self._lock:
            self._check_schema()
            # Do not materialize inventories or outputs when listing schedules.
            fields = ','.join(JobInfo.__dataclass_fields__)
            return [self._info(row) for row in self.db.execute(
                f'SELECT {fields} FROM jobs ORDER BY seq DESC LIMIT ? OFFSET ?', (limit, offset))]

    def cancel(self, id, now):
        with self._transaction():
            row = self._row(id)
            if row['state'] != JobState.PENDING:
                raise ScheduleError('only a pending job can be cancelled; running jobs are never replayed')
            self.db.execute('UPDATE jobs SET state=?,finished_at=?,reason=? WHERE id=?',
                            (JobState.CANCELLED, timestamp(now), 'cancelled_by_operator', id))
            self._event('schedule_cancelled', id, now)
            return self._info(self._row(id))

    def purge(self, id, now):
        with self._transaction():
            row = self._row(id)
            if JobState(row['state']) not in TERMINAL_STATES:
                raise ScheduleError('only a terminal job can be purged')
            self.db.execute('DELETE FROM jobs WHERE id=?', (id,))
            self._event('schedule_purged', id, now)

    def recover_running(self, now):
        with self._transaction():
            rows = self.db.execute('SELECT id FROM jobs WHERE state=?', (JobState.RUNNING,)).fetchall()
            for row in rows:
                id = row['id']
                self.db.execute('UPDATE jobs SET state=?,finished_at=?,reason=? WHERE id=?',
                                (JobState.INTERRUPTED, timestamp(now), 'previous_worker_stopped_no_replay', id))
                self._event('schedule_interrupted', id, now, reason='previous_worker_stopped_no_replay')
            return len(rows)

    def claim_due(self, now):
        now = utc_time(now)
        with self._transaction():
            missed = self.db.execute('SELECT id FROM jobs WHERE state=? AND deadline<?',
                                     (JobState.PENDING, timestamp(now))).fetchall()
            for row in missed:
                self.db.execute('UPDATE jobs SET state=?,finished_at=?,reason=? WHERE id=?',
                                (JobState.MISSED, timestamp(now), 'misfire_grace_exceeded', row['id']))
                self._event('schedule_missed', row['id'], now)
            while row := self.db.execute('SELECT * FROM jobs WHERE state=? AND due_at<=? ORDER BY due_at,seq LIMIT 1',
                                         (JobState.PENDING, timestamp(now))).fetchone():
                try:
                    if hashlib.sha256(row['payload'].encode('utf-8')).hexdigest() != row['payload_sha256']:
                        raise ScheduleError('scheduled snapshot integrity failed')
                    self._info(row)
                    invocation = decode_invocation(row['payload'])
                    if (len(invocation.hosts) != row['host_count'] or invocation.options.canary != row['canary']
                            or invocation.report_path != row['report_path']
                            or hashlib.sha256(invocation.command.encode('utf-8')).hexdigest() != row['command_sha256']):
                        raise ScheduleError('scheduled snapshot metadata mismatch')
                except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                    self.db.execute('UPDATE jobs SET state=?,finished_at=?,reason=? WHERE id=?',
                                    (JobState.FAILED, timestamp(now), 'invalid_job_snapshot', row['id']))
                    self._event('schedule_failed', row['id'], now, reason='invalid_job_snapshot')
                    continue
                self.db.execute('UPDATE jobs SET state=?,started_at=? WHERE id=?',
                                (JobState.RUNNING, timestamp(now), row['id']))
                self._event('schedule_started', row['id'], now, host_count=row['host_count'])
                return ClaimedJob(self._info(self._row(row['id'])), invocation)
            return None

    def finish_failure(self, id, now, diagnostic):
        """Atomically commit failed state and its safe outbox diagnostic."""
        if not isinstance(diagnostic, ExecutionFailure):
            raise ScheduleError('invalid execution diagnostic')
        return self.finish(id, JobState.FAILED, now, reason='execution_or_report_error',
                           diagnostic=diagnostic)

    def finish(self, id, state, now, *, summary=None, reason=None, diagnostic=None):
        if not isinstance(state, JobState) or state not in (JobState.SUCCEEDED, JobState.FAILED, JobState.INTERRUPTED):
            raise ScheduleError('invalid execution terminal state')
        if diagnostic is not None and (not isinstance(diagnostic, ExecutionFailure) or state != JobState.FAILED):
            raise ScheduleError('invalid execution diagnostic')
        with self._transaction():
            row = self._row(id)
            if row['state'] != JobState.RUNNING:
                raise ScheduleError('job is not running')
            counts, run_id = None, None
            if summary is not None:
                if (set(summary.counts) != {status.value for status in Status}
                        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in summary.counts.values())
                        or sum(summary.counts.values()) != row['host_count']):
                    raise ScheduleError('invalid execution counters')
                counts, run_id = json.dumps(summary.counts), summary.run_id
                if run_id is not None:
                    validate_job_id(run_id)
            self.db.execute('UPDATE jobs SET state=?,finished_at=?,counts=?,run_id=?,reason=? WHERE id=?',
                            (state, timestamp(now), counts, run_id, reason, id))
            self._event('schedule_' + state.value, id, now, state=state.value, run_id=run_id,
                        counts=summary.counts if summary is not None else None, reason=reason,
                        **({'diagnostic': asdict(diagnostic)} if diagnostic is not None else {}))
            return self._info(self._row(id))

    def events(self, limit=64):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ScheduleError("event batch must be between 1 and 200")
        with self._lock:
            self._check_schema()
            return [(row['seq'], json.loads(row['payload'])) for row in self.db.execute(
                'SELECT seq,payload FROM events ORDER BY seq LIMIT ?', (limit,))]

    def acknowledge_events(self, through):
        with self._transaction():
            self.db.execute('DELETE FROM events WHERE seq<=?', (through,))
