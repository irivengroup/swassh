"""Private bounded dependency workflows with durable claims and an audit outbox."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from ..application.contracts import RunSummary
from ..application.workflow_contracts import PreparedWorkflow, WorkflowInfo, WorkflowStepInfo, WorkflowVerificationInfo
from ..application.schedule_contracts import ExecutionFailure
from ..domain.models import Status
from ..domain.scheduling import timestamp, validate_job_id
from ..domain.workflows import Workflow, WorkflowError, WorkflowState, _identifier
from .audit import _WriterLock
from .database.migration.workflows_v1 import APPLICATION_ID, WorkflowSchema
from .filesystem import open_private_append, private_directory
from .inventory import _unique_object, _invalid_constant
from .schedule_store import encode_invocation, decode_invocation

MAX_PAYLOAD = 10 * 1024**2
MAX_RUNS = 1000


def encode_prepared(prepared):
    data = {'schema_version': 1, 'workflow': prepared.workflow.to_dict(),
            'invocations': [encode_invocation(item) for item in prepared.invocations]}
    payload = json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if len(payload.encode()) > MAX_PAYLOAD:
        raise WorkflowError('prepared workflow exceeds its 10 MiB snapshot budget')
    return payload


def decode_prepared(payload):
    if not isinstance(payload, str) or len(payload.encode()) > MAX_PAYLOAD:
        raise WorkflowError('workflow snapshot exceeds its budget')
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if (not isinstance(value, dict) or set(value) != {'schema_version','workflow','invocations'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or not isinstance(value['invocations'], list) or not 1 <= len(value['invocations']) <= 256):
            raise ValueError('unsupported workflow snapshot schema')
        return PreparedWorkflow(Workflow.from_dict(value['workflow']),
                                tuple(decode_invocation(item) for item in value['invocations']))
    except (ValueError, TypeError, RecursionError):
        raise WorkflowError('invalid durable workflow snapshot') from None


class SQLiteWorkflowStore:
    """One serial fleet worker per store; metadata is bounded independently of reports.

    Remote effects never happen inside a database transaction. Claims and their
    outbox events commit first. A crash changes running checkpoints to interrupted;
    successful checkpoints remain terminal and are never automatically rerun.
    """

    def __init__(self, directory, *, max_runs=MAX_RUNS):
        if type(max_runs) is not int or not 1 <= max_runs <= MAX_RUNS:
            raise WorkflowError('workflow store capacity must be 1..1000 runs')
        self.directory = private_directory(Path(directory).expanduser().absolute(), tighten=True)
        self.max_runs, self.lock = max_runs, threading.RLock()
        self.path = self.directory / 'workflows.sqlite'
        with open_private_append(self.path):
            pass
        if self.path.stat().st_size > 128 * 1024**2:
            raise WorkflowError('workflow database exceeds 128 MiB')
        self.db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=3,
                                 isolation_level=None, check_same_thread=False)
        try:
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=EXTRA')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA cache_size=-2048')
            page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
            self.db.execute('PRAGMA max_page_count=' + str(128 * 1024**2 // page_size))
            with self._transaction():
                WorkflowSchema.up(self.db)
            self.schema_version = self.db.execute('PRAGMA schema_version').fetchone()[0]
            self.db.row_factory = sqlite3.Row
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def _transaction(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                if hasattr(self, 'schema_version') and (
                        self.db.execute('PRAGMA schema_version').fetchone()[0] != self.schema_version
                        or self.db.execute('PRAGMA user_version').fetchone()[0] != 1
                        or self.db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID):
                    raise WorkflowError('workflow schema changed while open')
                yield
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def close(self):
        with self.lock:
            self.db.close()

    @contextmanager
    def worker_lock(self):
        try:
            owner = _WriterLock(self.directory / 'worker')
        except OSError:
            raise WorkflowError('another workflow worker or maintenance operation is active') from None
        try:
            yield
        finally:
            owner.close()

    def _event(self, event, id, now, **fields):
        payload = json.dumps({'event': event, 'fields': {'workflow_id': id,
            'occurred_at': timestamp(now), **fields}}, ensure_ascii=True, allow_nan=False)
        self.db.execute('INSERT INTO events(payload) VALUES (?)', (payload,))

    def _row(self, id, *, payload=False):
        validate_job_id(id)
        columns = '*' if payload else 'id,name,state,created_at,payload_sha256,checkpoint_sha256'
        row = self.db.execute('SELECT ' + columns + ' FROM runs WHERE id=?', (id,)).fetchone()
        if row is None:
            raise WorkflowError('workflow not found')
        return row

    @staticmethod
    def _checkpoint_digest(rows):
        values=[(row['step_id'],row['ordinal'],row['needs'],row['host_count'],row['report_path']) for row in rows]
        return hashlib.sha256(json.dumps(values,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()

    def _checkpoints(self,row):
        steps=self.db.execute('SELECT * FROM steps WHERE run_id=? ORDER BY ordinal',(row['id'],)).fetchall()
        self._check_checkpoint_digest(row,steps)
        return steps

    def _check_checkpoint_digest(self,row,steps):
        if not 1<=len(steps)<=256 or self._checkpoint_digest(steps)!=row['checkpoint_sha256']:
            raise WorkflowError('workflow checkpoint metadata changed; preserve the database')

    @staticmethod
    def _step_info(row):
        counts = json.loads(row['counts'],object_pairs_hook=_unique_object,parse_constant=_invalid_constant) if row['counts'] is not None else None
        if counts is not None and not isinstance(counts, dict):
            raise WorkflowError('invalid workflow counters')
        verification = None
        if row['verification'] is not None:
            value = json.loads(row['verification'], object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
            if not isinstance(value, dict) or set(value) != {'attempt','report_path','finished_at','run_id','counts'} or not isinstance(value['counts'], dict):
                raise WorkflowError('invalid workflow verification metadata')
            verification = WorkflowVerificationInfo(value['attempt'], value['report_path'], value['finished_at'],
                value['run_id'], tuple(value['counts'].items()), row['host_count'])
        return WorkflowStepInfo(row['step_id'], WorkflowState(row['state']), row['host_count'],
            row['report_path'], row['started_at'], row['finished_at'], row['reason'],
            row['execution_id'], tuple(counts.items()) if counts is not None else None, verification)

    def _info(self, row):
        steps = self._checkpoints(row)
        return WorkflowInfo(row['id'], row['name'], WorkflowState(row['state']), row['created_at'],
                            row['payload_sha256'], tuple(self._step_info(step) for step in steps))

    def get(self, id):
        with self.lock:
            return self._info(self._row(id))

    def list(self, limit=20, offset=0):
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= 1000000:
            raise WorkflowError('invalid workflow pagination')
        with self.lock:
            rows = self.db.execute('SELECT id,name,state,created_at,payload_sha256,checkpoint_sha256 FROM runs ORDER BY seq DESC LIMIT ? OFFSET ?',
                                   (limit, offset)).fetchall()
            if not rows:
                return []
            placeholders = ','.join('?' for row in rows)
            grouped = {row['id']: [] for row in rows}
            for step in self.db.execute('SELECT * FROM steps WHERE run_id IN (' + placeholders + ') ORDER BY ordinal',
                                        tuple(grouped)):
                grouped[step['run_id']].append(step)
            for row in rows:
                self._check_checkpoint_digest(row,grouped[row['id']])
            return [WorkflowInfo(row['id'], row['name'], WorkflowState(row['state']), row['created_at'],
                                 row['payload_sha256'], tuple(self._step_info(step) for step in grouped[row['id']])) for row in rows]

    def definition(self, id):
        with self.lock:
            row = self._row(id, payload=True)
            if hashlib.sha256(row['payload'].encode()).hexdigest() != row['payload_sha256']:
                raise WorkflowError('workflow snapshot digest mismatch; preserve the database')
            prepared = decode_prepared(row['payload'])
            if prepared.workflow.name != row['name']:
                raise WorkflowError('workflow metadata does not match its snapshot')
            steps=self._checkpoints(row)
            expected=[{'step_id':step.id,'ordinal':ordinal,'needs':json.dumps(step.needs),
                       'host_count':len(step.hosts),'report_path':invocation.report_path}
                for ordinal,(step,invocation) in enumerate(zip(prepared.workflow.ordered_steps,prepared.invocations))]
            if self._checkpoint_digest(expected)!=self._checkpoint_digest(steps):
                raise WorkflowError('workflow checkpoints do not match the definition')
            return prepared

    def create(self, id, prepared, now):
        validate_job_id(id)
        if not isinstance(prepared, PreparedWorkflow):
            raise WorkflowError('prepared workflow required')
        payload = encode_prepared(prepared)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with self._transaction():
            if self.db.execute('SELECT count(*) FROM runs').fetchone()[0] >= self.max_runs:
                raise WorkflowError('workflow store is full; archive terminal records explicitly')
            expected=[{'step_id':step.id,'ordinal':ordinal,'needs':json.dumps(step.needs),
                       'host_count':len(step.hosts),'report_path':invocation.report_path}
                for ordinal,(step,invocation) in enumerate(zip(prepared.workflow.ordered_steps,prepared.invocations))]
            self.db.execute('INSERT INTO runs(id,name,state,created_at,payload,payload_sha256,checkpoint_sha256) VALUES (?,?,?,?,?,?,?)',
                (id, prepared.workflow.name, 'pending', timestamp(now), payload, digest,self._checkpoint_digest(expected)))
            for ordinal, (step, invocation) in enumerate(zip(prepared.workflow.ordered_steps, prepared.invocations)):
                self.db.execute('INSERT INTO steps(run_id,step_id,ordinal,needs,state,host_count,report_path) VALUES (?,?,?,?,?,?,?)',
                    (id, step.id, ordinal, json.dumps(step.needs), 'pending', len(step.hosts), invocation.report_path))
            self._event('workflow_registered', id, now, step_count=len(prepared.invocations), definition_sha256=digest)
            return self._info(self._row(id))

    def claim_run(self, now):
        with self._transaction():
            if self.db.execute("SELECT 1 FROM runs WHERE state='running' LIMIT 1").fetchone():
                raise WorkflowError('an unrecovered workflow is already running')
            row = self.db.execute("SELECT id FROM runs WHERE state='pending' ORDER BY seq LIMIT 1").fetchone()
            if row is None:
                return None
            self.db.execute("UPDATE runs SET state='running' WHERE id=?", (row['id'],))
            self._event('workflow_started', row['id'], now)
            return row['id']

    def claim_step(self, id, now):
        with self._transaction():
            root=self._row(id)
            if root['state'] != 'running':
                raise WorkflowError('workflow is not running')
            rows = self._checkpoints(root)
            states = {row['step_id']: WorkflowState(row['state']) for row in rows}
            if WorkflowState.RUNNING in states.values():
                raise WorkflowError('a workflow checkpoint is already running')
            for row in rows:
                if row['state'] != 'pending':
                    continue
                needs = json.loads(row['needs'])
                if not isinstance(needs, list) or len(needs) > 256 or any(name not in states for name in needs):
                    raise WorkflowError('invalid persisted workflow dependencies')
                if any(states[name] in (WorkflowState.FAILED, WorkflowState.BLOCKED,
                                       WorkflowState.INTERRUPTED, WorkflowState.CANCELLED) for name in needs):
                    self.db.execute("UPDATE steps SET state='blocked',finished_at=?,reason='dependency_failed' WHERE run_id=? AND step_id=?",
                                    (timestamp(now), id, row['step_id']))
                    states[row['step_id']] = WorkflowState.BLOCKED
                    self._event('workflow_step_blocked', id, now, step_id=row['step_id'])
                elif all(states[name] == WorkflowState.SUCCEEDED for name in needs):
                    self.db.execute("UPDATE steps SET state='running',started_at=?,finished_at=NULL,reason=NULL WHERE run_id=? AND step_id=?",
                                    (timestamp(now), id, row['step_id']))
                    self._event('workflow_step_started', id, now, step_id=row['step_id'])
                    return row['step_id']
            if any(state in (WorkflowState.RUNNING, WorkflowState.PENDING) for state in states.values()):
                raise WorkflowError('workflow has unresolved or concurrently running checkpoints')
            final = 'succeeded' if all(state == WorkflowState.SUCCEEDED for state in states.values()) else 'failed'
            self.db.execute('UPDATE runs SET state=? WHERE id=?', (final, id))
            self._event('workflow_completed', id, now, state=final)
            return None

    @staticmethod
    def _summary(summary, expected):
        if (not isinstance(summary, RunSummary) or type(summary.total) is not int or summary.total != expected
                or set(summary.counts) != {status.value for status in Status}
                or any(type(value) is not int or value < 0 for value in summary.counts.values())
                or sum(summary.counts.values()) != expected):
            raise WorkflowError('invalid workflow execution summary')
        if summary.run_id is not None:
            validate_job_id(summary.run_id)
        return json.dumps(summary.counts, allow_nan=False)

    def finish_step(self, id, step, succeeded, now, summary=None, failure=None):
        _identifier(step)
        if type(succeeded) is not bool:
            raise WorkflowError('workflow completion must be boolean')
        if failure is not None and (not isinstance(failure, ExecutionFailure) or succeeded or summary is not None):
            raise WorkflowError('invalid workflow failure metadata')
        with self._transaction():
            self._checkpoints(self._row(id))
            row = self.db.execute('SELECT state,host_count FROM steps WHERE run_id=? AND step_id=?', (id, step)).fetchone()
            if row is None or row['state'] != 'running':
                raise WorkflowError('workflow checkpoint is not running')
            counts = self._summary(summary, row['host_count']) if summary is not None else None
            if succeeded and (summary is None or not summary.ok):
                raise WorkflowError('workflow success requires a complete successful summary')
            state = 'succeeded' if succeeded else 'failed'
            self.db.execute('UPDATE steps SET state=?,finished_at=?,reason=?,execution_id=?,counts=? WHERE run_id=? AND step_id=?',
                (state, timestamp(now), None if succeeded else 'execution_failed',
                 summary.run_id if summary else None, counts, id, step))
            details = {} if failure is None else {'failure_category': failure.category,
                'error_type': failure.error_type, 'errno': failure.errno}
            self._event('workflow_step_completed', id, now, step_id=step, state=state, **details)

    def recover(self, now):
        with self._transaction():
            running = self.db.execute("SELECT id FROM runs WHERE state='running'").fetchall()
            for row in running:
                self.db.execute("UPDATE steps SET state='interrupted',finished_at=?,reason='worker_interrupted' WHERE run_id=? AND state='running'",
                                (timestamp(now), row['id']))
                self.db.execute("UPDATE runs SET state='interrupted' WHERE id=?", (row['id'],))
                self._event('workflow_interrupted', row['id'], now)
            return len(running)

    def resume(self, id, now):
        with self._transaction():
            if self._row(id)['state'] not in ('failed', 'interrupted'):
                raise WorkflowError('only a reconciled failed or interrupted workflow can resume')
            if self.db.execute("SELECT 1 FROM steps WHERE run_id=? AND state IN ('running','failed','interrupted','cancelled') LIMIT 1", (id,)).fetchone():
                raise WorkflowError('verify every failed or interrupted step before resuming; no automatic replay')
            self.db.execute("UPDATE steps SET state='pending',finished_at=NULL,reason=NULL WHERE run_id=? AND state='blocked'", (id,))
            self.db.execute("UPDATE runs SET state='pending' WHERE id=?", (id,))
            self._event('workflow_resumed', id, now)
            return self._info(self._row(id))

    def prepare_reconciliation(self, id, step, now):
        _identifier(step)
        with self._transaction():
            if self._row(id)['state'] not in ('failed', 'interrupted'):
                raise WorkflowError('workflow must be stopped before reconciliation')
            row = self.db.execute('SELECT state,reconciliation_count FROM steps WHERE run_id=? AND step_id=?', (id, step)).fetchone()
            if row is None or row['state'] not in ('failed', 'interrupted'):
                raise WorkflowError('only failed or interrupted steps require reconciliation')
            if type(row['reconciliation_count']) is not int or not 0 <= row['reconciliation_count'] < 16:
                raise WorkflowError('workflow reconciliation budget exhausted; retain its evidence')
            ordinal = row['reconciliation_count'] + 1
            self.db.execute('UPDATE steps SET reconciliation_count=? WHERE run_id=? AND step_id=?', (ordinal, id, step))
            self._event('workflow_reconciliation_started', id, now, step_id=step, attempt=ordinal)
            return ordinal

    def reconcile(self, id, step, now, summary):
        with self._transaction():
            if self._row(id)['state'] not in ('failed', 'interrupted'):
                raise WorkflowError('workflow is not stopped')
            row = self.db.execute('SELECT state,host_count,report_path,reconciliation_count FROM steps WHERE run_id=? AND step_id=?', (id, step)).fetchone()
            if row is None or row['state'] not in ('failed', 'interrupted'):
                raise WorkflowError('workflow checkpoint cannot be reconciled')
            self._summary(summary, row['host_count'])
            receipt = WorkflowVerificationInfo(row['reconciliation_count'],
                str(Path(row['report_path']).with_name('reconcile-' + str(row['reconciliation_count']) + '.json')),
                timestamp(now), summary.run_id, tuple(summary.counts.items()), row['host_count'])
            self.db.execute('UPDATE steps SET verification=? WHERE run_id=? AND step_id=?',
                            (json.dumps(receipt.to_dict()), id, step))
            if not summary.ok:
                self._event('workflow_reconciliation_failed', id, now, step_id=step)
                return False
            self.db.execute("UPDATE steps SET state='succeeded',reason='verified_after_interruption' WHERE run_id=? AND step_id=?", (id, step))
            self._event('workflow_step_reconciled', id, now, step_id=step)
            return True

    def cancel(self, id, now):
        with self._transaction():
            if self._row(id)['state'] != 'pending':
                raise WorkflowError('only pending workflows can be cancelled')
            self.db.execute("UPDATE steps SET state='cancelled',finished_at=?,reason='cancelled' WHERE run_id=? AND state='pending'", (timestamp(now), id))
            self.db.execute("UPDATE runs SET state='cancelled' WHERE id=?", (id,))
            self._event('workflow_cancelled', id, now)
            return self._info(self._row(id))

    def events(self, limit=64):
        if type(limit) is not int or not 1 <= limit <= 64:
            raise WorkflowError('invalid workflow outbox limit')
        with self.lock:
            return [(row['seq'], json.loads(row['payload'])) for row in self.db.execute(
                'SELECT seq,payload FROM events ORDER BY seq LIMIT ?', (limit,))]

    def purge(self, id, now):
        """Remove terminal metadata explicitly; never remove reports or outbox evidence."""
        with self._transaction():
            if self._row(id)['state'] not in ('succeeded', 'failed', 'cancelled'):
                raise WorkflowError('only terminal workflows can be purged')
            self.db.execute('DELETE FROM runs WHERE id=?', (id,))
            self._event('workflow_purged', id, now)

    def acknowledge_events(self, through):
        if type(through) is not int or through < 0:
            raise WorkflowError('invalid workflow audit cursor')
        with self._transaction():
            self.db.execute('DELETE FROM events WHERE seq<=?', (through,))
