"""DAG contracts and isolated persistence/recovery integration; no remote targets."""
import asyncio
from contextlib import asynccontextmanager,nullcontext
from dataclasses import replace
from datetime import UTC, datetime
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import DesiredState, Host, Options, Workflow, WorkflowStep, WorkflowState, WorkflowError, WorkflowRunner, Swarm
from swassh.application.contracts import RunSummary
from swassh.application.schedule_contracts import ScheduledInvocation, ExecutionFailure
from swassh.application.workflow_contracts import PreparedWorkflow, WorkflowStepInfo, WorkflowVerificationInfo
from swassh.application.workflows import WorkflowService
from swassh.domain.models import Status
from swassh.infrastructure.audit import AuditTrail
from swassh.infrastructure.database.migration.workflows_v1 import WorkflowSchema
from swassh.infrastructure.resources import resource_plan
from swassh.infrastructure.workflow_execution import load_workflow, prepare_workflow, NativeWorkflowExecutor
from swassh.infrastructure import workflow_execution
from swassh.infrastructure.workflow_store import SQLiteWorkflowStore, encode_prepared, decode_prepared
from swassh.interfaces import cli
from swassh.interfaces import workflows as workflow_interfaces

NOW = datetime(2030, 1, 1, tzinfo=UTC)
ID, OTHER = 'a' * 32, 'b' * 32


def graph():
    return Workflow('release', (
        WorkflowStep('install', ('one',), command='install-private-value', reconcile_check='check-installed'),
        WorkflowStep('restart', ('one',), command='restart', needs=('install',)),
        WorkflowStep('independent', ('two',), action=DesiredState('setting', 'check', 'apply'))))


def prepared(root, workflow=None):
    workflow = workflow if workflow is not None else graph()
    return PreparedWorkflow(workflow, tuple(ScheduledInvocation(step.descriptor, step.hosts, Options(),
        str(Path(root) / 'runs' / ID / step.id / 'report.json')) for step in workflow.ordered_steps))


def result(invocation, success=True, run_id='c' * 32):
    counts = {status.value: 0 for status in Status}
    counts['success' if success else 'failed'] = len(invocation.hosts)
    return RunSummary(len(invocation.hosts), counts, NOW, NOW, resource_plan(invocation.options), run_id)


class DomainTests(unittest.TestCase):
    def test_step_host_limits_and_object_schema_reject_oversize_before_normalization(self):
        step=graph().steps[0]
        with self.assertRaises(WorkflowError):replace(step,hosts=(Host('one'),)*100001)
        oversized=step.to_dict();oversized['hosts']=[step.to_dict()['hosts'][0]]*100001
        with self.assertRaises(WorkflowError):WorkflowStep.from_dict(oversized)
        invalid=step.to_dict();invalid['hosts']=[1]
        with self.assertRaises(WorkflowError):WorkflowStep.from_dict(invalid)

    def test_topology_roundtrip_and_redacted_metadata(self):
        value = graph()
        self.assertEqual([node.id for node in value.ordered_steps], ['install','independent','restart'])
        self.assertEqual(Workflow.from_dict(value.to_dict()), value)
        self.assertEqual(Workflow.from_dict(value.to_dict()).digest, value.digest)
        self.assertNotIn('private-value', repr(value))
        plan = WorkflowRunner.plan(value, Options(ssh_executable='absent-test-client'))
        self.assertFalse(plan['automatic_replay'])
        self.assertNotIn('private-value', json.dumps(plan))
        self.assertEqual(plan['fleet_dispatch'], 'sequential')

    def test_plan_uses_native_memory_cost_and_resolved_target_identities(self):
        options=Options(username='admin',ssh_executable='absent-test-client')
        plan=WorkflowRunner.plan(graph(),options)
        self.assertEqual(plan['resource_plan_per_step'],Swarm(options).plan().to_dict())
        with self.assertRaises(TypeError): WorkflowRunner.plan(graph(),object())
        with self.assertRaises(ValueError): WorkflowRunner.plan(graph(),Options(memory_budget_mib=8))

    def test_invalid_nodes_edges_graphs_and_schema(self):
        valid = WorkflowStep('one', ('one',), command='true')
        for changes in ({'id':'../outside'}, {'hosts':[]}, {'hosts':()}, {'command':None},
                {'action':DesiredState('state','check','apply')}, {'needs':['one']},
                {'needs':('one',)}, {'needs':('two','two')}, {'reconcile_check':'true'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(valid, **changes)
        for nodes in ((), (valid,valid), (replace(valid,needs=('absent',)),),
                (replace(valid,needs=('two',)), WorkflowStep('two',('one',), command='true',needs=('one',)))):
            with self.subTest(nodes=nodes), self.assertRaises(WorkflowError):
                Workflow('plan', nodes)
        for value in ({}, {'schema_version':True,'name':'x','steps':[valid.to_dict()]},
                {'schema_version':1,'name':'x','steps':[]}, {'schema_version':1,'name':'x','steps':[{}]}):
            with self.subTest(value=value), self.assertRaises(WorkflowError):
                Workflow.from_dict(value)
        for value in ({'id':'one','hosts':['one'],'unknown':1}, {'id':'one','hosts':[{}]},
                {'id':'one','hosts':['one'],'needs':'x'}):
            with self.assertRaises(WorkflowError):
                WorkflowStep.from_dict(value)

    def test_prepared_and_checkpoint_invariants(self):
        value = prepared(Path.cwd())
        self.assertEqual(value.invocation('install').command, 'install-private-value')
        with self.assertRaises(WorkflowError):
            value.invocation('missing')
        for invocations in ((), list(value.invocations), (replace(value.invocations[0],command='wrong'), *value.invocations[1:]),
                (replace(value.invocations[0],options=Options(retries=1)), *value.invocations[1:])):
            with self.assertRaises(WorkflowError):
                PreparedWorkflow(value.workflow, invocations)
        good = WorkflowStepInfo('one', WorkflowState.PENDING, 1, str(Path.cwd() / 'report.json'))
        for change in ({'host_count':True}, {'report_path':'../report'}, {'started_at':'yesterday'},
                       {'reason':'secret message'}, {'run_id':'invalid'}, {'counts':(('success',1),)}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(good, **change)
        for opts in (Options(retries=1), Options(pty=True)):
            with self.assertRaises(WorkflowError):
                WorkflowRunner.plan(value.workflow, opts)


class StoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SQLiteWorkflowStore(self.root / 'state', max_runs=2)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.store.close)
        self.plan = prepared(self.root)

    def create(self, id=ID):
        return self.store.create(id, self.plan, NOW)

    def complete(self, step, success=True):
        self.store.finish_step(ID, step, success, NOW, result(self.plan.invocation(step),success))

    def test_oversized_persisted_store_is_rejected_before_opening_sqlite(self):
        root=self.root/'oversized';root.mkdir();path=root/'workflows.sqlite'
        with path.open('wb') as stream:stream.truncate(128*1024**2+1)
        with patch('swassh.infrastructure.workflow_store.sqlite3.connect',side_effect=AssertionError('oversize store parsed')) as connect,\
                self.assertRaisesRegex(WorkflowError,'exceeds 128 MiB'):SQLiteWorkflowStore(root)
        connect.assert_not_called();self.assertEqual(path.stat().st_size,128*1024**2+1)

    def test_invocation_and_pagination_upper_bounds_do_not_consume_events(self):
        value=json.loads(encode_prepared(self.plan));value['invocations']*=86
        self.assertGreater(len(value['invocations']),256)
        with self.assertRaisesRegex(WorkflowError,'invalid durable workflow snapshot'):decode_prepared(json.dumps(value))
        self.create();before=self.store.events()
        for offset in (True,1.5,'0',1000001):
            with self.subTest(offset=offset),self.assertRaisesRegex(WorkflowError,'pagination'):self.store.list(1,offset)
        self.assertEqual(self.store.events(),before)

    def test_empty_persisted_checkpoint_set_is_not_a_successful_workflow(self):
        self.create();self.store.db.execute('DELETE FROM steps WHERE run_id=?',(ID,))
        before=self.store.events()
        with self.assertRaisesRegex(WorkflowError,'checkpoint metadata changed'):self.store.get(ID)
        self.assertEqual(self.store.events(),before)

    def test_257_persisted_checkpoints_are_refused_without_truncation_or_repair(self):
        self.create()
        for ordinal in range(3,257):
            self.store.db.execute("INSERT INTO steps(run_id,step_id,ordinal,needs,state,host_count,report_path) VALUES (?, ?, ?, '[]','pending',1,'synthetic')",
                (ID,'extra'+str(ordinal),ordinal))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM steps').fetchone()[0],257)
        with self.assertRaisesRegex(WorkflowError,'checkpoint metadata changed'):self.store.get(ID)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM steps').fetchone()[0],257)

    def test_pending_workflow_and_pending_checkpoint_cannot_be_claimed_or_finished_as_running(self):
        self.create();before=self.store.events()
        with self.assertRaisesRegex(WorkflowError,'workflow is not running'):self.store.claim_step(ID,NOW)
        with self.assertRaisesRegex(WorkflowError,'checkpoint is not running'):
            self.store.finish_step(ID,'install',True,NOW,result(self.plan.invocation('install')))
        self.assertEqual(self.store.events(),before);self.assertEqual(self.store.get(ID).state,WorkflowState.PENDING)

    def test_failed_summary_cannot_commit_success_but_optional_run_identity_can_be_absent(self):
        self.create();self.store.claim_run(NOW);self.assertEqual(self.store.claim_step(ID,NOW),'install')
        before=self.store.events()
        with self.assertRaisesRegex(WorkflowError,'complete successful summary'):
            self.store.finish_step(ID,'install',True,NOW,result(self.plan.invocation('install'),False))
        self.assertEqual(self.store.events(),before)
        summary=replace(result(self.plan.invocation('install')),run_id=None)
        self.store.finish_step(ID,'install',True,NOW,summary)
        info=self.store.get(ID).steps[0]
        self.assertEqual(info.state,WorkflowState.SUCCEEDED);self.assertIsNone(info.run_id)
        self.assertEqual(dict(info.counts),summary.counts)

    def test_corrupt_reconciliation_counter_is_refused_and_completed_sibling_is_not_reconciled(self):
        self.create();self.store.claim_run(NOW);self.store.claim_step(ID,NOW);self.complete('install',False)
        self.assertEqual(self.store.claim_step(ID,NOW),'independent');self.complete('independent')
        self.assertIsNone(self.store.claim_step(ID,NOW))
        for count in (0.5,-1):
            if count<0:self.store.db.execute('PRAGMA ignore_check_constraints=ON')
            self.store.db.execute("UPDATE steps SET reconciliation_count=? WHERE step_id='install'",(count,))
            self.store.db.execute('PRAGMA ignore_check_constraints=OFF')
            before=self.store.events()
            with self.subTest(count=count),self.assertRaisesRegex(WorkflowError,'reconciliation budget exhausted'):
                self.store.prepare_reconciliation(ID,'install',NOW)
            self.assertEqual(self.store.events(),before)
            self.assertEqual(self.store.db.execute("SELECT reconciliation_count FROM steps WHERE step_id='install'").fetchone()[0],count)
        before=self.store.events()
        with self.assertRaisesRegex(WorkflowError,'checkpoint cannot be reconciled'):
            self.store.reconcile(ID,'independent',NOW,result(self.plan.invocation('independent')))
        self.assertEqual(self.store.events(),before)

    def test_registration_snapshot_integrity_and_pagination(self):
        info = self.create()
        self.assertEqual(self.store.definition(ID), self.plan)
        self.assertEqual(decode_prepared(encode_prepared(self.plan)), self.plan)
        self.assertNotIn('private-value', json.dumps(info.to_dict()))
        self.create(OTHER)
        statements=[]
        self.store.db.set_trace_callback(statements.append)
        self.assertEqual([item.id for item in self.store.list(2)], [OTHER,ID])
        self.assertEqual(sum(sql.startswith('SELECT') for sql in statements), 2)
        self.store.db.set_trace_callback(None)
        self.assertEqual(self.store.list(2,2), [])
        with self.assertRaises(WorkflowError): self.create('d'*32)
        for args in ((0,0), (201,0), (True,0), (1,-1)):
            with self.assertRaises(WorkflowError): self.store.list(*args)
        self.store.db.execute("UPDATE runs SET payload=payload || ' ' WHERE id=?", (ID,))
        with self.assertRaisesRegex(WorkflowError,'digest'): self.store.definition(ID)

    def test_dag_orders_all_dependencies_and_never_repeats_success(self):
        self.create()
        self.assertEqual(self.store.claim_run(NOW), ID)
        for step in ('install','independent','restart'):
            self.assertEqual(self.store.claim_step(ID,NOW), step)
            with self.assertRaises(WorkflowError): self.store.claim_step(ID,NOW)
            self.complete(step)
        self.assertIsNone(self.store.claim_step(ID,NOW))
        self.assertEqual(self.store.get(ID).state,WorkflowState.SUCCEEDED)
        self.assertIsNone(self.store.claim_run(NOW))
        with self.assertRaises(WorkflowError): self.store.resume(ID,NOW)

    def test_failed_dependency_blocks_descendants_but_independent_branch_runs(self):
        self.create(); self.store.claim_run(NOW)
        self.assertEqual(self.store.claim_step(ID,NOW),'install')
        self.complete('install',False)
        self.assertEqual(self.store.claim_step(ID,NOW),'independent')
        self.complete('independent')
        self.assertIsNone(self.store.claim_step(ID,NOW))
        info=self.store.get(ID)
        self.assertEqual(info.state,WorkflowState.FAILED)
        self.assertEqual({step.id:step.state for step in info.steps}['restart'],WorkflowState.BLOCKED)
        with self.assertRaisesRegex(WorkflowError,'verify every'): self.store.resume(ID,NOW)
        original=info.steps[0]
        self.assertEqual(self.store.prepare_reconciliation(ID,'install',NOW),1)
        self.assertFalse(self.store.reconcile(ID,'install',NOW,result(self.plan.invocation('install'),False)))
        self.assertEqual(self.store.prepare_reconciliation(ID,'install',NOW),2)
        self.assertTrue(self.store.reconcile(ID,'install',NOW,result(self.plan.invocation('install'),run_id='d'*32)))
        after=self.store.get(ID).steps[0]
        self.assertEqual(after.run_id,original.run_id)
        self.assertEqual(after.counts,original.counts)
        self.assertEqual(after.report_path,original.report_path)
        self.assertEqual(after.verification.run_id,'d'*32)
        self.assertTrue(after.verification.report_path.endswith('reconcile-2.json'))
        self.store.resume(ID,NOW); self.store.claim_run(NOW)
        self.assertEqual(self.store.claim_step(ID,NOW),'restart')
        self.complete('restart')
        self.assertIsNone(self.store.claim_step(ID,NOW))
        self.assertEqual(self.store.get(ID).state,WorkflowState.SUCCEEDED)

    def test_worker_recovery_marks_ambiguity_without_replay_and_bounds_checks(self):
        self.create(); self.store.claim_run(NOW); self.store.claim_step(ID,NOW)
        with self.assertRaises(WorkflowError): self.store.claim_run(NOW)
        self.assertEqual(self.store.recover(NOW),1)
        self.assertEqual(self.store.recover(NOW),0)
        self.assertEqual(self.store.get(ID).steps[0].state,WorkflowState.INTERRUPTED)
        with self.assertRaises(WorkflowError): self.store.resume(ID,NOW)
        for attempt in range(1,17):
            self.assertEqual(self.store.prepare_reconciliation(ID,'install',NOW),attempt)
        with self.assertRaises(WorkflowError): self.store.prepare_reconciliation(ID,'install',NOW)
        with self.assertRaises(WorkflowError): self.store.prepare_reconciliation(ID,'restart',NOW)
        with self.assertRaises(WorkflowError): self.store.purge(ID,NOW)

    def test_cancel_purge_locks_and_audit_evidence(self):
        self.create()
        with self.store.worker_lock():
            with self.assertRaises(WorkflowError):
                with self.store.worker_lock(): self.fail('duplicate owner admitted')
        self.assertEqual(self.store.cancel(ID,NOW).state,WorkflowState.CANCELLED)
        with self.assertRaises(WorkflowError): self.store.cancel(ID,NOW)
        self.store.purge(ID,NOW)
        self.assertTrue(any(record['event']=='workflow_purged' for _,record in self.store.events()))
        with self.assertRaises(WorkflowError): self.store.get(ID)
        records=self.store.events()
        self.store.acknowledge_events(records[-1][0])
        self.assertEqual(self.store.events(),[])
        for action,arg in ((self.store.events,65),(self.store.acknowledge_events,-1)):
            with self.assertRaises(WorkflowError): action(arg)

    def test_invalid_completion_does_not_commit_success(self):
        self.create(); self.store.claim_run(NOW); self.store.claim_step(ID,NOW)
        good=result(self.plan.invocation('install'))
        for summary in (None, replace(good,total=2),replace(good,counts={'success':1}),
                        replace(good,counts={**good.counts,'failed':True})):
            with self.assertRaises(WorkflowError): self.store.finish_step(ID,'install',True,NOW,summary)
            self.assertEqual(self.store.get(ID).steps[0].state,WorkflowState.RUNNING)
        self.store.finish_step(ID,'install',False,NOW,failure=ExecutionFailure.capture(RuntimeError('synthetic-secret')))
        self.assertNotIn('synthetic-secret',json.dumps(self.store.events()))

    def test_schema_changes_fail_closed(self):
        self.create()
        self.store.db.execute('CREATE TABLE unexpected (x)')
        with self.assertRaisesRegex(WorkflowError,'schema changed'): self.store.claim_run(NOW)

    def test_missing_leaf_or_removed_dependency_cannot_produce_a_false_success(self):
        self.create(); self.store.claim_run(NOW)
        self.store.db.execute("UPDATE steps SET needs='[]' WHERE step_id='restart'")
        with self.assertRaisesRegex(WorkflowError,'checkpoint metadata changed'):
            self.store.claim_step(ID,NOW)
        self.store.db.execute("UPDATE steps SET needs=? WHERE step_id='restart'",(json.dumps(('install',)),))
        self.store.db.execute("DELETE FROM steps WHERE step_id='restart'")
        for operation in (lambda:self.store.claim_step(ID,NOW),lambda:self.store.definition(ID),lambda:self.store.get(ID)):
            with self.assertRaisesRegex(WorkflowError,'checkpoint metadata changed'): operation()

    def test_up_down_are_transactional_and_preserve_nonempty_stores(self):
        self.assertEqual(self.store.db.execute('PRAGMA synchronous').fetchone()[0],3)
        db=sqlite3.connect(':memory:',isolation_level=None)
        self.addCleanup(db.close)
        db.execute('BEGIN'); WorkflowSchema.up(db); db.rollback()
        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0)
        db.execute('BEGIN'); WorkflowSchema.up(db); db.commit()
        db.execute('BEGIN'); WorkflowSchema.down(db); db.commit()
        self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0],0)
        self.create()
        with self.store._transaction(), self.assertRaisesRegex(ValueError,'nonempty'):
            WorkflowSchema.down(self.store.db)


class ServiceIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_during_active_checkpoint_drains_cleanup_and_never_dispatches_a_successor(self):
        stop, started, cleaned = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def execute(id, step, invocation):
            self.calls.append(step.id)
            started.set()
            try:
                await asyncio.Future()
            finally:
                await asyncio.sleep(0)
                cleaned.set()
        self.service.executor = execute
        task = asyncio.create_task(self.service.serve(once=True, stop_event=stop))
        try:
            async with asyncio.timeout(3):
                await started.wait()
                stop.set()
                self.assertEqual(await task, 1)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(cleaned.is_set())
        self.assertEqual(self.calls, ['install'])
        self.assertEqual(self.store.get(ID).state, WorkflowState.INTERRUPTED)
        self.assertEqual(await self.service.serve(once=True), 0)
        self.assertEqual(self.calls, ['install'])

    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.store=SQLiteWorkflowStore(self.root/'state')
        self.addCleanup(self.temp.cleanup); self.addCleanup(self.store.close)
        self.plan=prepared(self.root)
        self.store.create(ID,self.plan,NOW)
        self.calls=[]; self.events=[]
        @asynccontextmanager
        async def audit(path,scope):
            class Sink:
                async def emit(inner,event,fields): self.events.append(event)
            yield Sink()
        self.audit=audit
        async def execute(id,step,invocation):
            self.assertIn('workflow_step_started',self.events)
            self.assertEqual(self.store.events(),[])
            self.calls.append(step.id)
            return result(invocation)
        self.service=WorkflowService(self.store,execute,audit_factory=audit,audit_path='unused',clock=lambda:NOW)

    async def test_stop_after_workflow_claim_prevents_every_checkpoint_dispatch(self):
        stop=asyncio.Event()
        @asynccontextmanager
        async def audit(path,scope):
            class Sink:
                async def emit(inner,event,fields):
                    if event=='workflow_started':stop.set()
            yield Sink()
        self.service.audit_factory=audit
        self.assertEqual(await self.service.serve(once=True,stop_event=stop),1)
        self.assertEqual(self.calls,[]);self.assertEqual(self.store.get(ID).state,WorkflowState.INTERRUPTED)
        self.assertTrue(all(step.state==WorkflowState.PENDING for step in self.store.get(ID).steps))

    async def test_continuous_worker_can_stop_after_completion_without_replaying_successes(self):
        stop=asyncio.Event()
        @asynccontextmanager
        async def audit(path,scope):
            test=self
            class Sink:
                async def emit(inner,event,fields):
                    test.events.append(event)
                    if event=='workflow_completed':stop.set()
            yield Sink()
        self.service.audit_factory=audit
        async with asyncio.timeout(3):self.assertEqual(await self.service.serve(stop_event=stop),1)
        self.assertEqual(self.calls,['install','independent','restart'])
        self.assertEqual(self.store.get(ID).state,WorkflowState.SUCCEEDED)
        self.assertEqual(await self.service.serve(once=True),0)

    async def test_terminal_storage_failure_is_visible_and_never_replayed(self):
        with patch.object(self.store,'finish_step',side_effect=OSError('synthetic terminal storage failure')),\
                self.assertRaisesRegex(OSError,'synthetic terminal storage failure'):
            await self.service.serve(once=True)
        self.assertEqual(self.calls,['install']);self.assertEqual(self.store.get(ID).state,WorkflowState.INTERRUPTED)
        self.assertEqual(await self.service.serve(once=True),0);self.assertEqual(self.calls,['install'])

    async def test_serial_dispatch_and_outbox_before_effect(self):
        self.assertEqual(await self.service.serve(once=True),1)
        self.assertEqual(self.calls,['install','independent','restart'])
        self.assertEqual(self.store.get(ID).state,WorkflowState.SUCCEEDED)
        self.assertEqual(await self.service.serve(once=True),0)
        self.assertEqual(self.events[-1],'workflow_completed')

    async def test_cancel_drains_native_cleanup_before_release(self):
        started=asyncio.Event(); cleaned=asyncio.Event(); release=asyncio.Event()
        async def execute(*args):
            started.set()
            try: await asyncio.Future()
            finally:
                await release.wait()
                cleaned.set()
        self.service.executor=execute
        task=asyncio.create_task(self.service.serve(once=True))
        await asyncio.wait_for(started.wait(),3)
        task.cancel(); await asyncio.sleep(0); task.cancel()
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError): await asyncio.wait_for(task,3)
        self.assertTrue(cleaned.is_set())
        self.assertEqual(self.store.get(ID).state,WorkflowState.INTERRUPTED)
        self.assertEqual(self.store.get(ID).steps[0].state,WorkflowState.INTERRUPTED)
        self.assertEqual(await self.service.serve(once=True),0)

    async def test_stop_after_claim_does_not_start_remote_work(self):
        stop=asyncio.Event()
        @asynccontextmanager
        async def audit(path,scope):
            class Sink:
                async def emit(inner,event,fields):
                    if event=='workflow_step_started': stop.set()
            yield Sink()
        self.service.audit_factory=audit
        await self.service.serve(once=True,stop_event=stop)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.store.get(ID).steps[0].state,WorkflowState.INTERRUPTED)

    async def test_execution_error_is_redacted_and_failed_dependency_stays_blocked(self):
        async def execute(id,step,invocation):
            self.calls.append(step.id)
            if step.id=='install': raise RuntimeError('synthetic-private-exception')
            return result(invocation)
        self.service.executor=execute
        await self.service.serve(once=True)
        self.assertEqual(self.calls,['install','independent'])
        self.assertEqual(self.store.get(ID).state,WorkflowState.FAILED)
        self.assertNotIn('synthetic-private',json.dumps(self.store.get(ID).to_dict()))

    async def test_audit_failure_prevents_dispatch_and_keeps_outbox(self):
        @asynccontextmanager
        async def audit(path,scope):
            raise OSError('synthetic audit disk failure')
            yield
        self.service.audit_factory=audit
        with self.assertRaises(OSError): await self.service.serve(once=True)
        self.assertEqual(self.calls,[])
        self.assertTrue(self.store.events())

    async def test_invalid_worker_configuration(self):
        for kwargs in ({'once':1},{'poll_interval':0},{'poll_interval':float('nan')},{'stop_event':object()}):
            with self.assertRaises(WorkflowError): await self.service.serve(**kwargs)


class WorkflowFacadePolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_preparation_rejects_unsafe_modes_before_snapshotting_and_preserves_explicit_audit_path(self):
        directory=Path('/synthetic').absolute()
        with patch.object(workflow_execution,'prepare_invocation') as snapshot:
            with self.assertRaisesRegex(WorkflowError,'a Workflow is required'):
                prepare_workflow(ID,directory,object())
            for options in (object(),Options(retries=1),Options(stdin_file='synthetic'),Options(pty=True)):
                with self.subTest(options=options),self.assertRaisesRegex(WorkflowError,'durable workflows require'):
                    prepare_workflow(ID,directory,graph(),options)
            snapshot.assert_not_called()
        options=Options(log_file=str(directory/'audit.jsonl'))
        base=replace(prepared(directory).invocations[0],options=options)
        with patch.object(workflow_execution,'prepare_invocation',return_value=base) as snapshot:
            value=prepare_workflow(ID,directory,graph(),options)
        self.assertEqual(value.workflow,graph());self.assertEqual(len(value.invocations),3)
        self.assertEqual({item.options.log_file for item in value.invocations},{options.log_file})
        snapshot.assert_called_once_with(ID,directory,graph().ordered_steps[0].hosts,graph().ordered_steps[0].descriptor,options)

    def runner(self):
        base=Path('/synthetic').absolute()
        store=SimpleNamespace(directory=base/'workflows',close=Mock(),worker_lock=lambda:nullcontext(),
            definition=Mock(return_value=prepared(base/'workflows')),prepare_reconciliation=Mock())
        executor=SimpleNamespace(reconcile=AsyncMock())
        with patch.object(workflow_interfaces,'workflow_dependencies',return_value=(store,executor,Mock())) as factory,\
                patch.object(workflow_interfaces,'default_log_path',return_value=base/'audit.jsonl'):
            runner=WorkflowRunner()
        factory.assert_called_once_with(base/'workflows')
        return runner,store,executor

    async def test_default_state_location_is_resolved_without_opening_a_native_dependency(self):
        runner,store,executor=self.runner()
        self.assertEqual(runner.state_dir,Path('/synthetic').absolute()/'workflows')
        with runner as opened:self.assertIs(opened,runner)
        store.close.assert_called_once_with();executor.reconcile.assert_not_awaited()

    async def test_plan_defaults_and_invalid_inputs_do_not_create_storage(self):
        with patch.object(workflow_interfaces,'workflow_dependencies') as create:
            default=WorkflowRunner.plan(graph())
            self.assertFalse(default['automatic_replay']);self.assertEqual(len(default['steps']),3)
            with self.assertRaisesRegex(WorkflowError,'a Workflow is required'):WorkflowRunner.plan(object())
            for options in (Options(stdin_file='synthetic'),Options(retries=1),Options(pty=True)):
                with self.subTest(options=options),self.assertRaises(WorkflowError):WorkflowRunner.plan(graph(),options)
        create.assert_not_called()

    async def test_missing_step_or_missing_verifier_is_rejected_before_any_reconciliation_intent(self):
        for step in ('absent','restart'):
            runner,store,executor=self.runner()
            with self.subTest(step=step),self.assertRaisesRegex(WorkflowError,'declared read-only verifier'):
                await runner.reconcile(ID,step)
            store.definition.assert_called_once_with(ID)
            store.prepare_reconciliation.assert_not_called();executor.reconcile.assert_not_awaited()


class FacadeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_readonly_verification_and_resume(self):
        with tempfile.TemporaryDirectory() as directory, WorkflowRunner(Path(directory)/'state') as runner:
            info=runner.register(graph())
            snapshot=runner.store.definition(info.id)
            self.assertTrue(Path(snapshot.invocations[0].options.ssh_executable).is_absolute())
            calls=[]
            class Executor:
                async def __call__(self,id,step,invocation):
                    calls.append(('apply',step.id))
                    return result(invocation,step.id!='install')
                async def reconcile(self,id,step,invocation,path):
                    calls.append(('verify',step.verifier))
                    Path(path).parent.mkdir(parents=True,exist_ok=True)
                    Path(path).write_text('synthetic receipt')
                    return result(invocation)
            runner.executor=Executor()
            await runner.serve(once=True)
            checked=await runner.reconcile(info.id,'install')
            self.assertTrue(Path(checked.steps[0].verification.report_path).is_file())
            runner.resume(info.id)
            await runner.serve(once=True)
            self.assertEqual(calls,[('apply','install'),('apply','independent'),('verify','check-installed'),('apply','restart')])
            self.assertEqual(runner.store.get(info.id).state,WorkflowState.SUCCEEDED)
            runner.purge(info.id)
            self.assertTrue(Path(checked.steps[0].verification.report_path).is_file())

    async def test_native_executor_routes_verification_without_apply(self):
        calls=[]
        class Fleet:
            async def run_to_file(self,*args,**kwargs): calls.append(('run',args)); return 'run'
            async def verify_to_file(self,*args,**kwargs): calls.append(('verify',args)); return 'verify'
        executor=NativeWorkflowExecutor(lambda options:Fleet(),lambda action,options:Fleet())
        with tempfile.TemporaryDirectory() as directory:
            plan=prepared(Path(directory))
            for step in plan.workflow.steps:
                invocation=plan.invocation(step.id)
                await executor(ID,step,invocation)
                if step.verifier:
                    await executor.reconcile(ID,step,invocation,str(Path(invocation.report_path).with_name('reconcile-1.json')))
                else:
                    with self.assertRaises(WorkflowError): await executor.reconcile(ID,step,invocation,invocation.report_path)
            self.assertEqual([call[0] for call in calls],['run','run','run','run','verify'])
            self.assertEqual(calls[1][1][1],'check-installed')

    async def test_strict_loader_cli_plan_and_no_state_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); spec=root/'workflow.json'; state=root/'unused-state'
            spec.write_text(json.dumps(graph().to_dict()),encoding='utf-8')
            self.assertEqual(load_workflow(spec),graph())
            output=io.StringIO()
            with patch('sys.stdout',output):
                self.assertEqual(cli.main(['workflow','--workflow-file',str(spec),'--plan-only','--state-dir',str(state),'--ssh-executable','absent']),0)
            self.assertFalse(state.exists())
            self.assertFalse(json.loads(output.getvalue())['automatic_replay'])
            for text in ('{}','{"schema_version":1,"schema_version":1}', '{"name":NaN}'):
                spec.write_text(text)
                with self.assertRaises(WorkflowError): load_workflow(spec)
            for args in (['--list','--key','ignored'], ['--reconcile',ID], ['--show',ID,'--step','install'],
                         ['--workflow-file',str(spec),'--once']):
                with patch('sys.stderr',io.StringIO()): self.assertEqual(cli.main(['workflow',*args,'--state-dir',str(state)]),2)
            self.assertFalse(state.exists())


if __name__=='__main__':
    unittest.main()
