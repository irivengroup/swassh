"""Persistent workflow corruption is refused without dispatch or evidence loss."""
from dataclasses import replace
from datetime import UTC,datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from swassh import Host,Options,Workflow,WorkflowStep,WorkflowError
from swassh.application.contracts import RunSummary
from swassh.application.schedule_contracts import ScheduledInvocation,ExecutionFailure
from swassh.application.workflow_contracts import PreparedWorkflow
from swassh.domain.models import Status
from swassh.infrastructure import workflow_store
from swassh.infrastructure.schedule_store import decode_invocation
from swassh.domain.scheduling import ScheduleError
from swassh.infrastructure.resources import resource_plan


NOW=datetime(2030,1,1,tzinfo=UTC)
ID='a'*32


class WorkflowStorageFailureIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        self.store=workflow_store.SQLiteWorkflowStore(self.root/'state');self.addCleanup(self.store.close)
        self.workflow=Workflow('plan',(WorkflowStep('install',('one',),command='true',reconcile_check='check'),))
        self.invocation=ScheduledInvocation('true',(Host('one'),),Options(),str(self.root/'report.json'))
        self.prepared=PreparedWorkflow(self.workflow,(self.invocation,))

    def start(self):
        self.store.create(ID,self.prepared,NOW);self.store.claim_run(NOW);self.store.claim_step(ID,NOW)

    def summary(self):
        return RunSummary(1,{value.value:int(value==Status.SUCCESS) for value in Status},NOW,NOW,
                          resource_plan(Options()),'b'*32)

    def test_snapshot_schema_and_size_refusals_preserve_database(self):
        valid=json.loads(workflow_store.encode_prepared(self.prepared))
        for payload in (None,'x'*(workflow_store.MAX_PAYLOAD+1),'[]','NaN','{"schema_version":1,"schema_version":1}',
                json.dumps({**valid,'schema_version':True}),json.dumps({**valid,'schema_version':2}),
                json.dumps({**valid,'invocations':{}}),json.dumps({**valid,'invocations':[]}),
                json.dumps({**valid,'invocations':[None]}),json.dumps({**valid,'extra':1})):
            with self.subTest(kind=type(payload).__name__),self.assertRaises(WorkflowError):
                workflow_store.decode_prepared(payload)
        self.assertEqual(self.store.list(),[])
        for payload in (None,False,1,[],{},b'{}'):
            with self.assertRaisesRegex(ScheduleError,'must be text'):decode_invocation(payload)
        # The encoder must enforce the serialized snapshot budget independently
        # of higher-level workflow construction and its individual command limits.
        snapshot=Mock(workflow=Mock());snapshot.workflow.to_dict.return_value={'oversized':'x'*workflow_store.MAX_PAYLOAD};snapshot.invocations=()
        with self.assertRaisesRegex(WorkflowError,'10 MiB'):workflow_store.encode_prepared(snapshot)

    def test_capacity_missing_identity_and_schema_mutation_refuse_operations(self):
        for limit in (False,0,1001,1.5):
            with self.assertRaises(WorkflowError):workflow_store.SQLiteWorkflowStore(self.root/'unused',max_runs=limit)
        self.assertFalse((self.root/'unused').exists())
        with self.assertRaisesRegex(WorkflowError,'not found'):self.store.get(ID)
        with self.assertRaisesRegex(WorkflowError,'prepared workflow'):self.store.create(ID,object(),NOW)
        for setting,value in (('user_version',2),('application_id',0)):
            original=self.store.db.execute('PRAGMA '+setting).fetchone()[0]
            self.store.db.execute('PRAGMA '+setting+'='+str(value))
            with self.assertRaisesRegex(WorkflowError,'schema changed'):self.store.create(ID,self.prepared,NOW)
            self.store.db.execute('PRAGMA '+setting+'='+str(original))
        self.store.create(ID,self.prepared,NOW)
        self.store.db.execute('CREATE TABLE unexpected(value INTEGER)')
        with self.assertRaisesRegex(WorkflowError,'schema changed'):self.store.cancel(ID,NOW)
        self.assertEqual(self.store.get(ID).state.value,'pending')

    def test_consistent_checkpoint_digest_does_not_override_original_definition(self):
        self.store.create(ID,self.prepared,NOW)
        self.store.db.execute("UPDATE runs SET name='altered' WHERE id=?",(ID,))
        with self.assertRaisesRegex(WorkflowError,'metadata'):self.store.definition(ID)
        self.store.db.execute("UPDATE runs SET name='plan' WHERE id=?",(ID,))
        self.store.db.execute("UPDATE steps SET report_path=? WHERE run_id=?",(str(self.root/'other.json'),ID))
        rows=self.store.db.execute('SELECT * FROM steps WHERE run_id=?',(ID,)).fetchall()
        self.store.db.execute('UPDATE runs SET checkpoint_sha256=? WHERE id=?',(self.store._checkpoint_digest(rows),ID))
        with self.assertRaisesRegex(WorkflowError,'definition'):self.store.definition(ID)
        self.assertFalse((self.root/'other.json').exists())

    def test_corrupt_counters_and_verification_metadata_never_render_success(self):
        self.store.create(ID,self.prepared,NOW)
        for counts in ('[]','{"success":NaN}','{"success":1,"success":1}'):
            self.store.db.execute('UPDATE steps SET counts=? WHERE run_id=?',(counts,ID))
            with self.assertRaises(ValueError):self.store.get(ID)
        self.store.db.execute('UPDATE steps SET counts=NULL WHERE run_id=?',(ID,))
        for value in ('[]','{}',json.dumps({'attempt':1,'report_path':str(self.root/'check.json'),
                'finished_at':NOW.isoformat(),'run_id':'b'*32,'counts':[]})):
            self.store.db.execute('UPDATE steps SET verification=? WHERE run_id=?',(value,ID))
            with self.assertRaises(ValueError):self.store.list()

    def test_completion_summary_and_failure_guards_leave_running_claim_intact(self):
        self.start();good=self.summary()
        invalid=(None,object(),replace(good,total=True),replace(good,total=2),replace(good,counts={}),
            replace(good,counts={**good.counts,'success':True}),replace(good,counts={**good.counts,'success':-1}),
            replace(good,counts={**good.counts,'success':0}),replace(good,run_id='invalid'))
        for summary in invalid:
            with self.subTest(summary=type(summary).__name__),self.assertRaises(ValueError):
                self.store.finish_step(ID,'install',True,NOW,summary)
            self.assertEqual(self.store.get(ID).steps[0].state.value,'running')
        for succeeded,summary,failure in ((1,good,None),(False,None,object()),
                (True,None,ExecutionFailure('runtime','RuntimeError',None)),
                (False,good,ExecutionFailure('runtime','RuntimeError',None))):
            with self.assertRaises(ValueError):self.store.finish_step(ID,'install',succeeded,NOW,summary,failure)
        for method,args in ((self.store.finish_step,(ID,'absent',False,NOW)),
                (self.store.claim_run,(NOW,)),(self.store.cancel,(ID,NOW)),
                (self.store.purge,(ID,NOW)),(self.store.prepare_reconciliation,(ID,'install',NOW)),
                (self.store.reconcile,(ID,'install',NOW,good))):
            with self.assertRaises(WorkflowError):method(*args)
        self.store.finish_step(ID,'install',True,NOW,good)
        self.assertIsNone(self.store.claim_step(ID,NOW));self.assertEqual(self.store.get(ID).state.value,'succeeded')

    def test_reconciliation_and_audit_limits_do_not_silently_discard_evidence(self):
        self.start();self.store.finish_step(ID,'install',False,NOW);self.store.claim_step(ID,NOW)
        for step in ('absent','install'):
            if step=='install':self.store.db.execute('UPDATE steps SET reconciliation_count=16 WHERE run_id=?',(ID,))
            with self.assertRaises(WorkflowError):self.store.prepare_reconciliation(ID,step,NOW)
        with self.assertRaises(WorkflowError):self.store.reconcile(ID,'absent',NOW,self.summary())
        before=self.store.events()
        for limit in (True,0,65,1.5):
            with self.assertRaises(WorkflowError):self.store.events(limit)
        for cursor in (True,-1,1.5):
            with self.assertRaises(WorkflowError):self.store.acknowledge_events(cursor)
        self.assertEqual(self.store.events(),before)
        with patch.object(workflow_store,'_WriterLock',side_effect=OSError('private error')):
            with self.assertRaisesRegex(WorkflowError,'another workflow'):
                with self.store.worker_lock():self.fail('lock must not admit a worker')

    def test_persisted_dependency_shapes_and_cycles_refuse_dispatch_after_consistent_rehash(self):
        self.store.create(ID,self.prepared,NOW);self.store.claim_run(NOW)
        for needs in ({},['absent'],['install']*257,['install']):
            self.store.db.execute('UPDATE steps SET needs=? WHERE run_id=?',(json.dumps(needs),ID))
            rows=self.store.db.execute('SELECT * FROM steps WHERE run_id=? ORDER BY ordinal',(ID,)).fetchall()
            # Model a self-consistent but invalid persisted graph. Integrity is
            # not semantic authorization to dispatch or to declare completion.
            values=[(row['step_id'],row['ordinal'],row['needs'],row['host_count'],row['report_path']) for row in rows]
            digest=hashlib.sha256(json.dumps(values,ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
            self.store.db.execute('UPDATE runs SET checkpoint_sha256=? WHERE id=?',(digest,ID))
            before=self.store.events()
            with self.assertRaisesRegex(WorkflowError,'dependencies|unresolved'):self.store.claim_step(ID,NOW)
            self.assertEqual(self.store.events(),before)
            self.assertEqual(self.store.get(ID).state.value,'running')
            self.assertEqual(self.store.get(ID).steps[0].state.value,'pending')


if __name__=='__main__':unittest.main()
