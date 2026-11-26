"""Pure checkpoint and prepared-invocation rejection matrices."""
from dataclasses import replace
from datetime import UTC,datetime
from pathlib import Path
import unittest

from swassh import Host,Options,Status,Workflow,WorkflowStep,WorkflowState
from swassh.application.schedule_contracts import ExecutionFailure,ScheduledInvocation
from swassh.application.workflow_contracts import PreparedWorkflow,WorkflowInfo,WorkflowStepInfo,WorkflowVerificationInfo


class CheckpointBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.path=str((Path.cwd()/'synthetic-report.json').absolute())
        self.now=datetime(2030,1,1,tzinfo=UTC).isoformat(timespec='microseconds')
        self.counts=tuple((s.value,int(s==Status.SUCCESS)) for s in Status)
        self.verification=WorkflowVerificationInfo(1,self.path,self.now,'a'*32,self.counts,1)
        self.step=WorkflowStepInfo('one',WorkflowState.SUCCEEDED,1,self.path,
                    started_at=self.now,finished_at=self.now,counts=self.counts,verification=self.verification)

    def test_verification_receipts_reject_each_shape_and_keep_immutable_counts(self):
        for field,values in {'attempt':(True,'1',0,17),'host_count':(True,'1',0,100001),
                             'finished_at':(None,False,'yesterday','2030-01-01T00:00:00+00:00'),
                             'run_id':(False,'short'),
                             'counts':(None,[],(1,),(('success',),),(('success',1,2),),
                                       (('success',1),),self.counts+self.counts,tuple((s.value,-1) for s in Status),
                                       tuple((s.value,True) for s in Status),tuple((s.value,0) for s in Status))}.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):replace(self.verification,**{field:value})
        self.assertEqual(self.verification.to_dict(),{'attempt':1,'report_path':self.path,'finished_at':self.now,
                         'run_id':'a'*32,'counts':dict(self.counts)})
        self.assertEqual(replace(self.verification,run_id=None).run_id,None)

    def test_checkpoint_metadata_and_paths_reject_types_controls_and_noncanonical_timestamps(self):
        invalid={'id':(None,False,'','bad name','a'*65),'state':(None,'succeeded'),
                 'host_count':(True,'1',0,100001),'reason':(1,'bad reason','X','a'*65),
                 'run_id':(1,'short'),'verification':(1,replace(self.verification,host_count=2,counts=tuple((s.value,2*int(s==Status.SUCCESS)) for s in Status))),
                 'started_at':(1,'yesterday','2030-01-01T00:00:00'),
                 'finished_at':(True,'2030-01-01T00:00:00Z')}
        for field,values in invalid.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):replace(self.step,**{field:value})
        for value in (None,False,1,'','relative',str(Path(self.path).parent/('x'*4097)),self.path+'\n',self.path+'\x85',self.path+'\x7f'):
            with self.subTest(path=repr(value)),self.assertRaises(ValueError):replace(self.step,report_path=value)
        value=replace(self.step,reason='verification_failed',run_id='b'*32)
        self.assertEqual(value.to_dict()['verification'],self.verification.to_dict())
        self.assertEqual(value.to_dict()['counts'],dict(self.counts))
        self.assertEqual(replace(value,counts=None,verification=None).to_dict()['counts'],None)

    def test_workflow_header_cannot_use_blocked_or_malformed_snapshot_metadata(self):
        info=WorkflowInfo('c'*32,'plan',WorkflowState.SUCCEEDED,self.now,'d'*64,(self.step,))
        for field,values in {'state':('succeeded',WorkflowState.BLOCKED),'steps':([],(),(None,),(self.step,)*257),
                             'definition_sha256':(1,'d'*63,'D'*64),'created_at':(None,1,'yesterday')}.items():
            for value in values:
                with self.subTest(field=field,value=str(value)[:100]),self.assertRaises(ValueError):replace(info,**{field:value})
        self.assertEqual(info.to_dict()['steps'],[self.step.to_dict()])


class InvocationBoundaryTests(unittest.TestCase):
    def test_normalized_scheduling_paths_and_options_are_required_before_preparation(self):
        path=str((Path.cwd()/'synthetic-report.json').absolute())
        invocation=ScheduledInvocation('read',(Host('one'),),Options(),path)
        for field,values in {'hosts':([],(),('one',),(Host('one'),Host('one'))),
                             'options':(None,False),'format':(None,'pickle'),'report_path':(None,)}.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):replace(invocation,**{field:value})
        for field in ('report_path','spool_dir'):
            for value in (True,1,'','relative',path+'\n',path+'\x85',path+'\x7f',str(Path(path).parent/('x'*4097))):
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):replace(invocation,**{field:value})
        step=WorkflowStep('one',('one',),command='read');workflow=Workflow('plan',(step,))
        good=PreparedWorkflow(workflow,(invocation,))
        self.assertIs(good.invocation('one'),invocation)
        for changes in ({'workflow':None},{'invocations':[]},{'invocations':()},
                        {'invocations':(None,)},{'invocations':(replace(invocation,hosts=(Host('other'),)),)},
                        {'invocations':(replace(invocation,options=Options(stdin_file='input')), )},
                        {'invocations':(replace(invocation,options=Options(pty=True)), )}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):replace(good,**changes)

    def test_failure_categories_are_allowlisted_and_never_include_exception_messages(self):
        cases=((TimeoutError(), 'timeout'),(PermissionError(13,'synthetic-private-text'),'permission'),
               (FileNotFoundError(2,'synthetic-private-text'),'missing_file'),(OSError(5,'synthetic-private-text'),'io'),
               (ValueError('synthetic-private-text'),'invalid_input'),(RuntimeError('synthetic-private-text'),'runtime'),
               (Exception('synthetic-private-text'),'unexpected'))
        for error,category in cases:
            captured=ExecutionFailure.capture(error)
            self.assertEqual(captured.category,category)
            self.assertNotIn('synthetic-private-text',repr(captured))
        with self.assertRaises(TypeError):ExecutionFailure.capture(KeyboardInterrupt())
        for value in (True,'1',-1,65536):
            with self.assertRaises(ValueError):ExecutionFailure('io','OSError',value)
        for number in (-1,65536):
            self.assertIsNone(ExecutionFailure.capture(OSError(number,'synthetic')).errno)
        with self.assertRaises(ValueError):ExecutionFailure('permission','OSError')
