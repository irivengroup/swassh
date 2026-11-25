"""Composition-root dispatch: exact plans/options reach the intended engine.

System ports are replaced by recording in-memory ports. The real composition
functions and executors are exercised; no SSH command or user file is opened.
"""
import contextlib
from datetime import UTC,datetime
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from swassh import DesiredState, Host, NetworkProcedure, NetworkStep, NetworkSwarm, Options, WorkflowStep
from swassh import bootstrap
from swassh.application.schedule_contracts import ScheduledInvocation
from swassh.application.workflow_contracts import WorkflowInfo,WorkflowStepInfo
from swassh.domain.workflows import WorkflowState
from swassh.infrastructure import schedule_store
from swassh.interfaces import cli
from swassh.interfaces.convergence import ConvergentSwarm
from swassh.interfaces.workflows import render_workflows


class RecordingEngine:
    instances=[]
    def __init__(self,options,**dependencies):
        self.options,self.dependencies=options,dependencies
        self.calls=[];self.instances.append(self)
    async def run_to_file(self,*args,**kwargs):
        self.calls.append(('file',args,kwargs));return ('receipt',args,kwargs)
    async def run(self,*args):self.calls.append(('memory',args,{}));return ('report',args)


class CompositionTests(unittest.IsolatedAsyncioTestCase):
    async def test_workflow_factories_dispatch_commands_and_verification_without_replay(self):
        options=Options();hosts=(Host('one'),)
        directory=Path.cwd()/'synthetic-state';store=SimpleNamespace(directory=directory)
        RecordingEngine.instances=[]
        with patch('swassh.infrastructure.workflow_store.SQLiteWorkflowStore',return_value=store) as create,patch('swassh.application.swarm.Swarm',RecordingEngine),patch('swassh.infrastructure.workflow_execution.private_directory'):
            actual,executor,audit=bootstrap.workflow_dependencies(directory)
            self.assertIs(actual,store);create.assert_called_once_with(directory)
            opaque=WorkflowStep('opaque',hosts,command='mutate',reconcile_check='inspect')
            action=DesiredState('desired','check','apply','verify')
            convergent=WorkflowStep('desired',hosts,action=action)
            for step in (opaque,convergent):
                invocation=ScheduledInvocation(step.descriptor,hosts,options,str(directory/step.id/'report.json'))
                for verifying in (False,True):
                    output=str(directory/step.id/('verify.json' if verifying else 'report.json'))
                    receipt=await executor.reconcile('a'*32,step,invocation,output) if verifying else await executor('a'*32,step,invocation)
                    self.assertEqual(receipt[1][0],hosts)
                    self.assertEqual(receipt[1][2],output)
                    self.assertEqual(receipt[2],{'spool_dir':None})
                    engine=RecordingEngine.instances[-1]
                    self.assertIs(engine.options,options)
                    factory=engine.dependencies['transport_factory']
                    if step.action:
                        self.assertIs(factory.action,action)
                        self.assertIs(factory.verify_only,verifying)
                        self.assertEqual(receipt[1][1],action.descriptor)
                    else:self.assertEqual(receipt[1][1],'inspect' if verifying else 'mutate')
                    self.assertTrue(callable(engine.dependencies['planner']))
                    self.assertTrue(callable(engine.dependencies['reporter_factory']))
        self.assertEqual(len(RecordingEngine.instances),4)

    async def test_scheduler_and_interaction_factories_preserve_the_normal_boundaries(self):
        directory=Path.cwd()/'synthetic-schedules';store=SimpleNamespace(directory=directory)
        options=Options();hosts=(Host('one'),)
        invocation=ScheduledInvocation('opaque',hosts,options,str(directory/'runs'/('a'*32)/'report.json'))
        job=SimpleNamespace(info=SimpleNamespace(id='a'*32),invocation=invocation)
        RecordingEngine.instances=[]
        with patch('swassh.infrastructure.schedule_store.SQLiteScheduleStore',return_value=store),patch('swassh.application.swarm.Swarm',RecordingEngine),patch('swassh.infrastructure.scheduled_execution.private_directory'):
            actual,executor,audit=bootstrap.scheduler_dependencies(directory)
            self.assertIs(actual,store)
            receipt=await executor(job)
            self.assertEqual(receipt[1],(hosts,'opaque',invocation.report_path,'json'))
            self.assertIs(RecordingEngine.instances[-1].options,options)
        handler=lambda host:None
        with patch.object(bootstrap,'SSHTransport') as create:
            value=bootstrap.InteractionFactory(handler)(options)
            create.assert_called_once_with(options,interaction_factory=handler)
            self.assertIs(value,create.return_value)
        with self.assertRaises(TypeError):bootstrap.InteractionFactory(None)

    async def test_public_verify_apis_select_the_read_only_factory_and_keep_output_arguments(self):
        action=DesiredState('state','check','apply');hosts=(Host('one'),)
        RecordingEngine.instances=[]
        with patch('swassh.interfaces.convergence.Swarm',RecordingEngine):
            service=ConvergentSwarm(action)
            report=await service.verify(hosts)
            receipt=await service.verify_to_file(hosts,'output.json','csv',spool_dir='spool')
        self.assertEqual(report,('report',(hosts,action.descriptor)))
        self.assertEqual(receipt,('receipt',(hosts,action.descriptor,'output.json','csv'),{'spool_dir':'spool'}))
        self.assertEqual(RecordingEngine.instances[0].calls,[])
        self.assertTrue(RecordingEngine.instances[1].dependencies['transport_factory'].verify_only)

    async def test_network_public_dispatch_requires_the_exact_review_and_streams_output(self):
        plan=NetworkProcedure('cisco_ios','administration',(NetworkStep('identify','show',('evidence',)),))
        service=NetworkSwarm(plan);hosts=(Host('one'),);approval=service.plan(hosts)['approval_sha256']
        RecordingEngine.instances=[]
        with patch('swassh.interfaces.network.Swarm',RecordingEngine):
            report=await service.run(hosts,approval=approval)
            receipt=await service.run_to_file(hosts,'out.json','json',approval=approval,spool_dir='spool')
            with self.assertRaises(ValueError):await service.run_to_file(hosts,'out.json',approval='0'*64)
        self.assertEqual(report,('report',(hosts,'network:'+approval)))
        self.assertEqual(receipt[1],(hosts,'network:'+approval,'out.json','json'))
        self.assertEqual(receipt[2],{'spool_dir':'spool'})
        self.assertEqual(len(RecordingEngine.instances),2)


class MetadataAndCLICompositionTests(unittest.TestCase):
    def test_workflow_render_and_default_schedule_location_do_not_open_storage(self):
        path=str((Path.cwd()/'synthetic-report.json').absolute())
        step=WorkflowStepInfo('step',WorkflowState.SUCCEEDED,1,path)
        value=WorkflowInfo('a'*32,'plan',WorkflowState.SUCCEEDED,datetime(2030,1,1,tzinfo=UTC).isoformat(timespec='microseconds'),'b'*64,(step,))
        self.assertEqual(json.loads(render_workflows([value])),[value.to_dict()])
        self.assertEqual(render_workflows([]),'[]\n')
        with patch.object(schedule_store,'default_log_path',return_value=Path.cwd()/'private'/'audit.jsonl'):
            self.assertEqual(schedule_store.default_schedule_directory(),Path.cwd()/'private'/'schedules')

    def test_tunnel_cli_enters_waits_and_closes_its_scope_and_reports_no_remote_verification(self):
        events=[]
        class Tunnel:
            def __init__(self,host,forward,options,lifetime):
                self.host,self.forward=host,forward
                self.options,self.lifetime=options,lifetime
            async def __aenter__(self):events.append('enter');return self
            async def wait(self):events.append('wait')
            async def __aexit__(self,*args):events.append('close')
        with patch('swassh.interfaces.channels.SSHTunnel',Tunnel),patch.object(cli.LocalPreflight,'require_credentials'),contextlib.redirect_stdout(io.StringIO()) as output:
            code=cli.main(['tunnel','-H','one','--local-port','2222','--remote-host','internal','--remote-port','443','--lifetime','1'])
        self.assertEqual(code,0)
        self.assertEqual(events,['enter','wait','close'])
        self.assertEqual(json.loads(output.getvalue()),{'state':'listening','bind_address':'127.0.0.1','local_port':2222,'destination_verified':False})
