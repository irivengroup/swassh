"""Pure configuration acceptance boundaries; no files, commands or sockets."""
from dataclasses import replace
import math
import unittest

from swassh import DesiredState,Host,HostProfile,LocalForward,Options,Workflow,WorkflowStep
from swassh.domain.channels import ChannelCapture
from swassh.domain.models import Status


class OptionsBoundaryTests(unittest.TestCase):
    def test_integer_limits_reject_wrong_types_and_each_side_of_the_range(self):
        limits={'concurrency':(1,10000),'canary':(1,100000),'retries':(0,10),
                'max_output_bytes':(1,None),'memory_budget_mib':(8,None),'max_report_mib':(1,None),
                'bastion_concurrency':(1,10000),'bastion_memory_mib':(72,1048576),
                'bastion_bandwidth_kib':(1,2147483647),'circuit_threshold':(1,10000),
                'output_lines':(0,10000),'stream_rate':(1,10000),'max_stdin_bytes':(1,16777216)}
        for field,(minimum,maximum) in limits.items():
            invalid=[None,True,False,'1',1.5,[],minimum-1]
            if maximum is not None:invalid.append(maximum+1)
            for value in invalid:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    Options(**{field:value})
            for value in (minimum,maximum if maximum is not None else minimum+1):
                with self.subTest(field=field,boundary=value):
                    self.assertEqual(getattr(Options(**{field:value}),field),value)

    def test_numeric_limits_refuse_nonfinite_values_boolean_and_underflow(self):
        for field in ('connect_timeout','command_timeout','report_timeout','retry_delay','connect_rate'):
            for value in (None,True,False,'1',[],float('nan'),float('inf'),-float('inf'),-1,10**1000):
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):
                    Options(**{field:value})
            if field!='retry_delay':
                with self.subTest(field=field),self.assertRaises(ValueError):Options(**{field:0})
            self.assertEqual(getattr(Options(**{field:0.25}),field),0.25)
        self.assertEqual(Options(retry_delay=0).retry_delay,0)
        with self.assertRaises(ValueError):Options(connect_rate=math.ulp(0.0),jump_host=Host('jump'))
        for field,values in {'progress_interval':(None,True,'1',-1,0.5,86401,float('nan'),float('inf')),
                             'bastion_connect_rate':(None,True,'1',0,0.09,1001,float('nan'),float('inf'))}.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):Options(**{field:value})
        for value in (0,1,86400):self.assertEqual(Options(progress_interval=value).progress_interval,value)
        for value in (0.1,1000):self.assertEqual(Options(bastion_connect_rate=value).bastion_connect_rate,value)

    def test_boolean_paths_profiles_and_authentication_have_literal_contracts(self):
        for field in ('adaptive','show_output','stream_output','pty'):
            for value in (None,0,1,'false',[]):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):Options(**{field:value})
            for value in (True,False):self.assertIs(getattr(Options(**{field:value}),field),value)
        for field in ('known_hosts','log_file','budget_dir','stdin_file','askpass_executable','ssh_executable'):
            for value in (0,True,[], '', 'bad\npath','bad\0path','${UNRESOLVED}','x'*4097):
                # ssh_executable's executable-name validation is intentionally
                # separate from configuration-file path validation.
                if field=='ssh_executable' and isinstance(value,str) and value:continue
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):Options(**{field:value})
        for value in ([],('valid',None),('valid',''),('valid',1)):
            with self.subTest(client_keys=value),self.assertRaises(ValueError):Options(client_keys=value)
        for value in ('unsupported',None,False,[]):
            with self.subTest(auth_method=value),self.assertRaises(ValueError):Options(auth_method=value)
        with self.assertRaises(ValueError):Options(auth_method='password')
        self.assertEqual(Options(auth_method='password',askpass_executable='provider').auth_method,'password')
        with self.assertRaises(ValueError):Options(jump_host='jump')
        with self.assertRaises(ValueError):Options(jump_host=Host('jump'),bastion_concurrency=1)
        for value in ([],(None,),(HostProfile('same'),HostProfile('same'))):
            with self.subTest(host_profiles=value),self.assertRaises(ValueError):Options(host_profiles=value)
        for changes in ({'command_timeout':0},{'client_keys':[]},{'known_hosts':''},{'encoding':'invalid-codec'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                Options(host_profiles=(HostProfile('one',**changes),))
        for value in (None,[],True,'unsupported-codec','base64_codec'):
            with self.subTest(encoding=value),self.assertRaises(ValueError):Options(encoding=value)
        for digest in (None,'a'*64):
            self.assertEqual(Options(stdin_file='input',stdin_sha256=digest).stdin_sha256,digest)
        for changes in ({'stdin_sha256':'a'*64},{'stdin_file':'input','stdin_sha256':True},
                        {'stdin_file':'input','stdin_sha256':'A'*64}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):Options(**changes)


class ImmutablePlanBoundaryTests(unittest.TestCase):
    def test_binary_capture_preserves_failure_status_and_checks_each_field(self):
        baseline=ChannelCapture(Status.SUCCESS,0,b'\x00\xff',b'')
        for changes in ({'status':'success'},{'exit_code':True},{'stdout':'bytes'},
                        {'stderr':None},{'error':1},{'exit_code':1}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):replace(baseline,**changes)
        for status in Status:
            capture=ChannelCapture(status,0 if status==Status.SUCCESS else None,b'',b'',None)
            self.assertEqual(capture.ok,status==Status.SUCCESS)

    def test_loopback_forwarding_rejects_wildcard_invalid_ports_and_scoped_destinations(self):
        baseline=LocalForward(2222,'EXAMPLE.ORG',443)
        self.assertEqual(baseline.argument,'127.0.0.1:2222:example.org:443')
        self.assertEqual(LocalForward(2222,'::1',443,'::1').argument,'[::1]:2222:[::1]:443')
        for changes in ({'bind_address':'0.0.0.0'},{'bind_address':None},{'remote_host':'fe80::1%eth0'}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):replace(baseline,**changes)
        for field in ('local_port','remote_port'):
            for value in (True,0,-1,65536,1.5,'22'):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):replace(baseline,**{field:value})

    def test_workflow_and_desired_state_serialization_reject_ambiguous_shapes(self):
        action=DesiredState('state','check','apply','verify')
        step=WorkflowStep('first',('target',),action=action)
        workflow=Workflow('plan',(step,))
        self.assertEqual(Workflow.from_dict(workflow.to_dict()),workflow)
        self.assertEqual(WorkflowStep.from_dict(step.to_dict()),step)
        for value in (None,[],{}, {**action.to_dict(),'schema_version':True},
                      {**action.to_dict(),'schema_version':2},{**action.to_dict(),'extra':1}):
            with self.subTest(action=value),self.assertRaises(ValueError):DesiredState.from_dict(value)
        for value in (None,[],{}, {**step.to_dict(),'hosts':()}, {**step.to_dict(),'needs':()},
                      {**step.to_dict(),'hosts':[]},{**step.to_dict(),'hosts':[{}]},
                      {**step.to_dict(),'hosts':[{'hostname':'one','extra':1}]}):
            with self.subTest(step=value),self.assertRaises(ValueError):WorkflowStep.from_dict(value)
        for changes in ({'hosts':('bad host',)},{'action':True},{'needs':[]},{'needs':('first',)},
                        {'needs':('second','second')},{'reconcile_check':'verify'},
                        {'hosts':()},{'hosts':['target']}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):replace(step,**changes)
        self.assertEqual(step.verifier,'verify')
        self.assertTrue(step.descriptor.startswith('converge:state:'))
        opaque=WorkflowStep('opaque',('target',),command='apply',reconcile_check='inspect')
        self.assertEqual((opaque.verifier,opaque.descriptor),('inspect','apply'))
        with self.assertRaises(ValueError):replace(opaque,reconcile_check='apply')
