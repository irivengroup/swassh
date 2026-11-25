"""Pure domain rejection matrices and deterministic calendar/DAG boundaries.

All values are synthetic; domain tests use neither files nor sockets. Cases
exercise independent validation terms instead of compensating weak components
with unrelated successful operations.
"""
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
import io
import json
import struct
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from swassh import Host, Result, Status, Workflow, WorkflowStep
from swassh.domain.bandwidth import ByteWindow
from swassh.domain.channels import ChannelCapture
from swassh.domain.endpoints import Endpoint
from swassh.domain.inventory import InventoryError, normalize_hosts, parse_host
from swassh.domain.models import TransferReceipt
from swassh.domain.network import NetworkProcedure, NetworkStep, ReconnectPolicy
from swassh.domain.scheduling import JobInfo, JobState, ScheduleError, parse_schedule_time, utc_time, validate_job_id
from swassh.domain.transfers import FileTransfer, TransferDirection, local_filename


class ScalarBoundaryTests(unittest.TestCase):
    def test_byte_window_integer_type_limits_and_clock_regression(self):
        window=ByteWindow(1024,1024*10**9,10)
        for field,values in {'rate':(True,'1024',1023,2147483647*1024+1),
                             'credits':(True,'0',-1,1024*10**9+1),
                             'observed':(True,'0',-1,2**63)}.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    replace(window,**{field:value})
        for count in (True,'1',0,1025):
            with self.assertRaises(ValueError):window.reserve(count,10)
        for now in (True,'1',-1,2**63):
            with self.assertRaises(ValueError):window.reserve(1,now)
        next_window,wait=window.reserve(1,9)
        self.assertEqual((next_window.credits,next_window.observed,wait),(0,9,976563))
        self.assertEqual(ChannelCapture(Status.TIMEOUT,None,b'partial',b'',error='deadline').error,'deadline')

    def test_host_metadata_rejects_control_characters_without_restricting_display_unicode(self):
        for field,values in {'username':(1,True,'','bad name','a'*257),
                             'label':(1,True,'','a'*257,'line\nbreak','c1\x85control','delete\x7f')}.items():
            for value in values:
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):Host('host',**{field:value})
        host=Host('HOST',username='domain\\user',label='équipement')
        self.assertEqual((host.target,host.label),('domain\\user@host:22','équipement'))
        long_name='.'.join(('a'*63,'b'*63,'c'*63,'d'*62))
        with self.assertRaisesRegex(ValueError,'253'):Endpoint(long_name,22)
        # Unexpected library failures must stay distinguishable from bad input.
        with patch('swassh.domain.endpoints.ipaddress.IPv6Address',side_effect=RuntimeError('synthetic dependency fault')):
            with self.assertRaisesRegex(RuntimeError,'dependency fault'):Endpoint('::1',22)

    def test_inventory_brackets_limits_and_unexpected_host_errors(self):
        for value in ('[::1]junk','[::1]:x','[::1','[example]:22','host:bad','@host','a@b@c'):
            with self.subTest(value=value),self.assertRaises(InventoryError):parse_host(value)
        self.assertEqual(parse_host('[::1]'),Host('::1'))
        with patch('swassh.domain.inventory.MAX_HOSTS',2):
            with self.assertRaisesRegex(InventoryError,'too many input records'):normalize_hosts(('a','b','a'))
        with patch('swassh.domain.inventory.Host',side_effect=RuntimeError('synthetic dependency fault')):
            with self.assertRaisesRegex(RuntimeError,'dependency fault'):parse_host('host')

    def test_result_each_invalid_field_and_literal_json_error_contract(self):
        result=Result(Host('one'),Status.SUCCESS,exit_code=0)
        invalid={'host':(None,'one'),'status':('success',None),'changed':(1,None),
                 'stdout':(None,b'bytes'),'stderr':(None,b'bytes'),'error':(1,False),
                 'exit_signal':(1,False),'attempts':(True,'1',0,-1),
                 'duration':(True,'1',-1,float('nan'),float('inf')),
                 'phase':('other',True),'exit_code':(True,'0'),
                 'stdout_truncated':(1,None),'stderr_truncated':(1,None),'transfer':({},False)}
        for field,values in invalid.items():
            for value in values:
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):replace(result,**{field:value})
        with self.assertRaises(ValueError):replace(result,status=Status.FAILED,changed=True)
        with self.assertRaises(ValueError):replace(result,status=Status.SKIPPED,attempts=1)
        self.assertEqual(replace(result,status=Status.SKIPPED,attempts=0).attempts,0)
        self.assertEqual(replace(result,error='safe error',exit_signal='TERM',duration=0.5).error,'safe error')
        self.assertEqual(replace(result,stdout='{"values":[1,true,null]}').json(),{'values':[1,True,None]})
        for text in ('{"duplicate":1,"duplicate":2}','NaN','Infinity','['*2000):
            with self.subTest(text=text[:40]),self.assertRaises(ValueError):replace(result,stdout=text).json()

    def test_transfer_paths_sizes_and_filename_escaping_are_bounded(self):
        receipt=TransferReceipt('push','local','/remote',bytes_transferred=0)
        for field in ('local_path','remote_path','temporary_path','fallback_reason'):
            for value in (False,1,'','x'*4097,'x\nx','x\x85x','x\x7fx'):
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):replace(receipt,**{field:value})
        for value in (False,1.5,-1,'0'):
            with self.assertRaises(ValueError):replace(receipt,bytes_transferred=value)
        self.assertEqual(replace(receipt,temporary_path='/tmp/file',fallback_reason='explicit reason').temporary_path,'/tmp/file')
        transfer=FileTransfer(TransferDirection.PUSH,'local','/remote')
        with self.assertRaises(ValueError):replace(transfer,direction='push')
        for field in ('local_path','remote_path'):
            for value in (False,1,'','x'*4097,'x\nx','x\x85x','x\x7fx'):
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):replace(transfer,**{field:value})
        for remote in ('relative','/','/..','/safe/../escape'):
            with self.assertRaises(ValueError):replace(transfer,remote_path=remote)
        for remote in ('/','/.','/CON','/COM9.log','/bad:name','/é'*120):
            name=local_filename(remote)
            self.assertTrue(name)
            self.assertLessEqual(len(name.encode()),217)
            self.assertNotIn(':',name)
            self.assertEqual(name,local_filename(remote))


class CalendarBoundaryTests(unittest.TestCase):
    def test_utc_rejects_naive_absent_offsets_and_outside_calendar(self):
        class NoOffset(tzinfo):
            def utcoffset(self,value):return None
        for value in (None,'2030-01-01',datetime(2030,1,1),datetime(2030,1,1,tzinfo=NoOffset())):
            with self.assertRaises(ScheduleError):utc_time(value)
        for value in (1,None,[],False):
            with self.assertRaises(ScheduleError):parse_schedule_time(value)
            with self.assertRaises(ScheduleError):validate_job_id(value)
        for zone in (False,1,'x'*129):
            with self.assertRaises(ScheduleError):parse_schedule_time('2030-01-01 00:00',zone)
        for fold in (True,'0',-1,2):
            with self.assertRaises(ScheduleError):parse_schedule_time('2030-01-01 00:00',None,fold)
        self.assertEqual(parse_schedule_time('2030-01-01T00:00+23:59').day,31)
        with self.assertRaises(ScheduleError):parse_schedule_time('2030-01-01T00:00+24:00')

    def test_real_zoneinfo_transition_rules_from_an_in_memory_tzif(self):
        # This tiny TZif v1 has independently specified 2026 UTC transitions:
        # +01 -> +02 on March 29 at 01:00; reverse on October 25 at 01:00.
        transitions=(1774746000,1792890000)
        raw=(b'TZif\0'+b'\0'*15+struct.pack('!6l',0,0,0,2,2,8)
             +struct.pack('!2l',*transitions)+bytes((1,0))
             +struct.pack('!lbb',3600,0,0)+struct.pack('!lbb',7200,1,4)+b'CET\0CEST\0')
        zone=ZoneInfo.from_file(io.BytesIO(raw),key='Synthetic/Transitions')
        with patch('swassh.domain.scheduling.ZoneInfo',return_value=zone):
            with self.assertRaisesRegex(ScheduleError,'does not exist'):
                parse_schedule_time('2026-03-29 02:30','Synthetic/Transitions')
            with self.assertRaisesRegex(ScheduleError,'ambiguous'):
                parse_schedule_time('2026-10-25 02:30','Synthetic/Transitions')
            first=parse_schedule_time('2026-10-25 02:30','Synthetic/Transitions',0)
            second=parse_schedule_time('2026-10-25 02:30','Synthetic/Transitions',1)
            self.assertEqual(second-first,timedelta(hours=1))
            self.assertEqual(parse_schedule_time('2026-07-01 02:00','Synthetic/Transitions').hour,0)

    def test_job_metadata_calendar_types_counts_and_roundtrip(self):
        now=datetime(2030,1,1,tzinfo=UTC)
        job=JobInfo('a'*32,JobState.PENDING,now+timedelta(seconds=1),now,now+timedelta(seconds=2),
                    1,'b'*64,'report.json',1)
        for field,values in {'state':('pending',None),'host_count':(True,'1',0,100001),
                             'canary':(True,'1',0,100001),'command_sha256':(1,'x','A'*64),
                             'counts':([],{},dict.fromkeys((s.value for s in Status),-1),
                                       dict.fromkeys((s.value for s in Status),True),
                                       dict.fromkeys((s.value for s in Status),0))}.items():
            for value in values:
                with self.subTest(field=field,value=value),self.assertRaises(ScheduleError):replace(job,**{field:value})
        for changes in ({'due_at':now},{'deadline':job.due_at},{'started_at':now.replace(tzinfo=None)},
                        {'finished_at':'not a date'},{'run_id':'short'}):
            with self.assertRaises(ScheduleError):replace(job,**changes)
        counts={s.value:int(s==Status.SUCCESS) for s in Status}
        finished=replace(job,counts=counts,started_at=job.due_at,finished_at=job.deadline,run_id='c'*32)
        self.assertEqual(finished.to_dict()['counts'],counts)
        self.assertEqual(finished.to_dict()['started_at'],job.due_at.isoformat())


class PlanBoundaryTests(unittest.TestCase):
    def test_workflow_shape_edges_and_fan_in_topological_order(self):
        first=WorkflowStep('first',('one',),command='read')
        second=WorkflowStep('second',('one',),command='read')
        final=WorkflowStep('final',('one',),command='read',needs=('first','second'))
        workflow=Workflow('fan-in',(final,first,second))
        self.assertEqual(tuple(step.id for step in workflow.ordered_steps),('first','second','final'))
        self.assertEqual(Workflow.from_dict(workflow.to_dict()).digest,workflow.digest)
        for steps in ([],(),(None,),(first,)*257,(first,first)):
            with self.subTest(steps_type=type(steps)),self.assertRaises(ValueError):Workflow('bad',steps)
        with self.assertRaises(ValueError):replace(first,needs=('x',)*257)
        for raw in (None,[],{}, {**workflow.to_dict(),'schema_version':True},
                    {**workflow.to_dict(),'schema_version':2},{**workflow.to_dict(),'steps':()},
                    {**workflow.to_dict(),'steps':[]},{**workflow.to_dict(),'steps':[{}]*257},
                    {**workflow.to_dict(),'extra':1}):
            with self.assertRaises(ValueError):Workflow.from_dict(raw)
        # A realistic dense plan crosses the edge budget without any cycle.
        dense=tuple(WorkflowStep(f'n{i}',('one',),command='read',needs=tuple(f'n{j}' for j in range(i))) for i in range(93))
        with self.assertRaisesRegex(ValueError,'budget'):Workflow('dense',dense)
        hosts=tuple(Host(f'h{i}') for i in range(50001))
        step=WorkflowStep('large',hosts,command='read')
        with self.assertRaisesRegex(ValueError,'budget'):Workflow('too-many-targets',(step,replace(step,id='other')))

    def test_network_scalar_shapes_and_serialization_reject_each_ambiguous_term(self):
        step=NetworkStep('identify','show',('evidence',))
        for field,values in {'command':(None,1,'x'*4097,'line\nnext','c1\x85','delete\x7f'),
                             'expect':([],None,('x',)*17,('',),('x'*513,),(1,)),
                             'until':('',1,'x'*257),'reboot':(1,'yes'),'exact_lines':(1,None),
                             'stage':('unknown',None)}.items():
            for value in values:
                with self.subTest(field=field,value=repr(value)),self.assertRaises(ValueError):replace(step,**{field:value})
        policy=ReconnectPolicy()
        for field,values in {'attempts':(True,1.5,0,61),'timeout':(True,'1',0,3601,float('inf')),
                             'interval':(True,'1',0.09,61,float('nan'))}.items():
            for value in values:
                with self.assertRaises(ValueError):replace(policy,**{field:value})
        plan=NetworkProcedure('cisco_ios','administration',(step,))
        for steps in ([],(),(1,),(step,)*1001):
            with self.assertRaises(ValueError):replace(plan,steps=steps)
        huge=replace(step,command='x'*4096,expect=('x'*512,)*16)
        with self.assertRaisesRegex(ValueError,'1 MiB'):replace(plan,steps=(huge,)*100)
        for raw in (None,'text',[],{}, {**plan.to_dict(),'steps':[None]},
                    {**plan.to_dict(),'steps':[{}]}, {**plan.to_dict(),'steps':[{**plan.to_dict()['steps'][0],'unexpected':1}]},
                    {**plan.to_dict(),'reconnect':[]},{**plan.to_dict(),'reconnect':{}},
                    {**plan.to_dict(),'reconnect':{'attempts':1,'timeout':2,'interval':1,'extra':0}}):
            with self.subTest(raw=str(raw)[:100]),self.assertRaises(ValueError):
                NetworkProcedure.decode(raw if raw is None else json.dumps(raw).encode())

    def test_firmware_identity_and_confirmation_sequences_require_explicit_evidence(self):
        digest='a'*64
        stages=('identify','backup','transfer','checksum','activate','verify')
        evidence={'identify':('model','old'),'checksum':(digest,),'verify':('new',)}
        steps=tuple(NetworkStep(stage,stage,evidence.get(stage,('evidence',))) for stage in stages)
        firmware=NetworkProcedure('cisco_ios','firmware',steps,digest,'model','old','new','recover via isolated console')
        for change in ({'target_version':'old'},
                {'steps':(replace(steps[0],expect=('unrelated',)),*steps[1:])},
                {'steps':(*steps[:-1],replace(steps[-1],expect=('unrelated',)))}):
            with self.assertRaises(ValueError):replace(firmware,**change)
        normal=NetworkProcedure('cisco_ios','administration',(NetworkStep('identify','show',('evidence',)),))
        for field in ('model','current_version','target_version','recovery'):
            with self.assertRaisesRegex(ValueError,'only to firmware'):replace(normal,**{field:'not applicable'})
        prompted=(replace(normal.steps[0],until='confirm?'),NetworkStep('prepare','',('accepted',)))
        confirmed=replace(normal,steps=prompted)
        self.assertEqual(confirmed.steps[1].command,'')
        with self.assertRaisesRegex(ValueError,'confirmation response'):
            replace(normal,steps=(normal.steps[0],prompted[1]))
