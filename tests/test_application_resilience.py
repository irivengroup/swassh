"""Application invariants at admission, durable dispatch and replay boundaries."""
import asyncio
import contextlib
from datetime import UTC,datetime
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from swassh import DesiredState,Host,HostProfile,Options,Result,Status,Workflow,WorkflowStep
from swassh.application.admission import Admission
from swassh.application.contracts import ResourcePlan,RunSummary
from swassh.application.convergence import ConvergentTransport
from swassh.application.transfer_settings import TransferSettings
from swassh.application.transfers import TransferService
from swassh.application.workflows import WorkflowService
from swassh.domain.workflows import WorkflowError
from swassh.application import admission as admission_module

NOW=datetime(2030,1,1,tzinfo=UTC)


class MemoryWorkflowStore:
    """Recording application port; no database, file or command is simulated."""
    def __init__(self):self.calls=[];self.finish_error=None;self.claims=[];self.steps=[];self.on_claim=None
    @contextlib.contextmanager
    def worker_lock(self):
        self.calls.append(('lock',))
        try:yield
        finally:self.calls.append(('unlock',))
    def recover(self,now):self.calls.append(('recover',now));return 0
    def events(self):return []
    def claim_run(self,now):
        self.calls.append(('claim',now))
        if self.on_claim:self.on_claim()
        return self.claims.pop(0) if self.claims else None
    def definition(self,id):return self.prepared
    def claim_step(self,id,now):return self.steps.pop(0) if self.steps else None
    def finish_step(self,*args,**kwargs):
        self.calls.append(('finish',args,kwargs))
        if self.finish_error:raise self.finish_error


class AdmissionResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_circuit_opening_during_a_reserved_timer_returns_capacity_and_skips(self):
        admission=Admission(2,10,adaptive=True);admission.next_start=1
        times=iter((0,0,1));clock=SimpleNamespace(monotonic=lambda:next(times))
        async def sleep(delay):self.assertEqual(delay,1);admission.circuit_open=True
        with patch.object(admission_module,'time',clock),patch.object(admission_module.asyncio,'sleep',side_effect=sleep):
            self.assertFalse(await admission.acquire())
        self.assertEqual((admission.active,admission.skipped,admission.peak),(0,1,1))

    async def test_timer_exception_or_cancellation_releases_its_slot(self):
        for error in (RuntimeError('synthetic timer'),asyncio.CancelledError()):
            admission=Admission(1,10,adaptive=True);admission.next_start=1
            with patch.object(admission_module,'time',SimpleNamespace(monotonic=lambda:0)),patch.object(admission_module.asyncio,'sleep',side_effect=error):
                with self.assertRaises(type(error)):await admission.acquire()
            self.assertEqual(admission.active,0)

    async def test_waiting_worker_wakes_to_a_circuit_without_starting_any_operation(self):
        admission=Admission(1,10,adaptive=True,threshold=1)
        self.assertTrue(await admission.acquire())
        waiting=asyncio.create_task(admission.acquire());await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        await admission.complete(Result(Host('one'),Status.UNREACHABLE))
        self.assertFalse(await waiting)
        self.assertEqual((admission.active,admission.skipped,admission.failures),(0,1,1))


class DurableWorkflowBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def service(self,executor):
        store=MemoryWorkflowStore()
        return WorkflowService(store,executor,audit_factory=None,audit_path='unused',clock=lambda:NOW)

    @staticmethod
    def summary(ok=True):
        counts={status.value:int(status==(Status.SUCCESS if ok else Status.FAILED)) for status in Status}
        return RunSummary(1,counts,NOW,NOW,ResourcePlan(1,1,1024,1024,1))

    async def test_dispatch_rejects_invalid_summaries_and_never_reclassifies_failed_commits(self):
        step=WorkflowStep('one',('one',),command='opaque')
        for outcome in (object(),RuntimeError('synthetic-private'),self.summary(),self.summary(False)):
            async def execute(*args):
                if isinstance(outcome,Exception):raise outcome
                return outcome
            service=self.service(execute)
            self.assertTrue(await service._dispatch('a'*32,step,object(),asyncio.Event()))
            records=[record for record in service.store.calls if record[0]=='finish']
            self.assertEqual(len(records),1)
            self.assertEqual(records[0][1][2],isinstance(outcome,RunSummary) and outcome.ok)
            self.assertNotIn('synthetic-private',repr(records))
        async def execute(*args):return self.summary()
        service=self.service(execute);service.store.finish_error=OSError('durability fault')
        with self.assertRaisesRegex(OSError,'durability fault'):await service._dispatch('a'*32,step,object(),asyncio.Event())
        records=[record for record in service.store.calls if record[0]=='finish']
        self.assertEqual(len(records),1);self.assertTrue(records[0][1][2])

    async def test_stop_before_or_during_dispatch_prevents_replay_and_drains_cleanup(self):
        started=asyncio.Event();cleaned=asyncio.Event();calls=[]
        async def execute(*args):
            calls.append(args);started.set()
            try:await asyncio.Future()
            finally:cleaned.set()
        service=self.service(execute);step=WorkflowStep('one',('one',),command='opaque');stop=asyncio.Event();stop.set()
        self.assertFalse(await service._dispatch('a'*32,step,object(),stop));self.assertEqual(calls,[])
        stop.clear();dispatch=asyncio.create_task(service._dispatch('a'*32,step,object(),stop))
        await started.wait();stop.set();self.assertFalse(await dispatch)
        self.assertTrue(cleaned.is_set());self.assertEqual(len(calls),1)
        self.assertFalse(any(record[0]=='finish' for record in service.store.calls))

    async def test_serve_validates_options_polls_an_empty_queue_and_rejects_foreign_checkpoints(self):
        async def execute(*args):self.fail('foreign checkpoint executed')
        service=self.service(execute)
        for changes in ({'once':1},{'once':None},{'stop_event':object()},
                        *({'poll_interval':v} for v in (True,None,'1',0,0.09,61,float('nan'),float('inf')))):
            with self.subTest(changes=changes),self.assertRaises(ValueError):await service.serve(**changes)
        stop=asyncio.Event();claims=[];loop=asyncio.get_running_loop()
        def claimed():
            claims.append(True)
            if len(claims)==2:loop.call_soon_threadsafe(stop.set)
        service.store.on_claim=claimed
        async with asyncio.timeout(3):self.assertEqual(await service.serve(stop_event=stop,poll_interval=0.1),0)
        self.assertEqual(len(claims),2)
        self.assertEqual(sum(record[0]=='recover' for record in service.store.calls),2)
        self.assertEqual(service.store.calls[-1],('unlock',))
        service=self.service(execute);service.store.claims=['a'*32];service.store.steps=['foreign']
        step=WorkflowStep('one',('one',),command='opaque')
        service.store.prepared=SimpleNamespace(workflow=Workflow('plan',(step,)))
        with self.assertRaisesRegex(WorkflowError,'does not match'):await service.serve(once=True)
        self.assertEqual(service.store.calls[-1],('unlock',))
        self.assertEqual(sum(record[0]=='recover' for record in service.store.calls),2)


class ConfigurationAndTransferBoundaryTests(unittest.TestCase):
    def test_profile_metadata_budget_and_custom_codec_cannot_escape_their_contracts(self):
        # Repeated immutable path strings occupy little test memory while the
        # serialized inventory still crosses the real 4 MiB admission budget.
        profile_keys=('x'*4096,)*128
        profiles=tuple(HostProfile(f'h{i}',client_keys=profile_keys) for i in range(9))
        with self.assertRaisesRegex(ValueError,'4 MiB'):Options(host_profiles=profiles)
        decoder=SimpleNamespace(decode=lambda *args,**kwargs:b'not text')
        codec=SimpleNamespace(_is_text_encoding=True,incrementaldecoder=lambda **kwargs:decoder)
        with patch('swassh.application.options.codecs.lookup',return_value=codec),self.assertRaisesRegex(ValueError,'text codec'):
            Options(encoding='synthetic-codec')

    def test_transfer_policy_forbids_replay_interactive_modes_and_insufficient_capacity(self):
        ports=dict(transport_factory=lambda *args:None,audit_factory=None,planner=lambda options:ResourcePlan(1,1,8*1024**2,8*1024**2,1),reporter_factory=None,report_factory=None)
        for options in (Options(retries=1),Options(stdin_file='input'),Options(stream_output=True),Options(pty=True)):
            with self.assertRaises(ValueError):TransferService(options,TransferSettings(),**ports)
        with self.assertRaisesRegex(ValueError,'one native transfer worker'):TransferService(Options(),TransferSettings(),**ports).plan()
        for field in ('dry_run','verify_sha256'):
            with self.assertRaises(ValueError):TransferSettings(**{field:1})
        with self.assertRaises(ValueError):TransferSettings(dry_run=True,verify_sha256=True)
        with self.assertRaisesRegex(ValueError,'rsync options'):TransferSettings(rsync_options=('-a',))

    def test_desired_state_constructor_rejects_wrong_action_and_nonboolean_read_only_mode(self):
        action=DesiredState('state','check','apply')
        with self.assertRaises(TypeError):ConvergentTransport(None,None,None)
        with self.assertRaises(TypeError):ConvergentTransport(None,action,None,verify_only=1)

    def test_transfer_limits_reject_wrong_numeric_types_before_any_io(self):
        for value in (None, [], {}, '1', object()):
            with self.subTest(timeout_type=type(value).__name__), self.assertRaisesRegex(ValueError, 'timeout'):
                TransferSettings(timeout=value)
        for field in ('bandwidth_kib', 'max_file_mib', 'max_rsync_alloc_mib'):
            for value in (None, [], {}, '1', 1.0, True):
                with self.subTest(field=field, value_type=type(value).__name__), \
                        self.assertRaisesRegex(ValueError, field+' must be a positive integer'):
                    TransferSettings(**{field: value})
        self.assertEqual(TransferSettings(timeout=.25, bandwidth_kib=1,
            max_file_mib=1, max_rsync_alloc_mib=1).timeout, .25)

    def test_transfer_timeout_conversion_failure_never_creates_valid_settings(self):
        error = RuntimeError('synthetic numeric conversion failure')
        class UnavailableNumber(int):
            def __float__(self):
                raise error
        # The public SDK accepts int/float instances. A failing numeric
        # protocol is an error, never a validated or default timeout.
        with self.assertRaises(RuntimeError) as caught:
            TransferSettings(timeout=UnavailableNumber(1))
        self.assertIs(caught.exception, error)

    def test_transfer_executable_paths_require_nonempty_text_before_any_io(self):
        for field in ('rsync_executable', 'sftp_executable'):
            for value in (None, [], {}, False, 1, ''):
                with self.subTest(field=field, value_type=type(value).__name__), \
                        self.assertRaisesRegex(ValueError, field+' must be a nonempty executable path'):
                    TransferSettings(**{field: value})
