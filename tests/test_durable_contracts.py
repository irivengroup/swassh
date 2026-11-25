"""Owned cleanup survives repeated cancellation without dropping its result."""
import asyncio
import threading
import unittest
from contextlib import asynccontextmanager, nullcontext
from datetime import UTC, datetime
from contextvars import ContextVar
from unittest.mock import patch

from swassh.application import durable, workflows
from swassh.application.scheduling import SchedulingService
from swassh.application.task_ownership import wait_owned


class OwnedCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_durable_io_joins_a_thread_after_repeated_cancellation(self):
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        waits = asyncio.Queue()
        async def observed_wait(task):
            waits.put_nowait(None)
            return await wait_owned(task)
        def operation():
            started.set()
            if not release.wait(5):
                raise AssertionError('test did not release its owned operation')
            finished.set()
            return 17
        service = durable.DurableOutbox(None, audit_factory=None, audit_path='', audit_scope='test')
        with patch.object(durable, 'wait_owned', observed_wait):
            task = asyncio.create_task(service._io(operation))
            try:
                async with asyncio.timeout(4):
                    await waits.get()
                    self.assertTrue(await asyncio.to_thread(started.wait, 2))
                    for _ in range(3):
                        task.cancel()
                        await waits.get()
                        self.assertFalse(task.done())
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertTrue(finished.is_set())
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)

    async def test_workflow_drain_waits_for_native_cleanup_despite_repeated_cancellation(self):
        started, releasing, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        waits = asyncio.Queue()
        async def operation():
            started.set()
            try:
                await asyncio.Future()
            finally:
                await releasing.wait()
                finished.set()
        async def observed_wait(task):
            waits.put_nowait(None)
            return await wait_owned(task)
        owned = asyncio.create_task(operation())
        await started.wait()
        with patch.object(workflows, 'wait_owned', observed_wait):
            task = asyncio.create_task(workflows.WorkflowService._drain(owned))
            try:
                async with asyncio.timeout(4):
                    await waits.get()
                    for _ in range(3):
                        task.cancel()
                        await waits.get()
                        self.assertFalse(task.done())
                    releasing.set()
                    await task
                self.assertTrue(finished.is_set())
                self.assertTrue(owned.cancelled())
            finally:
                releasing.set()
                await asyncio.gather(task, owned, return_exceptions=True)



class OutboxBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """Exercise durable ordering in memory; filesystem durability stays integrated."""

    class Store:
        def __init__(self):
            self.records = [(1, {'event': 'first', 'fields': {'value': 17}})]
            self.trace = []
            self.reads = 0
            self.fail_read = False
            self.fail_ack = False
            self.on_ack = lambda: None
            self.on_read = lambda: None

        def events(self):
            self.reads += 1
            self.trace.append('read')
            self.on_read()
            if self.fail_read and self.reads == 2:
                raise OSError('synthetic read failure')
            return list(self.records)

        def acknowledge_events(self, through):
            self.trace.append(('ack', through))
            if self.fail_ack:
                raise OSError('synthetic acknowledgement failure')
            self.records = [record for record in self.records if record[0] > through]
            self.on_ack()

    def service(self, store, *, fail_emit=False, fail_close=False):
        @asynccontextmanager
        async def factory(path, scope):
            store.trace.append('open')
            class Sink:
                async def emit(inner, event, fields):
                    store.trace.append(('emit', event, fields['event_id']))
                    if fail_emit:
                        raise OSError('synthetic audit emission failure')
            yield Sink()
            store.trace.append('close')
            if fail_close:
                raise OSError('synthetic audit close failure')
        return durable.DurableOutbox(store, audit_factory=factory,
            audit_path='unused', audit_scope='test')

    async def test_every_batch_closes_before_ack_and_newly_committed_records_are_exported(self):
        store = self.Store()
        def publish_after_first_ack():
            if store.reads == 1:
                store.records.append((2, {'event': 'second', 'fields': {}}))
        store.on_ack = publish_after_first_ack
        await self.service(store)._flush_events()
        self.assertEqual(store.trace, ['read', 'open', ('emit', 'first', 1), 'close', ('ack', 1),
            'read', 'open', ('emit', 'second', 2), 'close', ('ack', 2), 'read'])
        self.assertEqual(store.records, [])

    async def test_post_ack_read_waits_for_all_batches_and_retains_caller_context(self):
        store=self.Store();service=self.service(store)
        context=ContextVar('synthetic-after-context',default='caller')
        slot=ContextVar('synthetic-after-slot',default=None)
        sequence=0;trace=[];reads=[]
        original_io=service._io
        async def observed_io(function,*args,**kwargs):
            nonlocal sequence
            sequence+=1
            token=slot.set(sequence)
            try:return await original_io(function,*args,**kwargs)
            finally:slot.reset(token)
        def on_ack():
            trace.append(('ack',slot.get(),context.get()))
            context.set('adapter-change')
            if store.reads==1:store.records.append((2,{'event':'second','fields':{}}))
        store.on_ack=on_ack
        def operation():return 17
        def after(value):
            self.assertEqual(value,17);self.assertEqual(store.records,[])
            reads.append((slot.get(),context.get()))
            store.trace.append('after-read')
            return 37
        with patch.object(service,'_io',observed_io):
            self.assertEqual(await service._io_then_flush_read(operation,after),(17,37))
        self.assertEqual(len(trace),2);self.assertEqual(reads,[(trace[-1][1],'caller')])
        self.assertIsNotNone(trace[-1][1])
        self.assertEqual(store.trace,['read','open',('emit','first',1),'close',('ack',1),
            'read','open',('emit','second',2),'close',('ack',2),'read','after-read'])

    async def test_empty_post_ack_read_error_remains_visible_without_repeating_operation(self):
        store=self.Store();store.records.clear();service=self.service(store);calls=[]
        def operation():calls.append('operation');return 17
        def after(value):
            self.assertEqual(value,17);calls.append('reader')
            raise OSError('synthetic reader failure')
        with self.assertRaisesRegex(OSError,'synthetic reader failure'):
            await service._io_then_flush_read(operation,after)
        self.assertEqual(calls,['operation','reader']);self.assertEqual(store.trace,['read'])

    async def test_missing_operation_result_still_drains_outbox_without_calling_reader(self):
        store=self.Store();service=self.service(store);calls=[]
        def operation():calls.append('operation');return None
        def after(value):raise AssertionError('reader must not be called without a result')
        self.assertEqual(await service._io_then_flush_read(operation,after),(None,None))
        self.assertEqual(calls,['operation']);self.assertEqual(store.records,[])
        self.assertEqual(store.trace,['read','open',('emit','first',1),'close',('ack',1),'read'])

    async def test_empty_outbox_never_opens_or_acknowledges_an_audit_batch(self):
        store = self.Store()
        store.records.clear()
        await self.service(store)._flush_events()
        self.assertEqual(store.trace, ['read'])

    async def test_emission_or_close_failure_retains_the_entire_unacknowledged_batch(self):
        for close in (False, True):
            with self.subTest(close=close):
                store = self.Store()
                service = self.service(store, fail_emit=not close, fail_close=close)
                with self.assertRaisesRegex(OSError, 'synthetic audit'):
                    await service._flush_events()
                self.assertEqual(len(store.records), 1)
                self.assertFalse(any(isinstance(value, tuple) and value[0] == 'ack' for value in store.trace))
                self.assertEqual(store.reads, 1)

    async def test_ack_failure_is_visible_before_any_following_read_or_export(self):
        store = self.Store()
        store.fail_ack = True
        with self.assertRaisesRegex(OSError, 'synthetic acknowledgement failure'):
            await self.service(store)._flush_events()
        self.assertEqual(store.trace, ['read', 'open', ('emit', 'first', 1), 'close', ('ack', 1)])
        self.assertEqual(len(store.records), 1)

    async def test_read_failure_after_committed_ack_is_visible_without_reexport(self):
        store = self.Store()
        store.fail_read = True
        with self.assertRaisesRegex(OSError, 'synthetic read failure'):
            await self.service(store)._flush_events()
        self.assertEqual(store.trace, ['read', 'open', ('emit', 'first', 1), 'close', ('ack', 1), 'read'])
        self.assertEqual(store.records, [])

    async def test_storage_context_changes_do_not_reach_the_next_read_or_caller(self):
        store = self.Store()
        context = ContextVar('synthetic_audit_context', default='absent')
        token = context.set('caller')
        observed = []
        store.on_read = lambda: observed.append(context.get())
        store.on_ack = lambda: context.set('storage-adapter')
        try:
            await self.service(store)._flush_events()
            self.assertEqual(observed, ['caller', 'caller'])
            self.assertEqual(context.get(), 'caller')
        finally:
            context.reset(token)

    async def test_repeated_cancellation_joins_the_ack_without_exporting_a_new_batch(self):
        store = self.Store()
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def acknowledge():
            entered.set()
            if not release.wait(3):
                raise AssertionError('owned acknowledgement was not released')
            store.records.append((2, {'event': 'second', 'fields': {}}))
            finished.set()
        store.on_ack = acknowledge
        task = asyncio.create_task(self.service(store)._flush_events())
        try:
            async with asyncio.timeout(4):
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                self.assertFalse(task.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertTrue(finished.is_set())
            self.assertEqual(store.records, [(2, {'event': 'second', 'fields': {}})])
            self.assertEqual([value for value in store.trace if isinstance(value, tuple) and value[0] == 'emit'],
                [('emit', 'first', 1)])
            self.assertEqual(store.trace.count(('ack', 1)), 1)
            # The owned native operation may finish its one bounded read after
            # committing the cursor. It must never start another audit effect.
            self.assertIn(store.reads, (1, 2))
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)

class WorkerOperationContextTests(unittest.IsolatedAsyncioTestCase):
    """Operation/read handoffs preserve public worker outcomes and context."""

    class EmptyStore:
        def __init__(self, context, fail_claim):
            self.context, self.fail_claim, self.trace = context, fail_claim, []

        def worker_lock(self):
            return nullcontext()

        def recover_running(self, now):
            self.trace.append('recover')
            self.context.set('recovery-adapter')
            return 0

        def claim_due(self, now):
            self.trace.append('claim')
            self.context.set('claim-adapter')
            if self.fail_claim:
                raise OSError('synthetic claim failure')
            return None

        def events(self):
            self.trace.append(('read', self.context.get()))
            return []

        def acknowledge_events(self, through):
            raise AssertionError('an empty outbox has no audit cursor')

    def worker(self, store):
        async def execute(job):
            raise AssertionError('an empty store cannot dispatch a job')
        def audit(path, scope):
            raise AssertionError('an empty outbox cannot open an audit sink')
        return SchedulingService(store, execute, audit_factory=audit, audit_path='unused',
            clock=lambda: datetime(2030, 1, 1, tzinfo=UTC))

    async def test_native_operation_context_does_not_change_following_reads_or_worker_result(self):
        context = ContextVar('synthetic_empty_worker_context', default='unset')
        token = context.set('caller')
        store = self.EmptyStore(context, False)
        try:
            self.assertEqual(await self.worker(store).serve(once=True), 0)
            self.assertEqual(store.trace, ['recover', ('read', 'caller'), 'claim',
                ('read', 'caller'), 'recover', ('read', 'caller')])
            self.assertEqual(context.get(), 'caller')
        finally:
            context.reset(token)

    async def test_failed_claim_is_propagated_before_any_following_read_and_recovery_is_drained(self):
        context = ContextVar('synthetic_failed_worker_context', default='unset')
        token = context.set('caller')
        store = self.EmptyStore(context, True)
        try:
            with self.assertRaisesRegex(OSError, 'synthetic claim failure'):
                await self.worker(store).serve(once=True)
            self.assertEqual(store.trace, ['recover', ('read', 'caller'), 'claim',
                'recover', ('read', 'caller')])
            self.assertEqual(context.get(), 'caller')
        finally:
            context.reset(token)


class NativeOwnerBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """One admitted native command, fresh context, and fully owned shutdown."""

    def service(self):
        return durable.DurableOutbox(None,audit_factory=None,audit_path='unused',audit_scope='test')

    async def test_serial_commands_share_one_worker_but_never_share_adapter_context(self):
        service=self.service();context=ContextVar('native-owner-request',default='caller');threads=[]
        def mutate():
            threads.append(threading.get_ident());context.set('adapter');return 17
        def read():threads.append(threading.get_ident());return context.get()
        async with service._native_scope():
            owner=service._native;self.assertEqual(owner.commands.maxsize,1)
            self.assertEqual(await service._io(mutate),17)
            self.assertEqual(await service._io(read),'caller')
            with self.assertRaisesRegex(ValueError,'synthetic native failure'):
                await service._io(lambda:(_ for _ in ()).throw(ValueError('synthetic native failure')))
            self.assertEqual(await service._io(lambda:23),23)
            self.assertEqual(context.get(),'caller');self.assertEqual(len(set(threads)),1);self.assertEqual(len(threads),2)
        self.assertIsNone(service._native);self.assertTrue(owner.worker.done());owner.worker.result()
        self.assertFalse(any(thread.ident==threads[0] for thread in threading.enumerate()))
        await owner.close()
        with self.assertRaisesRegex(RuntimeError,'closed'):owner.submit(lambda:None)

    async def test_overlapping_admission_is_refused_and_stale_release_cannot_drop_a_command(self):
        service=self.service();entered=threading.Event();release=threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):raise AssertionError('synthetic release missing')
            return 31
        async with service._native_scope():
            task=asyncio.create_task(service._io(operation))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait,2));owner=service._native
                pending=owner.pending;owner.release(asyncio.get_running_loop().create_future())
                self.assertIs(owner.pending,pending)
                with self.assertRaisesRegex(RuntimeError,'concurrent'):owner.submit(lambda:None)
                release.set();self.assertEqual(await task,31);self.assertIsNone(owner.pending)
            finally:release.set();await asyncio.gather(task,return_exceptions=True)

    async def test_repeated_cancellation_joins_the_admitted_command_before_scope_release(self):
        service=self.service();entered=threading.Event();release=threading.Event();finished=threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):raise AssertionError('synthetic release missing')
            finished.set();return 41
        async with service._native_scope():
            owner=service._native;task=asyncio.create_task(service._io(operation))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait,2))
                for _ in range(3):task.cancel();await asyncio.sleep(0);self.assertFalse(task.done())
                self.assertFalse(owner.pending.cancelled());release.set()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertTrue(finished.is_set());self.assertIsNone(owner.pending)
            finally:release.set();await asyncio.gather(task,return_exceptions=True)
        self.assertIsNone(service._native);self.assertTrue(owner.worker.done())

    async def test_close_joins_a_pending_command_and_worker_despite_repeated_cancellation(self):
        owner=durable._NativeOwner();entered=threading.Event();release=threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):raise AssertionError('synthetic release missing')
            return 47
        future=owner.submit(operation);closer=None
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait,2))
            closer=asyncio.create_task(owner.close());await asyncio.sleep(0)
            with self.assertRaisesRegex(RuntimeError,'closed'):owner.submit(lambda:None)
            for _ in range(3):closer.cancel();await asyncio.sleep(0);self.assertFalse(closer.done())
            self.assertFalse(future.cancelled());release.set()
            with self.assertRaises(asyncio.CancelledError):await closer
            self.assertEqual(future.result(),47);self.assertTrue(owner.worker.done());owner.worker.result()
        finally:
            release.set()
            if closer is not None:await asyncio.gather(closer,return_exceptions=True)
            await owner.close()

    async def test_scope_refuses_nesting_and_resets_owner_after_body_failure(self):
        service=self.service()
        with self.assertRaisesRegex(OSError,'synthetic body failure'):
            async with service._native_scope():
                owner=service._native
                with self.assertRaisesRegex(RuntimeError,'nested'):
                    async with service._native_scope():self.fail('nested owner accepted')
                raise OSError('synthetic body failure')
        self.assertIsNone(service._native);self.assertTrue(owner.worker.done())

    async def test_pending_failure_is_reported_after_worker_shutdown_and_on_repeated_close(self):
        owner=durable._NativeOwner();entered=threading.Event();release=threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):raise AssertionError('synthetic release missing')
            raise ValueError('synthetic pending failure')
        future=owner.submit(operation)
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait,2));release.set()
            with self.assertRaisesRegex(ValueError,'synthetic pending failure'):await owner.close()
            with self.assertRaisesRegex(ValueError,'synthetic pending failure'):future.result()
            self.assertTrue(owner.worker.done())
            with self.assertRaisesRegex(ValueError,'synthetic pending failure'):await owner.close()
        finally:release.set()

    async def test_premature_native_exit_fails_the_command_without_running_its_effect(self):
        for failure in (False,True):
            with self.subTest(failure=failure):
                release=threading.Event()
                def stopped(inner):
                    if not release.wait(3):raise AssertionError('synthetic worker release missing')
                    if failure:raise OSError('synthetic worker loss')
                with patch.object(durable._NativeOwner,'_run',stopped):owner=durable._NativeOwner()
                effects=[];expected=OSError if failure else RuntimeError
                try:
                    future=owner.submit(lambda:effects.append('unexpected'))
                    release.set()
                    with self.assertRaises(expected):await future
                    with self.assertRaises(expected):await owner.close()
                    with self.assertRaises(expected):owner.submit(lambda:None)
                    self.assertEqual(effects,[]);self.assertTrue(owner.worker.done())
                finally:
                    release.set()
                    try:await owner.close()
                    except expected:pass

    async def test_already_stopped_worker_refuses_admission_without_running_any_command(self):
        for failure in (False,True):
            with self.subTest(failure=failure):
                def stopped(inner):
                    if failure:raise OSError('synthetic worker loss')
                with patch.object(durable._NativeOwner,'_run',stopped):owner=durable._NativeOwner()
                await owner._join(owner.worker);effects=[]
                expected=OSError if failure else RuntimeError
                try:
                    with self.assertRaises(expected):owner.submit(lambda:effects.append('unexpected'))
                    self.assertEqual(effects,[])
                finally:
                    if failure:
                        with self.assertRaises(OSError):await owner.close()
                    else:await owner.close()

    async def test_cancelled_worker_notification_fails_pending_reply_and_still_joins_real_worker(self):
        owner=durable._NativeOwner();entered=threading.Event();release=threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):raise AssertionError('synthetic release missing')
            return 53
        future=owner.submit(operation)
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait,2))
            cancelled=asyncio.get_running_loop().create_future();cancelled.cancel()
            owner._worker_done(cancelled)
            with self.assertRaisesRegex(RuntimeError,'was cancelled'):await future
            release.set()
            with self.assertRaisesRegex(RuntimeError,'was cancelled'):await owner.close()
            self.assertTrue(owner.worker.done())
        finally:release.set()

    async def test_native_owner_never_occupies_the_single_thread_of_the_shared_executor(self):
        from concurrent.futures import ThreadPoolExecutor
        loop=asyncio.get_running_loop();loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        service=self.service()
        async with asyncio.timeout(3):
            async with service._native_scope():
                native=await service._io(threading.get_ident)
                shared=await asyncio.to_thread(threading.get_ident)
                self.assertNotEqual(native,shared)
                self.assertEqual(await service._io(lambda:67),67)
        self.assertIsNone(service._native)

    async def test_submission_failure_retires_executor_before_scope_entry_can_publish_owner(self):
        from concurrent.futures import ThreadPoolExecutor
        shutdown=[]
        class ObservedExecutor(ThreadPoolExecutor):
            def shutdown(inner,wait=True,*,cancel_futures=False):
                shutdown.append(wait)
                super().shutdown(wait=wait,cancel_futures=cancel_futures)
        service=self.service();loop=asyncio.get_running_loop()
        with patch.object(durable,'ThreadPoolExecutor',ObservedExecutor),\
                patch.object(loop,'run_in_executor',side_effect=RuntimeError('synthetic submission failure')):
            with self.assertRaisesRegex(RuntimeError,'synthetic submission failure'):
                async with service._native_scope():self.fail('failed owner was published')
        self.assertEqual(shutdown,[True]);self.assertIsNone(service._native)

    async def test_late_reply_notification_keeps_an_already_retrieved_outcome(self):
        loop=asyncio.get_running_loop()
        completed=loop.create_future();completed.set_result(59)
        durable._NativeOwner._complete(completed,None,ValueError('synthetic late failure'))
        self.assertEqual(completed.result(),59)
        cancelled=loop.create_future();cancelled.cancel()
        durable._NativeOwner._complete(cancelled,61,None);self.assertTrue(cancelled.cancelled())


class WorkflowCompletionBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """Completion snapshots share ownership; failures never repeat a commit."""

    async def exercise(self, *, read_failure=False, close_failure=False, execution_failure=False):
        from types import SimpleNamespace
        from swassh.application.contracts import RunSummary,ResourcePlan
        from swassh.domain.models import Status
        ticket=ContextVar('synthetic-native-ticket',default=None)
        context=ContextVar('synthetic-request-context',default='caller')
        trace=[];records=[];finished=[];closed=False;counter=0
        def finish(*args,**kwargs):
            finished.append((args,kwargs))
            trace.append(('finish',ticket.get(),context.get()))
            context.set('adapter-mutation')
            records.append((1,{'event':'workflow_step_completed','fields':{}}))
        def events():
            trace.append(('read',ticket.get(),context.get()))
            if read_failure:raise OSError('synthetic snapshot read failure')
            return list(records)
        def acknowledge(through):
            self.assertTrue(closed)
            trace.append(('ack',ticket.get(),context.get()))
            records.clear()
        store=SimpleNamespace(finish_step=finish,events=events,acknowledge_events=acknowledge)
        @asynccontextmanager
        async def audit(path,scope):
            nonlocal closed
            trace.append(('open',None,context.get()))
            class Sink:
                async def emit(inner,*args):trace.append(('emit',None,context.get()))
            yield Sink()
            trace.append(('close',None,context.get()))
            if close_failure:raise OSError('synthetic audit close failure')
            closed=True
        now=datetime(2030,1,1,tzinfo=UTC)
        counts={status.value:int(status==Status.SUCCESS) for status in Status}
        summary=RunSummary(1,counts,now,now,ResourcePlan(1,1,1,1,1))
        async def execute(*args):
            if execution_failure:raise RuntimeError('synthetic executor failure')
            return summary
        service=workflows.WorkflowService(store,execute,audit_factory=audit,audit_path='unused',clock=lambda:now)
        from contextvars import Context
        from functools import partial
        loop=asyncio.get_running_loop()
        original=loop.run_in_executor
        def observed(executor,function,*args):
            nonlocal counter
            counter+=1
            current=counter
            self.assertIsInstance(function,partial)
            captured=getattr(function.func,'__self__',None)
            self.assertIsInstance(captured,Context)
            def native():
                # Stamp inside the captured native context, not outside ctx.run.
                captured.run(ticket.set,current)
                return function(*args)
            return original(executor,native)
        error=None
        with patch.object(loop,'run_in_executor',observed):
            try:
                value=await service._dispatch('a'*32,SimpleNamespace(id='step'),object(),asyncio.Event())
            except OSError as caught:
                error=caught;value=None
        return SimpleNamespace(trace=trace,records=records,finished=finished,value=value,error=error)

    async def test_completion_and_first_snapshot_share_one_owned_native_context(self):
        result=await self.exercise()
        self.assertIsNone(result.error);self.assertIs(result.value,True)
        self.assertEqual(result.records,[])
        self.assertEqual(len(result.finished),1)
        finish=next(row for row in result.trace if row[0]=='finish')
        read=next(row for row in result.trace if row[0]=='read')
        self.assertIsNotNone(finish[1])
        self.assertEqual(read[1],finish[1])
        self.assertEqual(read[2],'caller')
        names=[row[0] for row in result.trace]
        self.assertLess(names.index('close'),names.index('ack'))

    async def test_snapshot_and_audit_failures_never_repeat_or_reclassify_the_commit(self):
        for read,close,execution in ((True,False,False),(False,True,False),(False,True,True)):
            with self.subTest(read=read,close=close,execution=execution):
                result=await self.exercise(read_failure=read,close_failure=close,execution_failure=execution)
                self.assertIsInstance(result.error,OSError)
                self.assertEqual(len(result.finished),1)
                self.assertIs(result.finished[0][0][2],not execution)
                self.assertEqual(len(result.records),1)
                self.assertNotIn('ack',[row[0] for row in result.trace])
