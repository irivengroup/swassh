"""Bounded queue accounting never borrows time from active SSH execution."""
import asyncio
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from swassh.infrastructure import process_guard as guard


class AdmissionReceiptTests(unittest.TestCase):
    def test_atomic_replacement_and_strict_local_schema(self):
        from swassh.infrastructure.admission_deadline import AdmissionDeadline, publish_admission
        with tempfile.TemporaryDirectory() as directory:
            deadline = AdmissionDeadline(directory, Mock(), .3, 0.)
            self.assertIsNone(deadline._read())
            publish_admission(directory, 'queued', 0.)
            self.assertEqual(deadline._read()['state'], 'queued')
            self.assertEqual(deadline._read()['seconds'], 0.)
            self.assertGreater(deadline._read()['completed_at'], 0.)
            publish_admission(directory, 'admitted', .125)
            self.assertEqual(deadline._read()['seconds'], .125)
            self.assertFalse((Path(directory) / 'admission.initializing').exists())
            valid = {'schema_version': 1, 'state': 'admitted', 'seconds': .1, 'completed_at': 1.}
            invalid = [None, [], {}, {**valid, 'extra': 1}, {**valid, 'schema_version': True},
                       {**valid, 'schema_version': 2},
                       {**valid, 'state': 'remote says admitted'}, {**valid, 'state': []}]
            invalid += [{**valid, 'seconds': v} for v in (True, -1, .301, float('inf'), float('nan'), '0.1')]
            invalid += [{**valid, 'completed_at': v} for v in (True, -1, float('inf'), float('nan'), '1', 10**1000)]
            for value in invalid:
                with self.subTest(value=value):
                    deadline.path.write_text(json.dumps(value), encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, '^invalid private admission receipt$'):
                        deadline._read()
            for raw in ('{', ' ' * 1025, json.dumps(valid)+' '*1025):
                deadline.path.write_text(raw, encoding='utf-8')
                with self.assertRaises(ValueError): deadline._read()

    def test_interrupted_publication_keeps_previous_complete_receipt(self):
        from swassh.infrastructure.admission_deadline import publish_admission
        with tempfile.TemporaryDirectory() as directory:
            publish_admission(directory, 'queued', 0.)
            path = Path(directory) / 'admission.json'
            before = path.read_bytes()
            from swassh.infrastructure import windows
            owner, method = (windows, 'replace_atomic_receipt') if os.name == 'nt' else (os, 'replace')
            with patch.object(owner, method, side_effect=OSError('interrupted')):
                with self.assertRaises(OSError): publish_admission(directory, 'admitted', .1)
            self.assertEqual(path.read_bytes(), before)

    def test_write_and_read_faults_cannot_publish_or_fabricate_admission(self):
        from swassh.infrastructure import admission_deadline as protocol
        with tempfile.TemporaryDirectory() as directory:
            protocol.publish_admission(directory, 'queued', 0.)
            path = Path(directory)/'admission.json'; original = path.read_bytes()
            with patch.object(protocol.json, 'dump', side_effect=OSError('synthetic disk fault')):
                with self.assertRaisesRegex(OSError, 'disk fault'):
                    protocol.publish_admission(directory, 'admitted', .1)
            self.assertEqual(path.read_bytes(), original)
            class FailedReader(io.BytesIO):
                def read(self, *args): raise OSError('synthetic read fault')
            observer = protocol.AdmissionDeadline(directory, Mock(), .3, 0.)
            # Inject at the actual reader boundary on each OS.
            owner, method = (protocol.os, 'fdopen') if os.name == 'nt' else (protocol.Path, 'open')
            def failing_reader(descriptor, *args):
                os.close(descriptor)
                return FailedReader()
            replacement = {'side_effect': failing_reader} if os.name == 'nt' else {'return_value': FailedReader()}
            with patch.object(owner, method, **replacement), \
                    self.assertRaisesRegex(OSError, 'read fault'):
                observer._read()
            # Resource exhaustion is not malformed input and cannot be hidden
            # by converting it to a successful or absent observation.
            with patch.object(protocol.json, 'loads', side_effect=MemoryError('synthetic allocation fault')), \
                    self.assertRaises(MemoryError):
                observer._read()


    @unittest.skipUnless(os.name == 'nt', 'native Windows sharing required')
    def test_reader_keeps_a_complete_snapshot_while_guardian_atomically_publishes(self):
        """The real Windows reader must not kill the guardian's publication."""
        import threading
        from swassh.infrastructure.admission_deadline import AdmissionDeadline,publish_admission
        with tempfile.TemporaryDirectory() as directory:
            publish_admission(directory,'queued',0.)
            path=Path(directory)/'admission.json'
            # Establish the native refusal independently of the adapter.
            with path.open('rb'),self.assertRaises(PermissionError):
                publish_admission(directory,'admitted',.1)
            (Path(directory)/'admission.initializing').unlink()
            observer=AdmissionDeadline(directory,Mock(),.3,0.)
            opened,fdopened=Path.open,os.fdopen
            writers=[];errors=[];held=[]
            class Reader:
                def __init__(inner,stream):inner.stream=stream
                def __enter__(inner):inner.stream.__enter__();return inner
                def __exit__(inner,*args):return inner.stream.__exit__(*args)
                def read(inner,*args):
                    raw=inner.stream.read(*args)
                    if not held:
                        held.append(True)
                        def publish():
                            try:publish_admission(directory,'admitted',.1)
                            except Exception as error:errors.append(error)
                        writer=threading.Thread(target=publish);writers.append(writer);writer.start();writer.join(2)
                    return raw
            def opening(target,*args,**kwargs):
                stream=opened(target,*args,**kwargs)
                return Reader(stream) if target==path and args==('rb',) else stream
            def fdopening(*args,**kwargs):return Reader(fdopened(*args,**kwargs))
            with patch.object(Path,'open',opening),patch.object(os,'fdopen',fdopening):
                first=observer._read()
            for writer in writers:writer.join(2)
            self.assertEqual(held,[True])
            self.assertFalse(any(writer.is_alive() for writer in writers))
            self.assertEqual(errors,[])
            self.assertEqual(first['state'],'queued')
            self.assertEqual(observer._read()['state'],'admitted')
            self.assertFalse((Path(directory)/'admission.initializing').exists())

    def test_windows_atomic_reader_keeps_read_rights_and_propagates_real_failures(self):
        """Replacement sharing must not fabricate admission or hide ACL/read errors."""
        from swassh.infrastructure import admission_deadline as protocol,windows
        record={'schema_version':1,'state':'admitted','seconds':.1,'completed_at':1.}
        payload=json.dumps(record).encode('ascii')
        port=SimpleNamespace(**vars(os));port.name='nt';port.fdopen=Mock(return_value=io.BytesIO(payload))
        observer=protocol.AdmissionDeadline('unused-private-directory',Mock(),.3,0.)
        with patch.object(protocol,'os',port),patch.object(windows,'open_file_without_reparse',return_value=41) as opening:
            self.assertEqual(observer._read(),record)
        opening.assert_called_once_with(observer.path,os.O_RDONLY,share_delete=True)
        port.fdopen.assert_called_once_with(41,'rb')
        for error in (OSError('synthetic stream failure'), MemoryError('synthetic stream allocation failure')):
            with self.subTest(stream_error=type(error).__name__),patch.object(protocol,'os',port), \
                    patch.object(windows,'open_file_without_reparse',return_value=41), \
                    patch.object(port,'fdopen',side_effect=error),patch.object(port,'close') as closing, \
                    self.assertRaises(type(error)):
                observer._read()
            closing.assert_called_once_with(41)
        for error in (PermissionError(13,'synthetic ACL denial'),OSError('synthetic native open failure'),MemoryError('synthetic allocation failure')):
            with self.subTest(error=type(error).__name__),patch.object(protocol,'os',port), \
                    patch.object(windows,'open_file_without_reparse',side_effect=error) as opening, \
                    self.assertRaises(type(error)):
                observer._read()
            self.assertEqual(opening.call_count,1)
        with patch.object(protocol,'os',port),patch.object(windows,'open_file_without_reparse',side_effect=FileNotFoundError):
            self.assertIsNone(observer._read())


    def test_windows_receipt_replacement_only_uses_move_for_initial_publication(self):
        """ACL, sharing and partial-replacement errors must remain failures."""
        from swassh.infrastructure import windows
        kernel=SimpleNamespace(ReplaceFileW=Mock(return_value=1))
        with patch.object(windows,'kernel32',return_value=kernel),patch.object(windows.os,'replace') as moving:
            windows.replace_atomic_receipt('new','current')
        kernel.ReplaceFileW.assert_called_once_with('current','new',None,0,None,None)
        moving.assert_not_called()
        for code in (2,5,32,33,1175,1176,1177):
            with self.subTest(code=code):
                kernel.ReplaceFileW.reset_mock();kernel.ReplaceFileW.return_value=0
                with patch.object(windows,'kernel32',return_value=kernel), \
                        patch.object(windows.ctypes,'get_last_error',return_value=code,create=True), \
                        patch.object(windows.ctypes,'WinError',side_effect=lambda number:OSError(number,'controlled native failure'),create=True), \
                        patch.object(windows.os,'replace') as moving:
                    if code==2:
                        windows.replace_atomic_receipt('new','current')
                        moving.assert_called_once_with('new','current')
                    else:
                        with self.assertRaises(OSError):windows.replace_atomic_receipt('new','current')
                        moving.assert_not_called()
                kernel.ReplaceFileW.assert_called_once_with('current','new',None,0,None,None)


    def test_each_platform_dispatches_to_its_atomic_reader_and_writer(self):
        """Exercise both dispatch contracts on every host; native sharing has its own integration test."""
        from swassh.infrastructure import admission_deadline as protocol, windows
        for platform in ('posix','nt'):
            with self.subTest(platform=platform),tempfile.TemporaryDirectory() as directory:
                port=SimpleNamespace(**vars(os));port.name=platform
                path=Path(directory)/'admission.json'
                temporary=path.with_suffix('.initializing')
                def opening(target,flags,*,share_delete):
                    self.assertTrue(share_delete)
                    return os.open(target,flags)
                # These doubles model only platform dispatch. The separate Windows
                # test holds a real handle during a real native replacement.
                with patch.object(protocol,'os',port), \
                        patch.object(windows,'replace_atomic_receipt',side_effect=os.replace) as replacing, \
                        patch.object(windows,'open_file_without_reparse',side_effect=opening) as reading:
                    observer=protocol.AdmissionDeadline(directory,Mock(),.3,0.)
                    protocol.publish_admission(directory,'queued',0.)
                    self.assertEqual(observer._read()['state'],'queued')
                    protocol.publish_admission(directory,'admitted',.1)
                    self.assertEqual(observer._read()['seconds'],.1)
                    self.assertFalse(temporary.exists())
                if platform=='nt':
                    self.assertEqual(replacing.call_count,2)
                    self.assertEqual(reading.call_count,2)
                    replacing.assert_called_with(temporary,path)
                    reading.assert_called_with(path,os.O_RDONLY,share_delete=True)
                else:
                    replacing.assert_not_called()
                    reading.assert_not_called()



class AdmissionClockTests(unittest.IsolatedAsyncioTestCase):
    async def observe(self, records, *, now=10., end=10.2, exited=False):
        from swassh.infrastructure.admission_deadline import AdmissionDeadline
        deadline = Mock(); deadline.when.return_value = end
        clock = AdmissionDeadline('unused-private-directory', deadline, .3, 9.9)
        process = SimpleNamespace(returncode=0 if exited else None)
        samples = iter(({**row, 'completed_at': 9.9+row['seconds']} if row is not None else None)
                       for row in records)
        async def yield_once(delay): self.assertEqual(delay, .005)
        with patch.object(clock, '_read', side_effect=lambda: next(samples)), \
                patch('asyncio.sleep', side_effect=yield_once), \
                patch('asyncio.get_running_loop', return_value=SimpleNamespace(time=lambda: now)):
            await clock.observe(process)
        return deadline

    async def test_only_measured_queue_time_extends_original_active_deadline(self):
        deadline = await self.observe([None, {'state': 'queued', 'seconds': 0.},
                                       {'state': 'queued', 'seconds': 0.},
                                       {'state': 'admitted', 'seconds': .075}])
        self.assertEqual([c.args for c in deadline.reschedule.call_args_list], [(10.5,), (10.274999999999999,)])
        deadline = await self.observe([{'state': 'admitted', 'seconds': 0.}])
        self.assertEqual([c.args for c in deadline.reschedule.call_args_list], [(10.5,), (10.2,)])

    async def test_expired_active_and_queue_deadlines_cannot_be_rescued_by_completion(self):
        for records, now in (([{'state': 'expired', 'seconds': .3}], 10.),
                             ([{'state': 'admitted', 'seconds': .1}], 10.4)):
            with self.subTest(records=records), self.assertRaises(TimeoutError):
                await self.observe(records, now=now, exited=True)

    async def test_process_death_cannot_leave_unearned_queue_credit(self):
        with self.assertRaisesRegex(ValueError, 'before admission receipt'):
            await self.observe([None], exited=True)
        with self.assertRaisesRegex(ValueError, 'before admission receipt'):
            await self.observe([{'state': 'queued', 'seconds': 0.}], exited=True)
        deadline = await self.observe([{'state': 'admitted', 'seconds': .1}], end=None)
        deadline.reschedule.assert_not_called()

    async def test_admission_credit_is_bounded_and_never_accepts_future_time(self):
        for seconds in (.25, .4):
            with self.subTest(seconds=seconds), self.assertRaises(TimeoutError):
                await self.observe([{'state': 'admitted', 'seconds': seconds}])
        with self.assertRaises(TimeoutError):
            await self.observe([{'state': 'admitted', 'seconds': .4}], now=10.4, end=None)

    async def test_observer_delay_cannot_rescue_an_expired_active_deadline(self):
        from swassh.infrastructure.admission_deadline import AdmissionDeadline
        deadline = Mock(); deadline.when.return_value = 10.2
        clock = AdmissionDeadline('unused-private-directory', deadline, .3, 9.9)
        loop = Mock(); loop.time.side_effect = [10., 10.4, 10.4]
        receipt = {'state': 'admitted', 'seconds': .05, 'completed_at': 9.95}
        with patch.object(clock, '_read', return_value=receipt), \
                patch('asyncio.get_running_loop', return_value=loop), self.assertRaises(TimeoutError):
            await clock.observe(SimpleNamespace(returncode=0))
        deadline.reschedule.assert_called_once_with(10.5)

    async def test_finite_inputs_cannot_overflow_the_combined_deadline_to_infinity(self):
        from swassh.infrastructure.admission_deadline import AdmissionDeadline
        deadline = Mock(); deadline.when.return_value = 1e308
        observer = AdmissionDeadline('unused-private-directory', deadline, 1e308, 1.)
        receipt = {'state': 'admitted', 'seconds': 1., 'completed_at': 2.}
        with patch.object(observer, '_read', return_value=receipt), \
                patch('asyncio.get_running_loop', return_value=SimpleNamespace(time=lambda: 2.)), \
                self.assertRaisesRegex(ValueError, 'supported clock range'):
            await observer.observe(SimpleNamespace(returncode=0))
        deadline.reschedule.assert_not_called()

    async def test_unfinished_guardian_has_a_finite_independent_admission_cap(self):
        from swassh.infrastructure.admission_deadline import AdmissionDeadline
        loop = asyncio.get_running_loop()
        started = loop.time()
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(.03) as deadline:
                initial = deadline.when()
                observer = AdmissionDeadline('unused-private-directory', deadline, .03, started)
                with patch.object(observer, '_read', return_value=None):
                    await observer.observe(SimpleNamespace(returncode=None))
        # A creation phase already expired under scheduling contention must
        # fail immediately; otherwise exactly one finite admission cap applies.
        self.assertIn(deadline.when(), (initial, initial+.03))
        # asyncio call_at may fire at most one monotonic-clock resolution
        # early. This is 15.625 ms on older native Windows interpreters.
        # The exact finite deadline above and every budget/refusal stay strict;
        # no time is added to the application or native guardian allowance.
        resolution = time.get_clock_info('monotonic').resolution
        self.assertGreaterEqual(loop.time() + resolution, deadline.when())


class GuardianQueueDeadlineTests(unittest.TestCase):
    def run_guardian(self, polls, *, limit=.3, prepare_seconds=0):
        now = [100.]; events = []
        lease = Mock(); lease.poll.side_effect = polls; lease.retry_after = .05
        pool = Mock(); pool.ticket.return_value = lease
        child = Mock(returncode=0); child.poll.return_value = 0
        fake_os = SimpleNamespace(**vars(os)); fake_os.name = 'posix'; fake_os.killpg = Mock()
        fake_signal = SimpleNamespace(**vars(signal)); fake_signal.SIGWINCH = getattr(signal, 'SIGWINCH', 28)
        fake_signal.SIGKILL = getattr(signal, 'SIGKILL', 9); fake_signal.signal = Mock()
        def sleep(seconds):
            self.assertGreater(seconds, 0); self.assertLessEqual(seconds, .05)
            now[0] += seconds
        def launch(*args, **kwargs):
            events.append(json.loads((path.parent/'admission.json').read_text()))
            return child
        data = dict(argv=['synthetic'], budget={}, connections=1, bandwidth=0, parent_pid=1,
                    parent_token=None, parent_fd=7, invocation=None, admission_wait_limit=limit)
        relay = Mock(); relay.arguments.side_effect = lambda argv: argv
        def prepare(*args):
            now[0] += prepare_seconds
            return relay
        if prepare_seconds: data['relay'] = {'host': 'synthetic', 'port': 22, 'connect_timeout': 1}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'request.json'; path.write_text(json.dumps(data))
            with patch.object(guard, 'os', fake_os), patch.object(guard, 'signal', fake_signal), \
                    patch.object(guard.select, 'select', return_value=([], [], [])), \
                    patch.object(guard, 'SharedBudget', return_value=pool), \
                    patch.object(guard.time, 'monotonic', side_effect=lambda: now[0]), \
                    patch.object(guard.time, 'sleep', side_effect=sleep), \
                    patch.object(guard.subprocess, 'Popen', side_effect=launch) as native, \
                    patch('swassh.infrastructure.socket_relay.GuardianRelay', side_effect=prepare):
                value = guard.main(path)
            receipt = json.loads((path.parent/'admission.json').read_text())
        lease.close.assert_called_once(); pool.close.assert_called_once()
        return value, receipt, events, native

    def test_admission_publishes_only_actual_queue_wait_before_native_launch(self):
        value, receipt, events, native = self.run_guardian([False, False, True])
        self.assertEqual(value, 0); native.assert_called_once()
        self.assertEqual(receipt['state'], 'admitted')
        self.assertAlmostEqual(receipt['seconds'], .1)
        self.assertEqual(events, [receipt])
        value, receipt, _, _ = self.run_guardian([True])
        self.assertEqual(receipt['seconds'], 0.)

    def test_expired_queue_never_starts_target_and_releases_lease(self):
        value, receipt, events, native = self.run_guardian([False]*30)
        self.assertEqual(value, 125); native.assert_not_called(); self.assertEqual(events, [])
        self.assertEqual(receipt['schema_version'], 1)
        self.assertEqual(receipt['state'], 'expired'); self.assertEqual(receipt['seconds'], .3)
        self.assertAlmostEqual(receipt['completed_at'], 100.3)

    def test_invalid_queue_limit_is_rejected_before_admission(self):
        for value in (True, 0, -1, '1', float('inf'), float('nan'), 10**1000):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'admission limit'):
                self.run_guardian([True], limit=value)

    def test_local_relay_preparation_must_finish_before_admission_receipt(self):
        value, receipt, events, native = self.run_guardian([True], prepare_seconds=.1)
        self.assertEqual(value, 0); native.assert_called_once(); self.assertEqual(events, [receipt])
        self.assertAlmostEqual(receipt['completed_at'], 100.1)
        value, receipt, _, native = self.run_guardian([True], prepare_seconds=.4)
        self.assertEqual(value, 125); native.assert_not_called(); self.assertEqual(receipt['state'], 'expired')

    def test_no_relay_still_retains_native_lifetime_scope(self):
        with guard.native_relay(None, .3):
            self.assertIsNone(guard._RELAY.get())
            self.assertEqual(guard._NATIVE_LIFETIME.get(), .3)
            with guard.native_relay(None, .1):
                self.assertIsNone(guard._RELAY.get())
                self.assertEqual(guard._NATIVE_LIFETIME.get(), .1)
            self.assertEqual(guard._NATIVE_LIFETIME.get(), .3)
        self.assertIsNone(guard._RELAY.get())
        self.assertIsNone(guard._NATIVE_LIFETIME.get())
