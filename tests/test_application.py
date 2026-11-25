"""Fleet orchestration, synchronous entry points and real adapter integration."""
import asyncio
import csv
import gzip
import itertools
import json
import os
import tempfile
import time
import tracemalloc
import unittest
from contextlib import aclosing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Options, Report, Result, Status, Swarm, execute
from swassh.application.contracts import ResourcePlan, RunSummary
from swassh.infrastructure.audit import AuditHandler, AuditTrail, _WriterLock
from swassh.application.pacing import ConnectionPacer


class FleetTransport:
    def __init__(self, delay=0, unique=False):
        self.active = self.peak = 0
        self.delay, self.unique = delay, unique

    async def execute(self, host, command):
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.delay)
            return Result(
                host,
                Status.SUCCESS,
                stdout=host.hostname if self.unique else "Linux",
                exit_code=0,
            )
        finally:
            self.active -= 1


class SyncFacadeTests(unittest.TestCase):
    """The synchronous boundary owns one loop, without any filesystem or SSH."""

    def test_execute_returns_the_completed_report_and_propagates_service_failure(self):
        from swassh.interfaces import api
        now = datetime(2030, 1, 1, tzinfo=UTC)
        expected = Report('read', (Result(Host('node'), Status.SUCCESS, exit_code=0),), now, now)
        options, hosts, calls = Options(), ('node',), []
        class Service:
            failure = None

            def __init__(self, received_options):
                calls.append(('construct', received_options))

            async def run(self, received_hosts, command):
                await asyncio.sleep(0)
                calls.append(('completed', received_hosts, command))
                if self.failure is not None:
                    raise self.failure
                return expected
        with patch.object(api, 'Swarm', Service):
            self.assertIs(api.execute(hosts, 'read', options), expected)
            failure = ValueError('synthetic execution failure')
            Service.failure = failure
            with self.assertRaises(ValueError) as captured:
                api.execute(hosts, 'read', options)
        self.assertIs(captured.exception, failure)
        self.assertEqual(calls, [('construct', options), ('completed', hosts, 'read'),
                                 ('construct', options), ('completed', hosts, 'read')])

    def test_execute_to_file_preserves_summary_and_explicit_output_contract(self):
        from swassh.interfaces import api
        now = datetime(2030, 1, 1, tzinfo=UTC)
        expected = RunSummary(1, {'success': 1}, now, now, ResourcePlan(1, 1, 1024, 1024, 1.0))
        options, hosts, path, spool = Options(), ('node',), Path('memory-report.json'), Path('memory-spool')
        calls = []
        class Service:
            def __init__(self, received_options):
                calls.append(received_options)

            async def run_to_file(self, received_hosts, command, received_path, format, *, spool_dir):
                await asyncio.sleep(0)
                calls.append((received_hosts, command, received_path, format, spool_dir))
                return expected
        with patch.object(api, 'Swarm', Service):
            actual = api.execute_to_file(hosts, 'read', path, options, 'csv', spool_dir=spool)
        self.assertIs(actual, expected)
        self.assertTrue(actual.ok)
        self.assertEqual(calls, [options, (hosts, 'read', path, 'csv', spool)])


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_both_sync_facades_refuse_an_existing_loop_before_construction(self):
        from swassh.interfaces import api
        class UnreadTargets:
            def __iter__(self):
                raise AssertionError('targets must not be consumed')
        with patch.object(api, 'Swarm', side_effect=AssertionError('must not construct')) as constructor:
            with self.assertRaisesRegex(RuntimeError, 'await Swarm.run\\(\\)'):
                api.execute(UnreadTargets(), 'read')
            with self.assertRaisesRegex(RuntimeError, 'await Swarm.run_to_file\\(\\)'):
                api.execute_to_file(UnreadTargets(), 'read', 'memory-report.json')
        constructor.assert_not_called()

    async def test_bounded_workers(self):
        transport = FleetTransport()
        report = await Swarm(Options(concurrency=7), transport=transport).run(
            [f"h-{i}" for i in range(1000)], "x"
        )
        self.assertEqual(transport.peak, 7)
        self.assertEqual(report.counts["success"], 1000)
        self.assertEqual(report.results[0].host.hostname, "h-0")

    async def test_cancellation(self):
        transport = FleetTransport(delay=10)
        task = asyncio.create_task(Swarm(transport=transport).run(["a", "b"], "x"))
        await asyncio.sleep(0.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(transport.active, 0)
        self.assertFalse(
            [t for t in asyncio.all_tasks() if t.get_name().startswith("swassh-worker")]
        )

    async def test_iterator_close(self):
        transport = FleetTransport()
        async with aclosing(
            Swarm(transport=transport).iter_results(["a", "b", "c"], "x")
        ) as results:
            await anext(results)
        self.assertEqual(transport.active, 0)

    async def test_effective_user_dedup(self):
        report = await Swarm(Options(username="admin"), transport=FleetTransport()).run(
            ["a", "admin@a", "other@a"], "x"
        )
        self.assertEqual(len(report.results), 2)

    async def test_bad_transport(self):
        class Bad:
            async def execute(self, host, command):
                raise ValueError("SECRET")

        report = await Swarm(transport=Bad()).run(["a"], "x")
        self.assertEqual(report.results[0].status, Status.ERROR)
        self.assertNotIn("SECRET", report.to_json())

    async def test_invalid_command_and_sync_in_loop(self):
        for value in ("", " ", "x\x00", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                await anext(
                    Swarm(transport=FleetTransport()).iter_results(["a"], value)
                )
        with self.assertRaises(RuntimeError):
            execute(["a"], "x")

    async def test_memory_report_guard(self):
        class Large:
            async def execute(self, host, command):
                return Result(host, Status.SUCCESS, stdout="x" * 100000)

        with self.assertRaisesRegex(ValueError, "run_to_file"):
            await Swarm(
                Options(concurrency=1, memory_budget_mib=16), transport=Large()
            ).run([f"h-{i}" for i in range(20)], "x")

    async def test_process_writer_and_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            for format in ("json", "text", "csv"):
                path = Path(directory) / format
                summary = await Swarm(transport=FleetTransport()).run_to_file(
                    ["a", "b"], "x", path, format
                )
                self.assertTrue(summary.ok)
                self.assertNotEqual(summary.report_worker_pid, os.getpid())
                self.assertEqual(summary.total, 2)
                self.assertTrue(path.stat().st_size)
                if format == "json":
                    data = json.loads(path.read_text())
                    self.assertEqual(len(data["results"]), 2)
                    self.assertEqual(data["run_id"], summary.run_id)
                    self.assertEqual(len(data["response_groups"]), 1)
            self.assertEqual(len(list(Path(directory).iterdir())), 3)

    async def test_spool_budget_preserves_old_report(self):
        class Large:
            async def execute(self, host, command):
                return Result(host, Status.SUCCESS, stdout=host.hostname + "x" * 100000)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report"
            path.write_text("previous")
            with self.assertRaisesRegex(ValueError, "spool budget"):
                await Swarm(Options(max_report_mib=1), transport=Large()).run_to_file(
                    [f"h-{i}" for i in range(30)], "x", path
                )
            self.assertEqual(path.read_text(), "previous")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    async def test_cancel_disk_run(self):
        with tempfile.TemporaryDirectory() as directory:
            task = asyncio.create_task(
                Swarm(transport=FleetTransport(delay=10)).run_to_file(
                    ["a"], "x", Path(directory) / "report"
                )
            )
            await asyncio.sleep(0.3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(list(Path(directory).iterdir()))

    async def test_pacer(self):
        pacer = ConnectionPacer(100)
        moments = []

        async def call():
            await pacer.acquire()
            moments.append(time.perf_counter())

        await asyncio.gather(*(call() for _ in range(8)))
        self.assertTrue(all(b - a >= 0.008 for a, b in itertools.pairwise(moments)))

    async def test_pacer_rechecks_deadline_after_early_wakeup(self):
        """A coarse event-loop timer must not permit an early admission."""
        pacer = ConnectionPacer(100)
        with patch('swassh.application.pacing.time') as clock:
            clock.perf_counter.side_effect = [0.0, 0.0, 0.0, 0.0, 0.004, 0.01, 0.01]
            with patch('swassh.application.pacing.asyncio.sleep') as sleep:
                await pacer.acquire()
                await pacer.acquire()
            self.assertEqual(sleep.await_count, 2)
            self.assertAlmostEqual(sleep.await_args_list[0].args[0], 0.01)
            self.assertAlmostEqual(sleep.await_args_list[1].args[0], 0.006)
            self.assertAlmostEqual(pacer._next, 0.02)

    async def test_pacer_never_catches_up_after_descheduling_during_handoff(self):
        """Model a host pause at the release boundary without relaxing 8 ms."""
        pacer = ConnectionPacer(100)
        now = [0.0]
        moments = []
        original_release = pacer._lock.release
        original_sleep = asyncio.sleep
        paused = [False]
        def release():
            if not paused[0]:
                paused[0] = True
                now[0] += 0.020
            original_release()
        async def sleep(delay):
            now[0] += delay
            await original_sleep(0)
        async def call():
            await pacer.acquire()
            moments.append(now[0])
        with patch('swassh.application.pacing.time') as clock:
            clock.perf_counter.side_effect = lambda: now[0]
            with patch.object(pacer._lock, 'release', release), patch('swassh.application.pacing.asyncio.sleep', sleep):
                await asyncio.gather(*(call() for _ in range(8)))
                await original_sleep(0)
        self.assertEqual(len(moments), 8)
        self.assertTrue(paused[0])
        self.assertTrue(all(b-a >= 0.008 for a,b in itertools.pairwise(moments)))
        self.assertFalse(pacer._lock.locked())

    async def test_cancelled_pacer_wait_does_not_keep_admission_locked(self):
        pacer = ConnectionPacer(100)
        pacer._next = time.perf_counter()+10
        task = asyncio.create_task(pacer.acquire())
        await asyncio.sleep(0)
        self.assertTrue(pacer._lock.locked())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(pacer._lock.locked())

    async def test_pacer_releases_ownership_if_handoff_cannot_be_queued(self):
        pacer = ConnectionPacer(100)
        loop = asyncio.get_running_loop()
        with patch.object(loop, 'call_soon', side_effect=RuntimeError('synthetic queue failure')):
            with self.assertRaisesRegex(RuntimeError, 'synthetic queue failure'):
                await pacer.acquire()
        self.assertFalse(pacer._lock.locked())

    async def test_report_batches_use_only_spare_memory_and_keep_every_result(self):
        """Avoid one-record RPCs when unused memory can safely hold a batch."""
        from swassh.application.swarm import Swarm as ApplicationSwarm
        mib = 1024 * 1024
        class MemoryAudit:
            def __init__(inner):
                inner.pending, inner.records = [], []

            async def __aenter__(inner):
                return inner

            async def emit(inner, event, values):
                inner.pending.append((event, dict(values)))

            async def flush(inner):
                inner.records.extend(inner.pending)
                inner.pending.clear()

            async def __aexit__(inner, *exc):
                await inner.flush()

        class MemoryWriter:
            worker_pid = None

            def __init__(inner, capability=None):
                if capability is not None:
                    inner.supports_spare_memory_batches = capability
                inner.batches, inner.rows = [], []
                inner.destination = inner.exported = None
                inner.closed = False

            async def __aenter__(inner):
                return inner

            async def prepare(inner, destination):
                inner.destination = destination

            async def append(inner, rows):
                if inner.destination is None or inner.closed:
                    raise RuntimeError('unprepared or closed memory writer')
                inner.batches.append(len(rows))
                inner.rows.extend(rows)

            async def summary(inner):
                return {status.value: sum(row.status == status for row in inner.rows) for status in Status}

            async def export(inner, destination, format, command, summary):
                inner.exported = destination, format, command, summary.total

            async def __aexit__(inner, *exc):
                inner.closed = True

        # These geometries exercise no spare memory, native-sized reservations,
        # ordinary multi-worker reservations and the retained 32-record ceiling.
        for label, workers, worker_mib, budget_mib, has_spare, advertised in (
                ('tight', 1, 73, 73, False, True),
                ('native-spare', 1, 73, 128, True, True),
                ('ordinary-tight', 4, 9, 36, False, True),
                ('ample-spare', 1, 73, 1024, True, True),
                ('many-workers', 40, 9, 512, False, True),
                ('legacy-unadvertised', 1, 73, 128, False, None),
                ('legacy-declined', 1, 73, 128, False, False),
                ('truthy-is-not-opt-in', 1, 73, 128, False, 1)):
            with self.subTest(geometry=label):
                options = Options(concurrency=workers, memory_budget_mib=budget_mib, canary=1)
                plan = ResourcePlan(workers, workers, budget_mib * mib, worker_mib * mib, 20.0)
                writer, audit, transport = MemoryWriter(advertised), MemoryAudit(), FleetTransport(unique=True)
                service = ApplicationSwarm(options, transport_factory=lambda _: transport,
                    audit_factory=lambda *args: audit, planner=lambda _: plan,
                    reporter_factory=lambda *args: writer, report_factory=Report)
                summary = await service.run_to_file((f'memory-{i}' for i in range(96)),
                    'read', Path('memory-report.csv'), 'csv')
                self.assertEqual(summary.total, 96)
                self.assertTrue(summary.ok)
                self.assertEqual(len(writer.rows), 96)
                self.assertEqual({row.host.hostname for row in writer.rows}, {f'memory-{i}' for i in range(96)})
                self.assertTrue(all(row.stdout == row.host.hostname for row in writer.rows))
                self.assertLessEqual(transport.peak, workers)
                self.assertTrue(writer.closed)
                self.assertEqual(writer.exported, (Path('memory-report.csv'), 'csv', 'read', 96))
                self.assertEqual(summary.plan, plan)
                self.assertFalse(audit.pending)
                self.assertTrue(all(1 <= size <= 32 for size in writer.batches))
                peak_batch = max(writer.batches)
                # Additional retained records consume spare admitted memory;
                # all native worker reservations remain owned in full.
                self.assertLessEqual(max(0, peak_batch - workers) * 9 * mib,
                    plan.memory_budget_bytes - workers * plan.estimated_worker_bytes)
                if has_spare:
                    self.assertGreater(peak_batch, workers)
                elif label != 'many-workers':
                    self.assertLessEqual(peak_batch, workers)

    async def test_50000_fleet(self):
        self._asyncioRunner.get_loop().set_debug(False)
        transport = FleetTransport(unique=True)
        tracemalloc.start()
        started = time.perf_counter()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "fleet.csv"
                summary = await Swarm(
                    Options(concurrency=10000), transport=transport
                ).run_to_file((f"host-{i}" for i in range(50000)), "x", path, "csv")
                _, peak = tracemalloc.get_traced_memory()
                self.assertEqual(summary.total, 50000)
                self.assertTrue(summary.ok)
                self.assertLessEqual(transport.peak, summary.plan.workers)
                self.assertLess(peak, 96 * 1024 * 1024)
                with path.open() as stream:
                    # Empty presentation separators are not CSV records. Preserve
                    # the exact fleet-size assertion independently of layout.
                    self.assertEqual(sum(1 for _ in csv.DictReader(stream)), 50000)
                with path.open() as stream:
                    self.assertEqual(sum(not line.strip() for line in stream), 50000)
                metrics = {
                    "hosts": 50000,
                    "peak_workers": transport.peak,
                    "peak_parent_python_bytes": peak,
                    "seconds": time.perf_counter() - started,
                    "report_worker_pid": summary.report_worker_pid,
                    "parent_pid": os.getpid(),
                }
                print("MASSIVE_BENCHMARK=" + json.dumps(metrics))
        finally:
            tracemalloc.stop()


class AuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with patch("swassh.infrastructure.audit.LOG_MAX_BYTES", 2048):
                async with AuditTrail(str(path), "id") as trail:
                    for i in range(300):
                        await trail.emit("test", {"sequence": i, "text": "x" * 100})
            archives = list(Path(directory).glob("*.gz"))
            self.assertEqual(len(archives), 3)
            for archive in archives:
                with gzip.open(archive, "rt") as stream:
                    self.assertTrue(
                        all(json.loads(line)["run_id"] == "id" for line in stream)
                    )
            self.assertEqual(
                json.loads(path.read_text().splitlines()[-1])["sequence"], 299
            )
            handler = AuditHandler(path)
            self.assertEqual(handler.maxBytes, 100 * 1024 * 1024)
            self.assertEqual(handler.backupCount, 3)
            handler.close()

    async def test_audit_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit"
            report = await Swarm(
                Options(log_file=str(path)), transport=FleetTransport()
            ).run(["a", "b"], "COMMAND_SECRET")
            data = path.read_text()
            self.assertNotIn("COMMAND_SECRET", data)
            self.assertNotIn("Linux", data)
            records = [json.loads(line) for line in data.splitlines()]
            self.assertEqual(records[-1]["event"], "execution_completed")
            self.assertTrue(all(item["run_id"] == report.run_id for item in records))

    async def test_audit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit"
            with patch.object(AuditHandler, "shouldRollover", side_effect=OSError):
                with self.assertRaises(OSError):
                    async with AuditTrail(str(path), "id") as trail:
                        await trail.emit("test", {})
            lock = _WriterLock(path)
            with self.assertRaises(OSError):
                _WriterLock(path)
            lock.close()
