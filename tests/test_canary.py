"""Canary barriers: first N distinct targets, bounded work and explicit skips."""
import asyncio
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from swassh import FileSwarm, FileTransfer, Host, Options, Result, Status, Swarm, TransferDirection
from swassh.infrastructure.spool import ReportStore
from swassh.interfaces import cli


class BarrierTransport:
    def __init__(self, canaries, failures=(), failure_status=Status.FAILED):
        self.canaries = set(canaries)
        self.failures = set(failures)
        self.failure_status = failure_status
        self.calls, self.completed = [], set()
        self.active = self.peak = 0
        self.fleet_before_canary = False

    async def execute(self, host, command):
        name = host.hostname
        self.calls.append(name)
        if name not in self.canaries and not self.canaries <= self.completed:
            self.fleet_before_canary = True
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.02 if name in self.canaries else 0)
            self.completed.add(name)
            return Result(host, self.failure_status if name in self.failures else Status.SUCCESS, stdout='same')
        finally:
            self.active -= 1


class CanaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_first_host_is_a_barrier(self):
        transport = BarrierTransport(['a'])
        report = await Swarm(transport=transport).run(['a', 'b', 'c'], 'opaque command')
        self.assertFalse(transport.fleet_before_canary)
        self.assertEqual(transport.calls[0], 'a')
        self.assertTrue(report.ok)
        self.assertEqual(report.canary_count, 1)
        self.assertTrue(report.canary_passed)
        self.assertEqual([r.phase for r in report.results], ['canary', 'fleet', 'fleet'])
        self.assertIn('Canary: 1 hosts — passed', report.to_text())
        self.assertEqual(report.to_dict()['canary'], {'requested': 1, 'selected': 1, 'passed': True})
        self.assertEqual(len(report.response_groups()), 1)

    async def test_five_canaries_finish_before_fleet_and_stay_bounded(self):
        canaries = [f'h-{i}' for i in range(5)]
        transport = BarrierTransport(canaries)
        report = await Swarm(Options(canary=5, concurrency=2), transport=transport).run(
            [*canaries, *[f'h-{i}' for i in range(5, 20)]], 'x')
        self.assertFalse(transport.fleet_before_canary)
        self.assertLessEqual(transport.peak, 2)
        self.assertEqual(set(transport.calls[:5]), set(canaries))
        self.assertEqual(report.canary_count, 5)
        self.assertTrue(report.canary_passed)
        self.assertEqual(len(report.results), 20)

    async def test_any_canary_failure_blocks_every_remaining_target(self):
        for status in (Status.FAILED, Status.TIMEOUT, Status.AUTH_FAILED, Status.HOST_KEY_FAILED,
                       Status.UNREACHABLE, Status.INTERRUPTED, Status.ERROR):
            transport = BarrierTransport(['a', 'b'], failures=['b'], failure_status=status)
            report = await Swarm(Options(canary=2), transport=transport).run(['a', 'b', 'c', 'd'], 'x')
            with self.subTest(status=status):
                self.assertEqual(set(transport.calls), {'a', 'b'})
                self.assertFalse(report.ok)
                self.assertFalse(report.canary_passed)
                self.assertEqual(report.counts['skipped'], 2)
                for result in report.results[2:]:
                    self.assertEqual(result.status, Status.SKIPPED)
                    self.assertEqual(result.attempts, 0)
                    self.assertEqual(result.duration, 0)
                    self.assertIsNone(result.exit_code)
                    self.assertIsNone(result.transfer)
                self.assertIn('fleet blocked', report.to_text())

    async def test_selection_happens_after_normalization_and_user_dedup(self):
        transport = BarrierTransport(['node', 'other'])
        report = await Swarm(Options(canary=5, username='admin'), transport=transport).run(
            ['NODE', 'admin@node', 'other'], 'x')
        self.assertEqual(transport.calls, ['node', 'other'])
        self.assertEqual(report.canary_count, 2)
        self.assertTrue(all(result.phase == 'canary' for result in report.results))
        self.assertEqual(report.canary_requested, 5)

    async def test_disk_failure_reports_skips_and_audit_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = BarrierTransport(['h-0', 'h-1', 'h-2', 'h-3', 'h-4'], failures=['h-3'])
            service = Swarm(Options(canary=5, log_file=str(root / 'audit')), transport=transport)
            summary = await service.run_to_file((f'h-{i}' for i in range(501)), 'x', root / 'report.json')
            self.assertEqual(len(transport.calls), 5)
            self.assertEqual(summary.total, 501)
            self.assertEqual(summary.counts['skipped'], 496)
            self.assertFalse(summary.ok)
            self.assertFalse(summary.canary_passed)
            data = json.loads((root / 'report.json').read_text())
            self.assertEqual(data['canary'], {'requested': 5, 'selected': 5, 'passed': False})
            self.assertEqual(len(data['results']), 501)
            self.assertEqual(sum(item['phase'] == 'canary' for item in data['results']), 5)
            self.assertTrue(all(item['attempts'] == 0 for item in data['results'] if item['status'] == 'skipped'))
            records = [json.loads(line) for line in (root / 'audit').read_text().splitlines()]
            events = [record['event'] for record in records]
            self.assertIn('canary_started', events)
            self.assertIn('canary_failed', events)
            self.assertNotIn('fleet_started', events)
            self.assertEqual(events.count('host_result'), 501)
            complete = next(record for record in records if record['event'] == 'execution_completed')
            self.assertEqual((complete['executed'], complete['skipped']), (5, 496))
            # Disk adapters retain phase and zero-attempt skips in every full format.
            store = ReportStore(root, 1024**2)
            try:
                store.append([Result(Host('skipped'), Status.SKIPPED, attempts=0, phase='fleet')])
                store.export(root / 'report.csv', 'csv', 'x', summary)
                self.assertIn('skipped,fleet', (root / 'report.csv').read_text())
                store.export(root / 'report.txt', 'text', 'x', summary)
                self.assertIn('Canary: 5 hosts — failed; fleet blocked', (root / 'report.txt').read_text(encoding='utf-8'))
            finally:
                store.close()

    async def test_audit_pass_precedes_fleet_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit'
            transport = BarrierTransport(['a'])
            await Swarm(Options(log_file=str(path)), transport=transport).run(['a', 'b'], 'x')
            events = [json.loads(line)['event'] for line in path.read_text().splitlines()]
            self.assertLess(events.index('canary_passed'), events.index('fleet_started'))

    async def test_cancellation_in_canary_never_releases_fleet(self):
        ready = asyncio.Event()
        calls = []
        class Slow:
            async def execute(self, host, command):
                calls.append(host.hostname)
                ready.set()
                await asyncio.sleep(30)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit'
            task = asyncio.create_task(Swarm(Options(log_file=str(path)), transport=Slow()).run(['a', 'b'], 'x'))
            await asyncio.wait_for(ready.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(calls, ['a'])
            data = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertNotIn('fleet_started', [item['event'] for item in data])
            self.assertIsNone(data[-1]['canary_passed'])
            self.assertFalse([t for t in asyncio.all_tasks() if t.get_name().startswith('swassh-worker')])

    async def test_transfers_use_the_same_gate_for_push_and_pull(self):
        for direction in (TransferDirection.PUSH, TransferDirection.PULL):
            calls, closed = [], []
            class Client:
                async def __aenter__(self):
                    return self
                async def __aexit__(self, *args):
                    closed.append(True)
                async def transfer(self, host):
                    calls.append(host.hostname)
                    return Result(host, Status.FAILED)
            service = FileSwarm(Options(canary=1))
            service._factory = lambda *args: Client()
            report = await service.run(['a', 'b', 'c'], FileTransfer(direction, '/local', '/remote'))
            self.assertEqual(calls, ['a'])
            self.assertEqual(report.counts['skipped'], 2)
            self.assertEqual(closed, [True])


class CanaryOptionTests(unittest.TestCase):
    def test_cli_default_bare_and_explicit_canary(self):
        for action in ('run', 'push', 'pull'):
            for extra, expected in (([], 1), (['--canary'], 1), (['--canary', '5'], 5)):
                arguments = [action, 'true'] if action == 'run' else [action, '--source', '/source/', '--destination', '/destination/']
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(cli.main([*arguments, '-H', 'a', 'b', *extra, '--plan-only']), 0)
                plan = json.loads(output.getvalue())
                self.assertEqual(plan['canary_requested'], expected)
                self.assertEqual(plan['canary_count'], min(expected, 2))

    def test_invalid_sizes_and_result_attempts(self):
        for size in (0, -1, 100001, True, 1.5, '5'):
            with self.subTest(size=size), self.assertRaises(ValueError):
                Options(canary=size)
        for argv in (['--canary', '0'], ['--canary', '-1'], ['--canary', '100001']):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['run', 'true', '-H', 'a', *argv, '--plan-only']), 2)
        with self.assertRaises(ValueError):
            Result(Host('a'), Status.SUCCESS, attempts=0)
        with self.assertRaises(ValueError):
            Result(Host('a'), Status.SKIPPED)
