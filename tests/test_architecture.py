"""Dependency boundaries, independent core execution and canonical DDD layout."""

import ast
import asyncio
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swassh.application.contracts import ResourcePlan
from swassh.application.options import Options
from swassh.application.swarm import Swarm as ExecutionService
from swassh.domain.models import Result, Status
from swassh.domain.report import ExecutionReport

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src/swassh"
LAYERS = {
    "domain": {"domain"},
    "application": {"domain", "application"},
    "infrastructure": {"domain", "application", "infrastructure"},
    "interfaces": {"domain", "application", "infrastructure", "interfaces", "bootstrap"},
}


def dependency_graph():
    graph = {}
    for layer in LAYERS:
        for path in (PACKAGE / layer).rglob("*.py"):
            parts = path.relative_to(PACKAGE).with_suffix("").parts
            module = "swassh." + ".".join(parts)
            package = module.rpartition(".")[0]
            if parts[-1] == "__init__":
                module = package
            imports = set()
            for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
                if isinstance(node, ast.Import):
                    imports.update(item.name for item in node.names)
                elif isinstance(node, ast.ImportFrom):
                    name = node.module or ""
                    if node.level:
                        name = importlib.util.resolve_name("." * node.level + name, package)
                    imports.add(name)
            graph[module] = {name for name in imports if name.startswith("swassh")}
    return graph


class BoundaryTests(unittest.TestCase):
    def test_layer_dependencies(self):
        for module, imports in dependency_graph().items():
            layer = module.split(".")[1]
            for target in imports:
                with self.subTest(module=module, target=target):
                    if target == "swassh":
                        self.assertEqual(layer, "interfaces")
                    else:
                        self.assertIn(target.split(".")[1], LAYERS[layer])

    def test_no_module_cycles(self):
        graph = dependency_graph()
        visited, active = set(), set()

        def visit(module):
            self.assertNotIn(module, active, f"dependency cycle through {module}")
            if module in visited:
                return
            active.add(module)
            for target in graph.get(module, set()):
                visit(target)
            active.remove(module)
            visited.add(module)

        for module in graph:
            visit(module)

    def test_core_import_does_not_load_adapters(self):
        code = (
            "import sys,json; import swassh.domain.models; "
            "import swassh.application.swarm; "
            "print(json.dumps([m for m in sys.modules "
            "if m.startswith(('swassh.infrastructure','swassh.interfaces','swassh.bootstrap'))]))"
        )
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        process = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
        )
        self.assertEqual(json.loads(process.stdout), [])

    def test_only_ddd_modules_remain_at_the_package_root(self):
        self.assertEqual(
            {path.name for path in PACKAGE.glob("*.py")},
            {"__init__.py", "__main__.py", "bootstrap.py"},
        )
        self.assertEqual(
            {path.name for path in PACKAGE.iterdir() if path.is_dir() and path.name != "__pycache__"},
            set(LAYERS),
        )

    def test_public_exports_resolve_to_canonical_ddd_types(self):
        import swassh
        from swassh.domain.models import Host

        self.assertIs(swassh.Host, Host)
        self.assertIs(swassh.Options, Options)
        self.assertTrue(set(swassh.__all__).issubset(dir(swassh)))
        for name in swassh.__all__:
            if name != "__version__":
                value = getattr(swassh, name)
                self.assertIn(value.__module__.split(".")[1], LAYERS)
        with self.assertRaises(AttributeError):
            getattr(swassh, "absent_export")

    def test_plan_does_not_require_an_ssh_executable(self):
        from swassh import Swarm

        swarm = Swarm(Options(ssh_executable="absent-swassh-test-client"))
        self.assertGreaterEqual(swarm.plan().workers, 1)


    def test_runtime_invariants_do_not_disappear_under_optimized_python(self):
        """Runtime validation must survive python -O and -OO unchanged."""
        assertions = []
        for path in sorted(PACKAGE.rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            assertions.extend((path.relative_to(PACKAGE).as_posix(), node.lineno)
                              for node in ast.walk(tree) if isinstance(node, ast.Assert))
        self.assertEqual(assertions, [], 'Runtime invariants require explicit exceptions')


class RecordingAudit:
    def __init__(self, events, run_id):
        self.events, self.run_id = events, run_id

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def emit(self, event, fields):
        self.events.append((self.run_id, event, fields))


class RecordingWriter:
    worker_pid = 123

    def __init__(self):
        self.counts = {status.value: 0 for status in Status}
        self.batches = []
        self.closed = False
        self.exported = None
        self.fail = False
        self.cancel = False
        self.active = 0
        self.peak = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.closed = True

    async def append(self, results):
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            snapshot = tuple(results)
            await asyncio.sleep(0)
            if self.cancel:
                raise asyncio.CancelledError()
            if self.fail:
                raise OSError("writer unavailable")
            if snapshot != tuple(results):
                raise AssertionError("batch changed before append acknowledgement")
            self.batches.append(len(snapshot))
            for result in snapshot:
                self.counts[result.status.value] += 1
        finally:
            self.active -= 1

    async def summary(self):
        return dict(self.counts)

    async def export(self, path, format, command, summary):
        self.exported = path, format, command, summary


class CoreUseCaseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.events = []
        self.writer = RecordingWriter()
        self.factories = []

        class Transport:
            async def execute(self, host, command):
                await asyncio.sleep(0)
                return Result(host, Status.SUCCESS, stdout="ok")

        def transport_factory(options):
            instance = Transport()
            self.factories.append(instance)
            return instance

        self.service = ExecutionService(
            Options(concurrency=3),
            transport_factory=transport_factory,
            audit_factory=lambda path, run_id: RecordingAudit(self.events, run_id),
            planner=lambda options: ResourcePlan(3, 3, 128 * 1024 * 1024, 1024, 20),
            reporter_factory=lambda directory, max_bytes: self.writer,
            report_factory=ExecutionReport,
        )

    async def test_independent_core_run_and_fresh_transports(self):
        for _ in range(2):
            report = await self.service.run(["a", "b", "a"], "command")
            self.assertIs(type(report), ExecutionReport)
            self.assertTrue(report.ok)
            self.assertEqual(report.counts["success"], 2)
            self.assertEqual(len(report.groups()["success"]), 2)
        self.assertEqual(len(self.factories), 2)
        self.assertIsNot(self.factories[0], self.factories[1])

    async def test_disk_port_backpressure_and_summary(self):
        summary = await self.service.run_to_file(
            [f"host-{i}" for i in range(100)], "command", "unused.json"
        )
        self.assertTrue(summary.ok)
        self.assertEqual(summary.total, 100)
        self.assertEqual(summary.report_worker_pid, 123)
        self.assertEqual(sum(self.writer.batches), 100)
        self.assertLessEqual(max(self.writer.batches), 3)
        self.assertEqual(self.writer.peak, 1)
        self.assertTrue(self.writer.closed)
        self.assertEqual(self.writer.exported[:3], (Path("unused.json"), "json", "command"))
        self.assertTrue(all(run_id == summary.run_id for run_id, _, _ in self.events))

    async def test_malformed_transport_result_cannot_cross_target_or_pass_canary(self):
        from swassh.domain.models import Host
        for foreign in (False, True):
            calls = []
            class Transport:
                async def execute(self, host, command):
                    calls.append(host.target)
                    if foreign:
                        return Result(Host('foreign'), Status.SUCCESS, stdout='unrelated output', exit_code=0)
                    return None
            self.service._transport_factory = lambda options: Transport()
            with self.subTest(foreign=foreign):
                report = await self.service.run(['expected', 'later'], 'read-only')
                self.assertEqual(calls, ['expected:22'])
                self.assertEqual([result.host.target for result in report.results], ['expected:22', 'later:22'])
                self.assertEqual([result.status for result in report.results], [Status.ERROR, Status.SKIPPED])
                self.assertEqual(report.results[0].stdout, '')
                self.assertEqual(report.results[0].error, 'transport error: ValueError')
                self.assertEqual(report.results[1].attempts, 0)
                self.assertFalse(report.ok)

    async def test_result_adapter_that_changes_target_during_accounting_cannot_escape_revalidation(self):
        """Even a Result subclass may implement unstable attribute access."""
        from swassh.domain.models import Host
        reads, calls = [], []
        class UnstableResult(Result):
            def __getattribute__(self, name):
                if name == 'host':
                    reads.append(name)
                    # Result construction validates host once; the next read
                    # belongs to the first worker check, the third to revalidation.
                    return Host('expected' if len(reads) <= 2 else 'foreign')
                return super().__getattribute__(name)
        class Transport:
            async def execute(self, host, command):
                calls.append(host.target)
                result = UnstableResult(host, Status.SUCCESS, stdout='must not be attributed')
                self_outer.assertEqual(reads, ['host'])
                return result
        self_outer = self
        self.service._transport_factory = lambda options: Transport()
        report = await self.service.run(['expected', 'later'], 'read-only')
        self.assertEqual(reads, ['host', 'host', 'host'])
        self.assertEqual(calls, ['expected:22'])
        self.assertEqual([result.host.hostname for result in report.results], ['expected', 'later'])
        self.assertEqual([result.status for result in report.results], [Status.ERROR, Status.SKIPPED])
        self.assertEqual(report.results[0].error, 'transport error: ValueError')
        self.assertEqual(report.results[0].stdout, '')
        self.assertEqual(report.results[1].attempts, 0)
        self.assertFalse(report.ok)

    async def test_writer_error_closes_and_audits_without_export(self):
        self.writer.fail = True
        with self.assertRaises(OSError):
            await self.service.run_to_file(["a", "b"], "command", "unused.json")
        self.assertTrue(self.writer.closed)
        self.assertIsNone(self.writer.exported)
        self.assertEqual(self.events[-1][1], "report_failed")

    async def test_writer_cancellation_closes_and_audits(self):
        self.writer.cancel = True
        with self.assertRaises(asyncio.CancelledError):
            await self.service.run_to_file(["a"], "command", "unused.json")
        self.assertTrue(self.writer.closed)
        self.assertIsNone(self.writer.exported)
        self.assertEqual(self.events[-1][1], "report_cancelled")

    async def test_invalid_format_rejected_before_opening_writer(self):
        with self.assertRaises(ValueError):
            await self.service.run_to_file(["a"], "command", "unused", "xml")
        self.assertFalse(self.writer.closed)
        self.assertEqual(self.events, [])

    async def test_fatal_transport_failure_wakes_the_consumer_and_closes_transport(self):
        """A failed worker must not strand the bounded result consumer."""
        class TransportFailure(BaseException):
            pass
        closed = asyncio.Event()
        class Transport:
            async def execute(self, host, command):
                raise TransportFailure('synthetic worker failure')
            async def aclose(self):
                closed.set()
        self.service._transport_factory = lambda options: Transport()
        with self.assertRaisesRegex(RuntimeError, 'workers ended before all targets'):
            async with asyncio.timeout(2):
                await self.service.run(['one'], 'read-only')
        self.assertTrue(closed.is_set())
        self.assertFalse(any(task.get_name().startswith('swassh-worker-')
                             for task in asyncio.all_tasks() if not task.done()))


class TransferCoreUseCaseTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the real orchestration through in-memory external ports."""

    async def test_streaming_and_report_paths_keep_transfer_modes_and_close_clients(self):
        from swassh.application.transfers import TransferService
        from swassh.application.transfer_settings import TransferSettings
        from swassh.domain.models import Host, TransferReceipt
        from swassh.domain.transfers import FileTransfer, TransferDirection
        request = FileTransfer(TransferDirection.PUSH, 'local', '/remote')
        for mode in ({}, {'dry_run': True}, {'verify_sha256': True}):
            events, clients, reporter_calls = [], [], []
            writer = RecordingWriter()
            class Transport:
                closed = False
                async def __aenter__(self):
                    return self
                async def __aexit__(self, *args):
                    self.closed = True
                def metrics(self):
                    return {'test_transfer_metric': 7}
                async def transfer(self, host):
                    receipt = TransferReceipt('push', 'local', '/remote', 'sftp', 8,
                                              'rsync unavailable', 'private-stage')
                    return Result(host, Status.SUCCESS, transfer=receipt)
            def factory(*args):
                client = Transport()
                clients.append(client)
                return client
            def reporter(directory, max_bytes):
                reporter_calls.append((directory, max_bytes))
                return writer
            service = TransferService(
                Options(connect_rate=100000, jump_host=Host('jump')), TransferSettings(**mode),
                transport_factory=factory,
                audit_factory=lambda path, run_id: RecordingAudit(events, run_id),
                planner=lambda options: ResourcePlan(2, 2, 128 * 1024 * 1024, 1024, 20),
                reporter_factory=reporter, report_factory=ExecutionReport)
            with self.subTest(mode=mode):
                results = [result async for result in service.iter_results(['one', 'two'], request)]
                self.assertEqual([result.host.hostname for result in results], ['one', 'two'])
                self.assertTrue(all(result.ok and not result.changed for result in results))
                report = await service.run(['three'], request)
                suffix = ':preview' if mode.get('dry_run') else ':verify-sha256' if mode else ''
                self.assertEqual(report.command, request.descriptor + suffix)
                self.assertEqual(report.results[0].transfer.temporary_path, 'private-stage')
                summary = await service.run_to_file(['four'], request, 'report.json', spool_dir='private-spool')
                self.assertTrue(summary.ok)
                self.assertEqual(writer.exported[2], request.descriptor + suffix)
                self.assertEqual(reporter_calls[0][0], 'private-spool')
                self.assertEqual(len(clients), 3)
                self.assertTrue(all(client.closed for client in clients))


class ReporterLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_pool_initialization_failure_removes_spool_directory(self):
        from swassh.infrastructure.process_reporter import ProcessReportWriter

        with tempfile.TemporaryDirectory() as directory:
            writer = ProcessReportWriter(directory, 1024)
            with patch(
                "swassh.infrastructure.process_reporter.ProcessPoolExecutor",
                side_effect=OSError("pool unavailable"),
            ), self.assertRaises(OSError):
                await writer.__aenter__()
            self.assertEqual(list(Path(directory).iterdir()), [])

    async def test_calls_before_opening_writer_are_rejected(self):
        from swassh.infrastructure.process_reporter import ProcessReportWriter

        writer = ProcessReportWriter(".", 1024)
        with self.assertRaises(RuntimeError):
            await writer.summary()
