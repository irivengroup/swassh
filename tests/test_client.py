"""Public SDK contracts, bounded streams and cancellation-owned resources."""
import asyncio
from datetime import UTC, datetime
import tempfile
from pathlib import Path
import unittest

from swassh import (AsyncClient, Client, CommandError, ExecutionError, Host, Options,
                    OutputDecodeError, Result, Status, Swarm)
from swassh.domain.report import ExecutionReport


class ControlledTransport:
    """Observable test adapter; all cleanup assertions concern real tasks."""
    def __init__(self, options, *, failure=False, blocked=False):
        self.options, self.failure, self.blocked = options, failure, blocked
        self.active = self.peak = self.sent = self.closed = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.closing = asyncio.Event()
        self.close_release = None

    async def execute(self, host, command):
        self.active += 1
        self.sent += 1
        self.peak = max(self.active, self.peak)
        self.entered.set()
        try:
            if self.blocked:
                await self.release.wait()
            await asyncio.sleep(0)
            return Result(host, Status.FAILED if self.failure else Status.SUCCESS,
                          stdout='{"value": 7}', exit_code=1 if self.failure else 0)
        finally:
            self.active -= 1

    async def aclose(self):
        self.closing.set()
        if self.close_release is not None:
            await self.close_release.wait()
        self.closed += 1


class Factory:
    def __init__(self, **settings):
        self.settings, self.created = settings, []

    def __call__(self, options):
        transport = ControlledTransport(options, **self.settings)
        self.created.append(transport)
        return transport


class ResultConvenienceTests(unittest.TestCase):
    def test_success_and_errors_preserve_outcomes_without_output_in_message(self):
        result = Result(Host('host'), Status.SUCCESS, stdout='{"value":7}')
        self.assertTrue(result.ok)
        self.assertIs(result.raise_for_status(), result)
        self.assertEqual(result.json(), {'value': 7})
        failed = Result(Host('host'), Status.AUTH_FAILED, stdout='private-output')
        with self.assertRaises(CommandError) as captured:
            failed.json()
        self.assertIs(captured.exception.result, failed)
        self.assertNotIn('private-output', str(captured.exception))
        now = datetime.now(UTC)
        report = ExecutionReport('private-command', (result, failed), now, now)
        with self.assertRaises(ExecutionError) as captured:
            report.raise_for_status()
        self.assertIs(captured.exception.report, report)
        self.assertNotIn('private-command', str(captured.exception))

    def test_strict_json_rejects_invalid_duplicate_nonfinite_and_truncated_output(self):
        for output in ('not-json', '{"a":1,"a":2}', 'NaN', 'Infinity', '['*2000):
            result = Result(Host('host'), Status.SUCCESS, stdout=output)
            with self.subTest(output=output[:12]), self.assertRaises(OutputDecodeError) as caught:
                result.json()
            self.assertIs(caught.exception.result, result)
        with self.assertRaises(OutputDecodeError):
            Result(Host('host'), Status.SUCCESS, stdout='{}', stdout_truncated=True).json()


class SyncClientTests(unittest.TestCase):
    def test_blocking_interface_still_executes_100_hosts_concurrently(self):
        """Blocking the caller must never serialize the remote fleet."""
        factory = Factory()
        report = Client([f'h{i}' for i in range(100)], concurrency=8,
                        transport_factory=factory).run('x')
        self.assertEqual(len(report.results), 100)
        self.assertTrue(report.ok)
        self.assertGreater(factory.created[0].peak, 1)
        self.assertLessEqual(factory.created[0].peak, 8)
        self.assertEqual(factory.created[0].closed, 1)

    def test_quick_parallel_usage_and_per_call_options_do_not_mutate_client(self):
        factory = Factory()
        client = Client(['a', 'b'], concurrency=2, canary=2, transport_factory=factory)
        report = client.run('uname -r', check=True, command_timeout=9)
        self.assertEqual(len(report.results), 2)
        self.assertIs(report.raise_for_status(), report)
        self.assertEqual(factory.created[0].peak, 2)
        self.assertEqual(factory.created[0].closed, 1)
        self.assertEqual(factory.created[0].options.command_timeout, 9)
        self.assertEqual(client.options.command_timeout, Options().command_timeout)
        self.assertEqual(client.on('c').hosts, (Host('c'),))
        self.assertEqual(client.with_options(concurrency=1).options.concurrency, 1)
        self.assertEqual(client.options.concurrency, 2)

    def test_sync_stream_break_cleans_resources_and_cannot_reopen(self):
        factory = Factory()
        stream = Client(['a', 'b', 'c'], transport_factory=factory).stream('x')
        self.assertEqual(factory.created, [])
        with self.assertRaises(RuntimeError):
            next(stream)
        with stream as results:
            self.assertTrue(next(results).ok)
        self.assertEqual(factory.created[0].active, 0)
        self.assertEqual(factory.created[0].closed, 1)
        with self.assertRaises(StopIteration):
            next(stream)
        with self.assertRaises(RuntimeError):
            with stream:
                self.fail('stream reopened')

    def test_sync_stream_exhaustion_and_checked_failure(self):
        factory = Factory()
        with Client(['a', 'b'], transport_factory=factory).stream('x') as stream:
            self.assertEqual(len(list(stream)), 2)
        with self.assertRaises(CommandError):
            with Client('a', transport_factory=Factory(failure=True)).stream('x', check=True) as stream:
                next(stream)

    def test_inventory_and_spooled_export_use_existing_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory)/'hosts.txt'
            inventory.write_text('a\nb\n', encoding='utf-8')
            client = Client.from_inventory(inventory, transport_factory=Factory())
            target = Path(directory)/'report.json'
            summary = client.run_to_file('x', target)
            self.assertTrue(summary.ok)
            self.assertEqual(summary.total, 2)
            self.assertTrue(target.is_file())

    def test_invalid_configuration_and_conflicting_injection(self):
        for settings in ({'options': {}}, {'transport_factory': 1}, {'unknown': 1}, {'concurrency': 0}):
            with self.subTest(settings=settings), self.assertRaises((ValueError, TypeError)):
                Client('host', **settings)
        with self.assertRaises(ValueError):
            Swarm(transport=object(), transport_factory=Factory())
        with self.assertRaises(TypeError):
            Swarm(transport_factory=1)


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_host_does_not_block_other_hosts_or_application_loop(self):
        """After canary, a waiting host must not stall the other 98 targets."""
        slow_entered, last_entered, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        class SlowHostTransport(ControlledTransport):
            async def execute(self, host, command):
                if host.hostname == 'h1':
                    slow_entered.set()
                    await release.wait()
                if host.hostname == 'h99':
                    last_entered.set()
                return await super().execute(host, command)
        transport = SlowHostTransport(Options())
        client = AsyncClient([f'h{i}' for i in range(100)], concurrency=8,
                             transport_factory=lambda options: transport)
        task = asyncio.create_task(client.run('x'))
        try:
            async with asyncio.timeout(10):
                await slow_entered.wait()
                await last_entered.wait()
                # This application coroutine and the last host both advanced
                # before the first post-canary host was allowed to finish.
                self.assertFalse(task.done())
                self.assertEqual(transport.closed, 0)
                release.set()
                report = await task
            self.assertTrue(report.ok)
            self.assertEqual(len(report.results), 100)
            self.assertEqual(transport.closed, 1)
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_sync_calls_rejected_inside_loop_before_allocating_coroutines(self):
        client = Client('host', transport_factory=Factory())
        for operation in (lambda: client.run('x'), lambda: client.run_to_file('x', 'report.json'),
                          lambda: client.stream('x')):
            with self.assertRaisesRegex(RuntimeError, 'AsyncClient'):
                operation()

    async def test_check_returns_full_report_and_preserves_canary(self):
        factory = Factory(failure=True)
        client = AsyncClient(['a', 'b'], transport_factory=factory)
        with self.assertRaises(ExecutionError) as caught:
            await client.run('x', check=True)
        self.assertEqual([r.status for r in caught.exception.report.results], [Status.FAILED, Status.SKIPPED])
        self.assertEqual(factory.created[0].sent, 1)
        self.assertEqual(factory.created[0].closed, 1)
        with self.assertRaises(TypeError):
            await client.run('x', check='false')

    async def test_concurrent_runs_get_independent_transports_and_close_each(self):
        factory = Factory()
        client = AsyncClient(['a', 'b'], transport_factory=factory)
        reports = await asyncio.gather(client.run('one'), client.run('two'))
        self.assertTrue(all(report.ok for report in reports))
        self.assertEqual(len(factory.created), 2)
        self.assertTrue(all(t.closed == 1 for t in factory.created))

    async def test_stream_backpressure_and_early_break(self):
        factory = Factory()
        client = AsyncClient([f'h{i}' for i in range(1000)], concurrency=2, transport_factory=factory)
        stream = client.stream('x')
        with self.assertRaises(RuntimeError):
            await anext(stream)
        async with stream:
            self.assertTrue((await anext(stream)).ok)
            # Give workers scheduling opportunities without relying on timing.
            for _ in range(30):
                await asyncio.sleep(0)
            transport = factory.created[0]
            self.assertLessEqual(transport.sent, 8)
            self.assertEqual(transport.peak, 2)
        self.assertEqual(transport.closed, 1)
        self.assertEqual(transport.active, 0)
        with self.assertRaises(StopAsyncIteration):
            await anext(stream)
        with self.assertRaises(RuntimeError):
            async with stream:
                self.fail('stream reopened')

    async def test_producer_failure_is_not_silently_converted_to_eof(self):
        def factory(options):
            raise ValueError('factory failed')
        with self.assertRaisesRegex(ValueError, 'factory failed'):
            async with AsyncClient('host', transport_factory=factory).stream('x') as stream:
                await anext(stream)

    async def test_consumer_cancellation_and_repeated_cancel_wait_for_cleanup(self):
        factory = Factory(blocked=True)
        client = AsyncClient('host', transport_factory=factory)
        async def consume():
            async with client.stream('x') as stream:
                await anext(stream)
        task = asyncio.create_task(consume())
        while not factory.created:
            await asyncio.sleep(0)
        transport = factory.created[0]
        await transport.entered.wait()
        transport.close_release = asyncio.Event()
        task.cancel()
        await transport.closing.wait()
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        transport.close_release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(transport.active, 0)
        self.assertEqual(transport.closed, 1)

    async def test_simultaneous_stream_readers_rejected(self):
        factory = Factory(blocked=True)
        async with AsyncClient('host', transport_factory=factory).stream('x') as stream:
            first = asyncio.create_task(anext(stream))
            while not factory.created:
                await asyncio.sleep(0)
            await factory.created[0].entered.wait()
            with self.assertRaises(RuntimeError):
                await anext(stream)
            factory.created[0].release.set()
            self.assertTrue((await first).ok)

    async def test_early_stream_exit_never_hides_transport_cleanup_failure(self):
        factory = Factory(blocked=True)
        async def broken_close():
            raise RuntimeError('transport cleanup failed')
        with self.assertRaisesRegex(RuntimeError, 'transport cleanup failed'):
            async with AsyncClient('host', transport_factory=factory).stream('x'):
                while not factory.created:
                    await asyncio.sleep(0)
                await factory.created[0].entered.wait()
                factory.created[0].aclose = broken_close

    async def test_single_host_session_reuses_existing_contract(self):
        session = AsyncClient('host', username='operator').session(lifetime=5)
        self.assertEqual(session.host, Host('host', username='operator'))
        self.assertEqual(session.lifetime, 5)
        for client in (AsyncClient(['a', 'b']), AsyncClient('a', transport_factory=Factory())):
            with self.assertRaises(ValueError):
                client.session()

    async def test_sdk_operations_do_not_borrow_an_enclosing_invocation(self):
        """A client call is independent, even inside an existing Session scope."""
        from swassh.infrastructure.bastion import _HELD
        observed = []
        def factory(options):
            observed.append(_HELD.get())
            return ControlledTransport(options)
        token = _HELD.set(('outer-budget', 'outer-lease'))
        try:
            client = AsyncClient('host', transport_factory=factory)
            await client.run('x')
            async with client.stream('x') as stream:
                await anext(stream)
            with tempfile.TemporaryDirectory() as directory:
                await client.run_to_file('x', Path(directory)/'out.json')
            self.assertEqual(observed, [None, None, None])
            self.assertEqual(_HELD.get(), ('outer-budget', 'outer-lease'))
        finally:
            _HELD.reset(token)
