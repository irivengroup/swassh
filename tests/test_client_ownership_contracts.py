"""SDK stream ownership errors remain explicit across threads and event loops."""
import asyncio
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import AsyncClient,Client,DesiredState,Host,Result,Status
from swassh.interfaces.client import ResultStream, _SyncStream
from swassh.interfaces import client as client_module


class MemoryResults:
    def __init__(self):self.closed=0;self.ready=asyncio.Event();self.release=asyncio.Event()
    async def iter_results(self,hosts,command):
        self.ready.set()
        try:
            await self.release.wait()
            yield Result(hosts[0],Status.SUCCESS,stdout='synthetic')
        finally:self.closed+=1


class AsyncOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_while_closing_preserves_an_unobserved_producer_cleanup_error(self):
        started, cleanup_started, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        failure = OSError('synthetic adapter cleanup failure')
        class Service:
            async def iter_results(self, hosts, command):
                started.set()
                try:
                    await asyncio.Future()
                    yield Result(hosts[0], Status.SUCCESS)
                finally:
                    cleanup_started.set()
                    await release.wait()
                    raise failure
        stream = ResultStream(Service(), (Host('one'),), 'true', False)
        await stream.__aenter__()
        await started.wait()
        closing = asyncio.create_task(stream.__aexit__(None, None, None))
        try:
            async with asyncio.timeout(3):
                await cleanup_started.wait()
                closing.cancel()
                await asyncio.sleep(0)
                self.assertFalse(closing.done())
                release.set()
                with self.assertRaises(OSError) as observed:
                    await closing
            self.assertIs(observed.exception, failure)
            self.assertTrue(stream._closed)
            self.assertTrue(stream._producer.done())
        finally:
            release.set()
            await asyncio.gather(closing, return_exceptions=True)

    async def test_exit_cancellation_does_not_repeat_a_producer_error_already_observed_by_reader(self):
        from swassh.application.task_ownership import wait_owned
        failure = OSError('synthetic stream failure')
        class Service:
            async def iter_results(self, hosts, command):
                raise failure
                yield Result(hosts[0], Status.SUCCESS)
        stream = ResultStream(Service(), (Host('one'),), 'true', False)
        await stream.__aenter__()
        with self.assertRaises(OSError) as observed:
            await anext(stream)
        self.assertIs(observed.exception, failure)
        entered = asyncio.Event()
        async def scheduled_wait(task):
            # Hold only the injected wait boundary; the owned producer and
            # drain task still run normally and their real outcomes are read.
            entered.set()
            await asyncio.Future()
            return await wait_owned(task)
        with patch.object(client_module, 'wait_owned', scheduled_wait):
            closing = asyncio.create_task(stream.__aexit__(None, None, None))
            async with asyncio.timeout(3):
                await entered.wait()
                closing.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await closing
        self.assertTrue(stream._failure_observed)
        self.assertTrue(stream._closed)

    async def test_foreign_event_loop_cannot_read_or_close_owner_stream(self):
        service=MemoryResults();stream=ResultStream(service,(Host('one'),),'true',False)
        async with stream:
            await service.ready.wait()
            async def misuse():
                with self.assertRaisesRegex(RuntimeError,'this event loop'):await anext(stream)
                with self.assertRaisesRegex(RuntimeError,'owning event loop'):await stream.__aexit__(None,None,None)
            await asyncio.to_thread(lambda:asyncio.run(misuse()))
            self.assertFalse(stream._closed);service.release.set()
            self.assertEqual((await anext(stream)).stdout,'synthetic')
        await stream.__aexit__(None,None,None)
        self.assertEqual(service.closed,1)

    async def test_completed_external_cancellation_is_not_successful_end_of_stream(self):
        service=MemoryResults();stream=ResultStream(service,(Host('one'),),'true',False)
        await stream.__aenter__();await service.ready.wait()
        stream._producer.cancel();await asyncio.gather(stream._producer,return_exceptions=True)
        with self.assertRaises(asyncio.CancelledError):await stream.__aexit__(None,None,None)
        self.assertEqual(service.closed,1);self.assertTrue(stream._closed)
        await stream.__aexit__(None,None,None)

    async def test_checked_convergence_and_interaction_keep_typed_failure_and_native_scope(self):
        report=Mock();report.raise_for_status.return_value='checked'
        service=SimpleNamespace(run=AsyncMock(return_value=report))
        client=AsyncClient('one');action=DesiredState('state','check','apply')
        with patch('swassh.interfaces.convergence.ConvergentSwarm',return_value=service) as factory:
            self.assertIs(await client.converge(action),report)
            self.assertEqual(await client.converge(action,check=True),'checked')
            with self.assertRaises(TypeError):await client.converge(action,check=1)
            self.assertEqual(factory.call_count,2)
        handler=lambda host:None
        with patch('swassh.interfaces.client.Swarm',return_value=service):
            self.assertIs(await client.interact('true',handler),report)
            self.assertEqual(await client.interact('true',handler,check=True),'checked')
            stream=client.interact_stream('true',handler)
            self.assertIsInstance(stream,ResultStream)
            for kwargs in ({'check':1},{'stdin_file':'synthetic'},{'retries':1}):
                with self.assertRaises((TypeError,ValueError)):client.interact_stream('true',handler,**kwargs)
        with self.assertRaises(ValueError):AsyncClient('one',transport_factory=lambda options:None).interact_stream('true',handler)
        self.assertEqual(service.run.await_count,4)


class SyncOwnershipTests(unittest.TestCase):
    def test_failed_stream_entry_closes_its_private_runner(self):
        failure = OSError('synthetic stream entry failure')
        stream = SimpleNamespace(__aenter__=AsyncMock(side_effect=failure))
        runner = asyncio.Runner()
        with patch.object(client_module.asyncio, 'Runner', return_value=runner), \
                patch.object(runner, 'close', wraps=runner.close) as close:
            with self.assertRaises(OSError) as observed:
                _SyncStream(stream).__enter__()
            self.assertIs(observed.exception, failure)
            close.assert_called_once_with()

    def test_foreign_thread_cannot_use_or_close_stream_and_owner_remains_usable(self):
        class Service:
            async def iter_results(self,hosts,command):
                for host in hosts:yield Result(host,Status.SUCCESS)
        with patch('swassh.interfaces.client.Swarm',return_value=Service()):stream=Client('one').stream('true')
        with self.assertRaisesRegex(RuntimeError,'enter the result stream'):next(stream)
        with stream:
            failures=[]
            def misuse():
                for call in (lambda:next(stream),lambda:stream.__exit__(None,None,None)):
                    try:call()
                    except RuntimeError as error:failures.append(str(error))
            thread=threading.Thread(target=misuse);thread.start();thread.join(timeout=2)
            self.assertFalse(thread.is_alive());self.assertEqual(len(failures),2)
            self.assertTrue(all('entering thread' in value for value in failures))
            self.assertTrue(next(stream).ok)
            with self.assertRaises(StopIteration):next(stream)
        stream.__exit__(None,None,None)
        with self.assertRaises(StopIteration):next(stream)


if __name__=='__main__':unittest.main()
