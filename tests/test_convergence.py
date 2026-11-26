"""Desired-state contracts: no mutation on ambiguity, durable no-replay and canary."""
import asyncio
from contextlib import asynccontextmanager
from contextlib import aclosing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import ConvergentSwarm, DesiredState, Host, Options, Result, Status
from swassh.application.convergence import ConvergentTransport
from swassh.infrastructure.convergence import SQLiteConvergenceJournal, load_desired_state
from swassh.infrastructure.database.migration.convergence_v1 import ConvergenceSchema


class MemoryJournal:
    """In-memory unit-test boundary; its state survives adapter replacement."""
    def __init__(self):
        self.records, self.active, self.closed = {}, set(), False

    @asynccontextmanager
    async def scope(self, host, action):
        key = host.target, action.digest
        if key in self.active:
            raise ValueError('operation already active')
        self.active.add(key)
        self.records.setdefault(key, 'checking')
        journal = self
        class Lease:
            pending = journal.records[key] in ('applying', 'blocked')

            async def applying(self):
                journal.records[key] = 'applying'

            async def verified(self):
                journal.records[key] = 'verified'

            async def blocked(self):
                journal.records[key] = 'blocked'
        try:
            yield Lease()
        finally:
            self.active.remove(key)

    async def aclose(self):
        self.closed = True


class StatefulTransport:
    """A desired state with externally visible mutation counts and failures."""
    def __init__(self):
        self.desired, self.mutations, self.commands = False, 0, []
        self.failure, self.closed = None, False

    async def execute(self, host, command):
        self.commands.append(command)
        if self.failure is not None:
            return self.failure
        if command == 'change-state':
            self.mutations += 1
            self.desired = True
        code = 0 if self.desired else 1
        return Result(host, Status.SUCCESS if code == 0 else Status.FAILED, exit_code=code)

    async def aclose(self):
        self.closed = True


class DesiredStateUnitTests(unittest.TestCase):
    def test_identity_binds_every_command_without_exposing_it_in_repr(self):
        action = DesiredState('configuration', 'inspect-state', 'change-state')
        self.assertNotIn('inspect-state', repr(action))
        self.assertNotIn('change-state', repr(action))
        self.assertEqual(action.verification, 'inspect-state')
        self.assertEqual(DesiredState.from_dict(action.to_dict()), action)
        self.assertEqual(len(action.digest), 64)
        self.assertNotEqual(replace(action, apply='another-action').digest, action.digest)
        self.assertNotIn(action.apply, action.descriptor)

    def test_invalid_specifications_are_rejected_before_execution(self):
        for name in ('', '../state', 'bad\nname', 'a' * 65, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                DesiredState(name, 'check', 'apply')
        for command in ('', '  ', 'a\0b', 'x' * 16385, False):
            for field in ('check', 'apply', 'verify'):
                values = {'name': 'state', 'check': 'check', 'apply': 'apply', field: command}
                with self.subTest(field=field), self.assertRaises(ValueError):
                    DesiredState(**values)
        valid = DesiredState('state', 'check', 'apply').to_dict()
        for data in ([], {}, {**valid, 'schema_version': True}, {**valid, 'schema_version': 2},
                     {**valid, 'unknown': 'field'}):
            with self.assertRaises(ValueError):
                DesiredState.from_dict(data)


class ConvergenceUseCaseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.host = Host('node')
        self.action = DesiredState('state', 'inspect-state', 'change-state')
        self.native = StatefulTransport()
        self.journal = MemoryJournal()
        self.adapter = ConvergentTransport(self.native, self.action, self.journal)

    async def test_metrics_are_forwarded_and_absent_optional_transport_close_still_closes_journal(self):
        metrics={'native_client_seconds':1.25};transport=SimpleNamespace(metrics=Mock(return_value=metrics))
        adapter=ConvergentTransport(transport,self.action,self.journal)
        self.assertIs(adapter.metrics(),metrics);transport.metrics.assert_called_once_with()
        await adapter.aclose();self.assertTrue(self.journal.closed)

    async def test_non_result_transport_output_cannot_authorize_a_mutation(self):
        transport=SimpleNamespace(execute=AsyncMock(return_value=object()))
        adapter=ConvergentTransport(transport,self.action,self.journal)
        with self.assertRaisesRegex(ValueError,'mismatched result'):
            await adapter.execute(self.host,self.action.descriptor)
        transport.execute.assert_awaited_once_with(self.host,self.action.check)
        self.assertEqual(set(self.journal.records.values()),{'checking'});self.assertFalse(self.journal.active)

    async def test_mutation_is_verified_and_a_second_call_does_not_repeat_it(self):
        first = await self.adapter.execute(self.host, self.action.descriptor)
        second = await self.adapter.execute(self.host, self.action.descriptor)
        self.assertTrue(first.ok)
        self.assertTrue(first.changed)
        self.assertEqual(first.attempts, 3)
        self.assertFalse(second.changed)
        self.assertEqual(second.attempts, 1)
        self.assertEqual(self.native.mutations, 1)
        self.assertEqual(self.native.commands, ['inspect-state', 'change-state', 'inspect-state', 'inspect-state'])
        self.assertEqual(set(self.journal.records.values()), {'verified'})

    async def test_probe_failure_never_authorizes_mutation(self):
        for status, code in ((Status.FAILED, 2), (Status.AUTH_FAILED, 255),
                             (Status.INTERRUPTED, 255), (Status.TIMEOUT, None),
                             (Status.SUCCESS, None)):
            with self.subTest(status=status):
                self.native.failure = Result(self.host, status, exit_code=code)
                result = await self.adapter.execute(self.host, self.action.descriptor)
                self.assertFalse(result.ok)
                self.assertFalse(result.changed)
                self.assertEqual(self.native.mutations, 0)

    async def test_pending_mutation_is_only_verified_and_never_automatically_repeated(self):
        self.journal.records[(self.host.target, self.action.digest)] = 'applying'
        result = await self.adapter.execute(self.host, self.action.descriptor)
        self.assertFalse(result.ok)
        self.assertEqual(self.native.commands, ['inspect-state'])
        self.assertEqual(self.native.mutations, 0)
        self.native.desired = True
        result = await self.adapter.execute(self.host, self.action.descriptor)
        self.assertTrue(result.ok)
        self.assertFalse(result.changed)
        self.assertEqual(self.native.mutations, 0)

    async def test_explicit_verify_never_mutates_or_poison_a_fresh_intent(self):
        adapter = ConvergentTransport(self.native, self.action, self.journal, verify_only=True)
        result = await adapter.execute(self.host, self.action.descriptor)
        self.assertFalse(result.ok)
        self.assertEqual(self.native.commands, ['inspect-state'])
        self.assertEqual(set(self.journal.records.values()), {'checking'})
        result = await self.adapter.execute(self.host, self.action.descriptor)
        self.assertTrue(result.ok)
        self.assertEqual(self.native.mutations, 1)

    async def test_failed_action_and_failed_postcondition_leave_a_pending_intent(self):
        for fail_at in ('change-state', 'verify-state'):
            action = replace(self.action, verify='verify-state')
            native, journal = StatefulTransport(), MemoryJournal()
            original = native.execute
            async def execute(host, command):
                if command == fail_at:
                    native.commands.append(command)
                    return Result(host, Status.FAILED, exit_code=3)
                return await original(host, command)
            native.execute = execute
            adapter = ConvergentTransport(native, action, journal)
            result = await adapter.execute(self.host, action.descriptor)
            self.assertFalse(result.ok)
            self.assertFalse(result.changed)
            self.assertEqual(set(journal.records.values()), {'blocked'})
            self.assertEqual(native.mutations, 0 if fail_at == 'change-state' else 1)

    async def test_cancellation_during_action_keeps_the_intent_and_releases_the_scope(self):
        entered = asyncio.Event()
        original = self.native.execute
        async def execute(host, command):
            if command == 'change-state':
                entered.set()
                await asyncio.Event().wait()
            return await original(host, command)
        self.native.execute = execute
        task = asyncio.create_task(self.adapter.execute(self.host, self.action.descriptor))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(set(self.journal.records.values()), {'applying'})
        self.assertFalse(self.journal.active)

    async def test_mismatched_descriptor_host_or_mutating_probe_is_rejected(self):
        with self.assertRaises(ValueError):
            await self.adapter.execute(self.host, 'other-descriptor')
        for result in (Result(Host('other'), Status.SUCCESS, exit_code=0),
                       Result(self.host, Status.SUCCESS, exit_code=0, changed=True)):
            self.native.failure = result
            with self.assertRaises(ValueError):
                await self.adapter.execute(self.host, self.action.descriptor)
        await self.adapter.aclose()
        self.assertTrue(self.native.closed)
        self.assertTrue(self.journal.closed)


class ConvergenceJournalIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Real private files, OS locks and SQLite; these are not unit-test doubles."""

    async def test_intent_survives_reopen_and_concurrent_owners_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            host, action = Host('node'), DesiredState('state', 'check', 'apply')
            first = SQLiteConvergenceJournal(Options(), directory=directory)
            second = SQLiteConvergenceJournal(Options(), directory=directory)
            try:
                async with first.scope(host, action) as lease:
                    self.assertEqual(first.db.execute('PRAGMA synchronous').fetchone()[0],3)
                    self.assertFalse(lease.pending)
                    await lease.applying()
                    with self.assertRaisesRegex(ValueError, 'already active'):
                        async with second.scope(host, action):
                            self.fail('a competing mutation was admitted')
                await first.aclose()
                async with second.scope(host, action) as lease:
                    self.assertTrue(lease.pending)
                    await lease.verified()
                async with second.scope(host, action) as lease:
                    self.assertFalse(lease.pending)
            finally:
                await first.aclose()
                await second.aclose()

    async def test_capacity_failure_cannot_create_unbounded_lock_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = SQLiteConvergenceJournal(Options(), directory=directory, max_records=1)
            action = DesiredState('state', 'check', 'apply')
            try:
                async with journal.scope(Host('first'), action):
                    pass
                with self.assertRaisesRegex(ValueError, 'full'):
                    async with journal.scope(Host('second'), action):
                        self.fail('journal capacity bypassed')
                self.assertEqual(len(list((Path(directory) / 'locks').iterdir())), 1)
                self.assertEqual(journal.db.execute('SELECT count(*) FROM records').fetchone()[0], 1)
            finally:
                await journal.aclose()

    async def test_process_death_releases_lock_but_preserves_mutation_intent(self):
        code = '''
import asyncio,os,sys
from swassh import DesiredState,Host,Options
from swassh.infrastructure.convergence import SQLiteConvergenceJournal
async def mutate():
    journal=SQLiteConvergenceJournal(Options(),directory=sys.argv[1])
    async with journal.scope(Host('node'),DesiredState('state','check','apply')) as lease:
        await lease.applying()
        os._exit(9)
asyncio.run(mutate())
'''
        with tempfile.TemporaryDirectory() as directory:
            result = await asyncio.to_thread(subprocess.run,
                [sys.executable, '-c', code, directory], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 9, result.stderr)
            journal = SQLiteConvergenceJournal(Options(), directory=directory)
            try:
                async with journal.scope(Host('node'), DesiredState('state', 'check', 'apply')) as lease:
                    self.assertTrue(lease.pending)
                    await lease.verified()
            finally:
                await journal.aclose()

    async def test_cancellation_during_lock_creation_closes_the_completed_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = SQLiteConvergenceJournal(Options(), directory=directory)
            host, action = Host('node'), DesiredState('state', 'check', 'apply')
            async with journal.scope(host, action):
                pass
            entered, release = threading.Event(), threading.Event()
            class Handle:
                closed = False

                def close(self):
                    self.closed = True
            handle = Handle()
            def creating(path):
                entered.set()
                if not release.wait(2):
                    raise TimeoutError('test lock release was not signalled')
                return handle
            async def acquire():
                async with journal.scope(host, action):
                    self.fail('cancelled acquisition entered its protected operation')
            try:
                with patch('swassh.infrastructure.convergence._WriterLock', side_effect=creating):
                    task = asyncio.create_task(acquire())
                    self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                    task.cancel()
                    release.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                self.assertTrue(handle.closed)
                self.assertEqual(journal.active, 0)
            finally:
                release.set()
                await journal.aclose()

    async def test_invalid_schema_and_corrupt_counters_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            action = DesiredState('state', 'check', 'apply')
            journal = SQLiteConvergenceJournal(Options(), directory=directory)
            async with journal.scope(Host('node'), action):
                pass
            journal.db.execute('UPDATE capacity SET records=0')
            await journal.aclose()
            reopened = SQLiteConvergenceJournal(Options(), directory=directory)
            try:
                with self.assertRaisesRegex(ValueError, 'counters'):
                    async with reopened.scope(Host('node'), action):
                        self.fail('corrupt journal was admitted')
            finally:
                await reopened.aclose()

    async def test_down_migration_refuses_loss_and_ddl_rolls_back_on_error(self):
        db = sqlite3.connect(':memory:', isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE')
            ConvergenceSchema.up(db)
            db.rollback()
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
            db.execute('BEGIN IMMEDIATE')
            ConvergenceSchema.up(db)
            ConvergenceSchema.down(db)
            db.commit()
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
            db.execute('BEGIN IMMEDIATE')
            ConvergenceSchema.up(db)
            db.execute("INSERT INTO records VALUES (?, 'applying')", ('a' * 64,))
            with self.assertRaisesRegex(ValueError, 'nonempty'):
                ConvergenceSchema.down(db)
            db.rollback()
        finally:
            db.close()

    async def test_strict_json_loader_and_cli_plan_do_not_create_runtime_state(self):
        from swassh.interfaces import cli
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / 'action.json'
            action = DesiredState('state', 'check', 'apply')
            spec.write_text(json.dumps(action.to_dict()), encoding='utf-8')
            self.assertEqual(load_desired_state(spec), action)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(['converge', '--action-file', str(spec), '-H', 'node',
                                           '--budget-dir', str(root / 'budget'), '--plan-only']), 0)
            self.assertGreater(json.loads(output.getvalue())['workers'], 0)
            self.assertFalse((root / 'budget').exists())
            for text in ('{"schema_version":1,"schema_version":1}', '[]', '{"bad":NaN}'):
                spec.write_text(text)
                with self.assertRaises(ValueError):
                    load_desired_state(spec)


class ConvergenceFacadeTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_result_iteration_preserves_targets_and_closes_the_source(self):
        action = DesiredState('state', 'inspect-state', 'change-state')
        expected = (Result(Host('first'), Status.SUCCESS, exit_code=0),
                    Result(Host('second'), Status.SUCCESS, exit_code=0))
        class MemoryService:
            closed = False
            calls = []

            async def iter_results(self, hosts, command):
                self.calls.append((hosts, command))
                try:
                    for result in expected:
                        yield result
                finally:
                    self.closed = True
        memory = MemoryService()
        with patch('swassh.interfaces.convergence.Swarm', return_value=memory):
            service = ConvergentSwarm(action)
        hosts = ('first', 'second')
        results = tuple([result async for result in service.iter_results(hosts)])
        self.assertEqual(results, expected)
        self.assertEqual(memory.calls, [(hosts, action.descriptor)])
        self.assertTrue(memory.closed)

    async def test_disk_report_and_early_iterator_close_use_existing_contracts(self):
        action = DesiredState('state', 'inspect-state', 'change-state')
        with tempfile.TemporaryDirectory() as directory:
            native, journal = StatefulTransport(), MemoryJournal()
            service = ConvergentSwarm(action, transport_factory=lambda _: native,
                                      journal_factory=lambda _: journal)
            report_path = Path(directory) / 'report.json'
            summary = await service.run_to_file(['node'], report_path)
            self.assertTrue(summary.ok)
            payload = json.loads(report_path.read_text(encoding='utf-8'))
            self.assertTrue(payload['results'][0]['changed'])
            self.assertEqual(payload['command'], action.descriptor)
            self.assertNotIn('change-state', report_path.read_text(encoding='utf-8'))
            self.assertTrue(journal.closed)
        native, journal = StatefulTransport(), MemoryJournal()
        native.desired = True
        service = ConvergentSwarm(action, transport_factory=lambda _: native,
                                  journal_factory=lambda _: journal)
        async with aclosing(service.iter_results(['first', 'second'])) as results:
            self.assertTrue((await anext(results)).ok)
        self.assertEqual(native.commands, ['inspect-state'])
        self.assertTrue(journal.closed)

    async def test_falsey_trusted_factories_do_not_fall_back_to_native_adapters(self):
        native, journal = StatefulTransport(), MemoryJournal()
        native.desired = True
        class Factory:
            def __init__(self, value):
                self.value = value

            def __bool__(self):
                return False

            def __call__(self, options):
                return self.value
        service = ConvergentSwarm(DesiredState('state', 'inspect-state', 'change-state'),
                                  Options(ssh_executable='swassh-absent-test-client'),
                                  transport_factory=Factory(native), journal_factory=Factory(journal))
        self.assertTrue((await service.run(['node'])).ok)
        self.assertTrue(journal.closed)

    async def test_async_client_retains_durable_intents_and_typed_failure(self):
        from swassh import AsyncClient, Client, ExecutionError
        with tempfile.TemporaryDirectory() as directory:
            native = StatefulTransport()
            native.desired = True
            client = AsyncClient('node', options=Options(budget_dir=directory),
                                 transport_factory=lambda _: native)
            action = DesiredState('state', 'inspect-state', 'change-state')
            self.assertTrue((await client.converge(action, check=True)).ok)
            native.failure = Result(Host('node'), Status.AUTH_FAILED, exit_code=255)
            with self.assertRaises(ExecutionError):
                await client.converge(action, check=True)
            with self.assertRaises(TypeError):
                await client.converge(action, check=1)
            with self.assertRaisesRegex(RuntimeError, 'AsyncClient'):
                Client('node').converge(action)

    async def test_canary_failure_stops_the_remaining_hosts(self):
        action = DesiredState('state', 'check', 'apply')
        native = StatefulTransport()
        native.failure = Result(Host('first'), Status.AUTH_FAILED, exit_code=255)
        journal = MemoryJournal()
        service = ConvergentSwarm(action, transport_factory=lambda _: native,
                                  journal_factory=lambda _: journal)
        report = await service.run(['first', 'second'])
        self.assertFalse(report.ok)
        self.assertEqual(report.results[0].status, Status.AUTH_FAILED)
        self.assertEqual(report.results[1].status, Status.SKIPPED)
        self.assertEqual(native.commands, ['check'])
        self.assertNotIn('apply', report.command)

    async def test_invalid_options_and_factories_fail_before_service_construction(self):
        action = DesiredState('state', 'check', 'apply')
        # Invalid extension configuration must fail before storage, native
        # adapters or an execution service can be constructed.
        with patch('swassh.interfaces.convergence.Swarm', side_effect=AssertionError('must not construct')) as constructor:
            for options in (False, True, 0, 1, 'options', object()):
                with self.subTest(options=type(options).__name__), self.assertRaisesRegex(TypeError, '^options must be Options$'):
                    ConvergentSwarm(action, options)
            for field in ('transport_factory', 'journal_factory'):
                for value in (False, True, 0, 1, 'factory', object()):
                    with self.subTest(field=field, value=type(value).__name__), self.assertRaisesRegex(TypeError, '^desired-state factories must be callable$'):
                        ConvergentSwarm(action, **{field: value})
        constructor.assert_not_called()

    async def test_configuration_refuses_implicit_replay_and_interactive_input(self):
        action = DesiredState('state', 'check', 'apply')
        for options in (Options(retries=1), Options(stdin_file='input'), Options(pty=True)):
            with self.assertRaises(ValueError):
                ConvergentSwarm(action, options)
        with self.assertRaises(TypeError):
            ConvergentSwarm('not-an-action')
