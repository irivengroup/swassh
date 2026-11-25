"""Cross-process safety and the seven improvements shipped in 1.4.0."""
import asyncio
import contextlib
import contextvars
import hashlib
import io
import json
import os
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swassh import Host, Options, Result, Status, Swarm
from swassh.application.admission import Admission
from swassh.application.transfer_settings import TransferSettings
from swassh.domain.transfers import FileTransfer, TransferDirection, host_directory
from swassh.infrastructure.bastion import FileLock, SharedBudget, specification, invocation_budget, cli_invocation_budget, current_reservation
from swassh.infrastructure.filesystem import AtomicOutput, PinnedDirectory, private_directory
from swassh.infrastructure.integrity import PROBE, TOOLS, digest_file, hash_command, parse_hash, publish_command
from swassh.infrastructure.preview import PreviewBuffer
from swassh.infrastructure.process_guard import launch_native
from swassh.infrastructure.ssh import _cleanup_process
from swassh.infrastructure.transfers import NativeFileTransport
from swassh.infrastructure.schedule_store import decode_invocation, encode_invocation
from swassh.application.schedule_contracts import ScheduledInvocation
from swassh.interfaces.cli import _parser


class SharedBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.options = Options(budget_dir=self.temp.name, bastion_concurrency=2, bastion_connect_rate=1000)
        self.pool = SharedBudget(specification(self.options))
        self.addCleanup(self.pool.close)

    def lease(self, **kwargs):
        lease = self.pool.ticket(**kwargs)
        self.addCleanup(lease.close)
        return lease

    @patch('swassh.infrastructure.bastion.time.monotonic',return_value=100.0)
    def test_atomic_first_admission_keeps_fifo_capacity_and_pacing(self,clock):
        first=self.lease(connections=2,activate=True)
        self.assertEqual(self.pool.db.execute('SELECT active FROM leases WHERE id=?',
                                              (first.identity,)).fetchone()[0],1)
        second=self.lease(connections=1,activate=True)
        self.assertFalse(second.poll())
        first.close()
        self.assertFalse(second.poll())  # The connection-rate slot still holds.
        clock.return_value=101.0
        third=self.lease(connections=1,activate=True)
        self.assertFalse(third.poll())  # New publication cannot overtake second.
        self.assertTrue(second.poll())
        clock.return_value=102.0
        self.assertTrue(third.poll())

    def test_atomic_admission_requires_boolean_and_retains_parent_checks(self):
        for value in (None,0,1,'yes'):
            with self.assertRaisesRegex(ValueError,'activation'):
                self.pool.ticket(connections=1,activate=value)
        with self.assertRaisesRegex(ValueError,'memory reservation unavailable'):
            self.pool.ticket(connections=1,parent='a'*32,activate=True)
        self.assertEqual(self.pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0],0)
        self.assertFalse(self.pool.db.in_transaction)

    def test_closing_unowned_handle_preserves_local_ownership(self):
        from swassh.infrastructure.bastion import _OWNED
        path = self.pool.directory / 'ownership-test.lock'
        owner = FileLock(path)
        self.addCleanup(owner.close)
        self.assertTrue(owner.acquire())
        # A contender may be opened but never acquire the lock. Closing it must
        # not erase the marker protecting the owner's recovery path.
        contender = FileLock(path)
        contender.close()
        self.assertIn(path, _OWNED)
        owner.close()
        self.assertNotIn(path, _OWNED)

    def test_database_writer_contention_defers_admission_without_failure(self):
        lease = self.lease(connections=1)
        self.pool.db.execute('PRAGMA busy_timeout=0')
        writer = sqlite3.connect(self.pool.directory / 'budget.sqlite3', isolation_level=None)
        try:
            writer.execute('BEGIN IMMEDIATE')
            self.assertFalse(lease.poll())
            self.assertFalse(self.pool.db.in_transaction)
            writer.execute('ROLLBACK')
            writer.execute('BEGIN')
            writer.execute('SELECT * FROM policy').fetchall()
            self.assertFalse(lease.poll())  # Reader blocks COMMIT, not BEGIN.
            self.assertFalse(self.pool.db.in_transaction)
            self.assertEqual(self.pool.db.execute('SELECT active FROM leases WHERE id=?',
                                                 (lease.identity,)).fetchone()[0], 0)
            writer.execute('ROLLBACK')
            self.assertTrue(lease.poll())
        finally:
            writer.close()

    def test_poll_yields_before_busy_peers_release_and_restores_connection_timeout(self):
        # Real writer and reader transactions exercise BEGIN and COMMIT contention.
        # The contender must return while the blocking peer still owns its lock.
        for mode in ('writer', 'reader'):
            with self.subTest(mode=mode):
                lease = self.lease(connections=1)
                self.pool.db.execute('PRAGMA busy_timeout=5000')
                writer = sqlite3.connect(self.pool.directory / 'budget.sqlite3', isolation_level=None)
                entered, done = threading.Event(), threading.Event()
                values, errors = [], []
                def poll():
                    entered.set()
                    try:
                        values.append(lease.poll())
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        done.set()
                worker = threading.Thread(target=poll)
                try:
                    writer.execute('BEGIN IMMEDIATE' if mode == 'writer' else 'BEGIN')
                    if mode == 'reader':
                        writer.execute('SELECT * FROM policy').fetchall()
                    worker.start()
                    scheduled = entered.wait(5)
                    returned_with_peer_held = done.wait(1)
                finally:
                    if writer.in_transaction:
                        writer.execute('ROLLBACK')
                    if worker.ident is not None:
                        worker.join(10)
                    writer.close()
                self.assertTrue(scheduled)
                self.assertFalse(worker.is_alive())
                self.assertTrue(returned_with_peer_held, 'poll blocked inside SQLite instead of yielding')
                self.assertEqual(errors, [])
                self.assertEqual(values, [False])
                self.assertFalse(self.pool.db.in_transaction)
                self.assertEqual(self.pool.db.execute('PRAGMA busy_timeout').fetchone()[0], 5000)
                self.assertEqual(self.pool.db.execute('SELECT active FROM leases WHERE id=?',
                    (lease.identity,)).fetchone()[0], 0)
                self.pool.db.execute('PRAGMA busy_timeout=37')
                self.assertTrue(lease.poll())
                self.assertEqual(self.pool.db.execute('PRAGMA busy_timeout').fetchone()[0], 37)
                lease.close()

    def test_scope_is_shared_across_users_and_jumps(self):
        normal = specification(self.options)
        jumped = specification(replace(self.options, username="different", jump_host=Host("jump", username="relay")))
        self.assertEqual(normal['directory'], jumped['directory'])

    @patch('swassh.infrastructure.bastion.time.monotonic', return_value=0.0)
    def test_capacity_bandwidth_memory_and_fifo(self, clock):
        # Windows runtimes can expose a clock coarser than a 3 ms sleep. Advance
        # logical time explicitly: this test isolates FIFO/capacity from timing.
        first = self.lease(connections=1, bandwidth=10240)
        second = self.lease(connections=1, bandwidth=1)
        self.assertTrue(first.poll())
        clock.return_value = 0.003
        self.assertFalse(second.poll())
        third = self.lease(connections=1)
        self.assertFalse(third.poll())  # Never overtake a bandwidth-blocked peer.
        first.close()
        self.assertTrue(second.poll())
        clock.return_value = 0.006
        self.assertTrue(third.poll())
        fourth = self.lease(connections=1)
        self.assertFalse(fourth.poll())
        memory = self.lease(memory=512 * 1024**2)
        self.assertTrue(memory.poll())  # Separate queue avoids memory/client deadlock.
        another = self.lease(memory=1)
        self.assertFalse(another.poll())
        self.assertEqual(second.wait_seconds, 0.003)

    @patch('swassh.infrastructure.bastion.time.monotonic', return_value=0.0)
    def test_pacing_proxyjump_and_idle(self, clock):
        self.pool.close()
        self.pool = SharedBudget(specification(replace(self.options, bastion_connect_rate=20)))
        self.addCleanup(self.pool.close)
        lease = self.lease(connections=2)
        self.assertTrue(lease.poll())
        lease.close()
        following = self.lease(connections=1)
        self.assertFalse(following.poll())  # Idle does not reset pacing.
        clock.return_value = 0.099
        self.assertFalse(following.poll())  # Two jump slots require a full 100 ms.
        clock.return_value = 0.1
        self.assertTrue(following.poll())

    @patch('swassh.infrastructure.bastion.time.monotonic', return_value=1000.0)
    def test_long_pacing_deadline_and_reboot_recovery(self, clock):
        self.pool.close()
        options = replace(self.options, bastion_concurrency=20, bastion_connect_rate=0.1)
        self.pool = SharedBudget(specification(options))
        self.addCleanup(self.pool.close)
        lease = self.lease(connections=13)
        self.assertTrue(lease.poll())
        lease.close()
        following = self.lease(connections=1)
        self.assertFalse(following.poll())
        clock.return_value = 1129.0
        self.assertFalse(following.poll())
        clock.return_value = 1130.0
        self.assertTrue(following.poll())
        following.close()
        # No OS reservation survives a reboot, but the persisted deadline does.
        clock.return_value = 1.0
        after_reboot = self.lease(connections=1)
        self.assertTrue(after_reboot.poll())
        clock.return_value = 0.5
        blocked = self.lease(connections=1)
        with self.assertRaisesRegex(ValueError, 'clock regressed'):
            blocked.poll()

    @patch('swassh.infrastructure.bastion.time.monotonic', return_value=1000.0)
    def test_legacy_long_deadline_survives_migration_and_policy_reduction(self, clock):
        self.pool.close()
        options = replace(self.options, bastion_concurrency=20, bastion_connect_rate=0.1)
        self.pool = SharedBudget(specification(options))
        self.pool.db.execute('UPDATE policy SET next=1130 WHERE id=1')
        self.pool.db.execute('DROP TABLE clock')
        self.pool.close()
        self.pool = SharedBudget(specification(self.options))
        self.addCleanup(self.pool.close)
        following = self.lease(connections=1)
        self.assertFalse(following.poll())
        clock.return_value = 1130.0
        self.assertTrue(following.poll())

    def test_equivalent_integer_and_float_rates_share_active_policy(self):
        held = self.lease(memory=1)
        self.assertTrue(held.poll())
        # Reproduce a persisted CLI integer default and an API float default.
        self.pool.db.execute('UPDATE policy SET value=? WHERE id=1',
            (json.dumps(specification(self.options)['policy']),))
        other = SharedBudget(specification(replace(self.options, bastion_connect_rate=1000.0)))
        other.close()

    def test_mismatched_active_policy_and_idle_update(self):
        held = self.lease(memory=1)
        self.assertTrue(held.poll())
        different = specification(replace(self.options, bastion_concurrency=3))
        with self.assertRaisesRegex(ValueError, 'policy differs'):
            SharedBudget(different)
        held.close()
        pool = SharedBudget(different)
        pool.close()

    def test_stale_os_lock_recovery_not_pid_or_time(self):
        identity = 'f' * 32
        self.pool.db.execute("INSERT INTO leases(id,kind,active,connections,memory,bandwidth) VALUES (?,'client',1,2,0,0)", (identity,))
        lease = self.lease(connections=1)
        self.assertTrue(lease.poll())
        self.assertIsNone(self.pool.db.execute('SELECT id FROM leases WHERE id=?', (identity,)).fetchone())
        with self.assertRaises(ValueError):
            self.pool.ticket(connections=3)
        for spec in ({}, {'directory': self.temp.name, 'policy': [True, 2, 5, 1]}):
            with self.assertRaises(ValueError):
                SharedBudget(spec)

    def test_ten_independent_processes_respect_shared_limit(self):
        # Ten CLI interpreter invocations compete for the same two slots. Times
        # are written by the admitted processes, not inferred from parent sleeps.
        events = [Path(self.temp.name) / ('events-' + str(i)) for i in range(10)]
        source = ("import json,sys,time;from swassh.infrastructure.bastion import SharedBudget;"
            "p=SharedBudget(json.loads(sys.argv[1]));l=p.ticket(connections=1);\n"
            "while not l.poll(): time.sleep(.005)\n"
            "start=time.monotonic();time.sleep(.08);end=time.monotonic()\n"
            "with open(sys.argv[2],'w') as f: json.dump([start,end],f)\n"
            "l.close();p.close()")
        spec = json.dumps(specification(self.options))
        clients = [subprocess.Popen([sys.executable, '-c', source, spec, str(events[i]), str(i)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(10)]
        try:
            for process in clients:
                _, errors = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, errors.decode())
            rows = sorted((t, event, identity) for identity, path in enumerate(events)
                for t, event in zip(json.loads(path.read_text()), ('start', 'stop')))
            active = peak = 0
            for _, event, _ in rows:
                active += 1 if event == 'start' else -1
                peak = max(peak, active)
            self.assertEqual(active, 0)
            self.assertLessEqual(peak, 2)
            self.assertEqual(len(rows), 20)
        finally:
            for process in clients:
                if process.poll() is None:
                    process.kill()
                process.communicate()


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_early_timer_wakeup_does_not_admit_before_reserved_slot(self):
        control = Admission(2, 10, adaptive=True)
        control.next_start = 11.0
        # Event-loop timers may wake early on coarse clocks. A wakeup is not
        # evidence that the reserved admission deadline has been reached.
        with patch('swassh.application.admission.time.monotonic',
                   side_effect=[10.0, 10.0, 10.5, 11.0, 11.0]), \
                patch('swassh.application.admission.asyncio.sleep', new_callable=AsyncMock) as sleep:
            self.assertTrue(await control.acquire())
        self.assertEqual([call.args[0] for call in sleep.await_args_list], [1.0, 0.5])
        self.assertEqual(control.active, 1)
        self.assertEqual(control.next_start, 11.1)

    async def test_reduction_recovery_circuit_and_no_replay(self):
        control = Admission(8, 10000, adaptive=True, threshold=3)
        for _ in range(2):
            self.assertTrue(await control.acquire())
            await control.complete(Result(Host('a'), Status.TIMEOUT))
        self.assertEqual(control.limit, 2)
        for _ in range(4):
            self.assertTrue(await control.acquire())
            await control.complete(Result(Host('a'), Status.SUCCESS))
        self.assertEqual(control.limit, 3)
        for _ in range(3):
            self.assertTrue(await control.acquire())
            await control.complete(Result(Host('a'), Status.UNREACHABLE))
        self.assertFalse(await control.acquire())
        self.assertTrue(control.circuit_open)
        self.assertEqual(control.limit, 1)
        self.assertLessEqual(control.peak, 8)

    async def test_fleet_skips_are_distinct_from_canary(self):
        calls = []
        class Transport:
            async def execute(self, host, command):
                calls.append(host.target)
                return Result(host, Status.SUCCESS if host.hostname == 'canary' else Status.TIMEOUT)
        report = await Swarm(Options(concurrency=1, adaptive=True, circuit_threshold=2, connect_rate=10000),
            transport=Transport()).run(['canary', 'a', 'b', 'c', 'd'], 'x')
        self.assertEqual(len(calls), 3)
        self.assertEqual(report.counts['skipped'], 2)
        self.assertTrue(all(r.attempts == 0 and 'circuit' in r.error for r in report.results[3:]))
        self.assertTrue(report.canary_passed)

    async def test_remote_stderr_does_not_trip_network_circuit(self):
        control = Admission(2, 1000, adaptive=True, threshold=1)
        self.assertTrue(await control.acquire())
        await control.complete(Result(Host('a'), Status.FAILED, stderr='connection refused timeout'))
        self.assertFalse(control.circuit_open)
        self.assertEqual(control.limit, 2)

    async def test_waiter_cancellation_releases_capacity(self):
        control = Admission(1, 1, adaptive=True)
        self.assertTrue(await control.acquire())
        waiter = asyncio.create_task(control.acquire())
        await asyncio.sleep(0)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertEqual(control.active, 1)
        await control.complete(Result(Host('a'), Status.SUCCESS))
        control.next_start = time.monotonic() + 20
        waiter = asyncio.create_task(control.acquire())
        await asyncio.sleep(0.01)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertEqual(control.active, 0)

    async def test_progress_bounded_and_json_unchanged(self):
        from swassh.infrastructure.progress import progress as render_progress
        # Real SDK reporting is exercised. Only its progress timer is controlled:
        # machine speed and asyncio debug messages do not define formatter size.
        tick, observed = asyncio.Event(), asyncio.Event()
        sleeps, observed_in_flight, updates = [], [], []
        stream, diagnostics = io.StringIO(), io.StringIO()
        class ProgressClock:
            def __getattr__(self, name):
                return getattr(asyncio, name)
            async def sleep(self, delay):
                if delay == 1:
                    sleeps.append(delay)
                    await tick.wait()
                    tick.clear()
                else:
                    await asyncio.sleep(delay)
        class Transport:
            async def execute(self, host, command):
                if host.hostname == 'h250':
                    tick.set()
                    # The ready progress task emits synchronously before the
                    # next cooperative turn; no wall-clock deadline is guessed.
                    await asyncio.sleep(0)
                    observed_in_flight.append(observed.is_set())
                return Result(host, Status.SUCCESS, stdout='same')
        def show_progress(metrics, *, final=False):
            with contextlib.redirect_stderr(stream):
                render_progress(metrics, final=final)
            updates.append((metrics['completed'], final))
            if not final:
                observed.set()
        try:
            with contextlib.redirect_stderr(diagnostics), \
                    patch('swassh.application.swarm.asyncio', ProgressClock()), \
                    patch('swassh.bootstrap.progress', show_progress):
                report = await Swarm(Options(progress_interval=1), transport=Transport()).run(
                    [f'h{i}' for i in range(500)], 'x')
        finally:
            # Keep runtime warnings in the runner journal; never hide a slow
            # callback or change the loop's debug/exception-handler settings.
            sys.stderr.write(diagnostics.getvalue())
        self.assertLess(len(stream.getvalue()), 512)
        self.assertIn('500/500', stream.getvalue())
        self.assertNotIn('h499', stream.getvalue())
        self.assertEqual(json.loads(report.to_json())['schema_version'], 1)
        self.assertEqual(sleeps, [1, 1])
        self.assertEqual(observed_in_flight, [True])
        self.assertEqual(len(updates), 2)
        self.assertLess(updates[0][0], 500)
        self.assertEqual(updates[-1], (500, True))
        self.assertTrue(report.ok)
        self.assertEqual(len(report.results), 500)
        self.assertTrue(all(result.stdout == 'same' for result in report.results))
        captured_progress = stream.getvalue()
        self.assertTrue(all(result.host.hostname not in captured_progress for result in report.results))
        self.assertNotIn('exception was never retrieved', diagnostics.getvalue().lower())
        self.assertNotIn('exception in callback', diagnostics.getvalue().lower())

    async def test_memory_boundary_reentrant_cancelled_and_too_large(self):
        with tempfile.TemporaryDirectory() as directory:
            options = Options(budget_dir=directory)
            async with invocation_budget(options):
                async with invocation_budget(options):
                    pool = SharedBudget(specification(options))
                    self.assertEqual(pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 1)
                    pool.close()
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                async with invocation_budget(replace(options, memory_budget_mib=512)):
                    self.fail('oversized memory admission')
            async with invocation_budget(replace(options, memory_budget_mib=448)):
                # Create in a fresh context to model another independent invocation.
                task = asyncio.create_task(invocation_wait(options), context=contextvars.Context())
                await asyncio.sleep(0.1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            pool = SharedBudget(specification(options))
            self.assertEqual(pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)
            pool.close()


async def invocation_wait(options):
    async with invocation_budget(options):
        raise AssertionError('must wait for shared memory')


class FilesystemPinTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX descriptors')
    def test_publication_stays_in_pinned_directory_after_parent_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'parent'
            original.mkdir()
            destination = original / 'report'
            output = AtomicOutput(destination)
            with output as stream:
                original.rename(root / 'moved')
                original.mkdir()
                stream.write('verified')
            self.assertFalse(destination.exists())
            self.assertEqual((root / 'moved/report').read_text(), 'verified')

    @unittest.skipUnless(os.name == 'posix', 'POSIX descriptor race')
    def test_missing_parent_replaced_during_mkdir_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.mkdir()
            original = os.mkdir
            def raced(path, *args, **kwargs):
                if path == 'missing':
                    original(path, *args, **kwargs)
                    os.rmdir(path, dir_fd=kwargs['dir_fd'])
                    os.symlink(outside, path, dir_fd=kwargs['dir_fd'])
                    return
                return original(path, *args, **kwargs)
            # A final alias is rejected even if this test runs with the same UID.
            with patch('os.mkdir', raced), self.assertRaises(ValueError):
                private_directory(root / 'missing')
            self.assertEqual(list(outside.iterdir()), [])

    def test_atomic_failure_preserves_previous_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'report'
            destination.write_text('old')
            with self.assertRaises(RuntimeError):
                with AtomicOutput(destination) as stream:
                    stream.write('partial')
                    raise RuntimeError('export failed')
            self.assertEqual(destination.read_text(), 'old')
            self.assertEqual(list(Path(directory).iterdir()), [destination])

    def test_names_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            with PinnedDirectory(directory, private=True) as pinned:
                for value in ('', '.', '..', '../escape', 'a/b', 'a\\b'):
                    with self.assertRaises(ValueError):
                        pinned.open(value, os.O_WRONLY)
                pinned.unlink('missing')
            if os.name == 'posix':
                Path(directory).chmod(0o777)
                with self.assertRaises(ValueError):
                    PinnedDirectory(directory)
                Path(directory).chmod(0o700)


class PreviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_large_stream_aggregates_without_truncation_or_filenames(self):
        buffer = PreviewBuffer(1)
        stream = asyncio.StreamReader()
        # Feeding/read concurrency remains bounded; never accumulate a file list.
        async def feed():
            for _ in range(100):
                stream.feed_data(b'SWASSH:>f+++++++++\n' * 100)
                stream.feed_data(b'SWASSH:>f.s.......\nSWASSH:*deleting  \n')
                await asyncio.sleep(0)
            stream.feed_eof()
        await asyncio.gather(buffer.consume(stream), feed())
        self.assertEqual((buffer.added, buffer.changed, buffer.deleted), (10000, 100, 100))
        self.assertFalse(buffer.invalid)
        self.assertLess(len(buffer.text), 100)
        self.assertFalse(buffer.truncated)

    async def test_malformed_or_unbounded_records_fail_closed(self):
        for record in (b'SWASSH:xf+++++++++\n', b'file secret\n', b'a'*10000, b'SWASSH:xx\n'):
            stream = asyncio.StreamReader()
            stream.feed_data(record)
            stream.feed_eof()
            buffer = PreviewBuffer(1)
            await buffer.consume(stream)
            self.assertTrue(buffer.invalid)


class IntegrityContractTests(unittest.TestCase):
    def test_bounded_stream_hash_and_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data'
            path.write_bytes(b'data' * 1000000)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest_file(path, 5 * 1024**2), digest)
            with self.assertRaises(ValueError):
                digest_file(path, 1)
            if os.name == 'posix':
                link = path.with_name('link')
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    digest_file(link, 5 * 1024**2)
        for tool in TOOLS:
            self.assertIn(shlex.quote('/srv/a;touch bad'), hash_command(tool, '/srv/a;touch bad'))
        for tool, value in (('sha256sum', digest+'  /file\n'), ('shasum', digest+' */file\n'),
                ('openssl', 'SHA2-256(/file)= '+digest+'\n'), ('digest', digest+'\n')):
            self.assertEqual(parse_hash(tool, value), digest)
            with self.assertRaises(ValueError):
                parse_hash(tool, 'invalid')
            self.assertIn('&& mv -f ', publish_command(tool, '/tmp/private', '/srv/final', digest))
        with self.assertRaises(ValueError):
            hash_command('evil', '/file')
        with self.assertRaises(ValueError):
            publish_command('digest', '/a', '/b', 'nothex')

    def test_cli_validation_and_legacy_schedule_snapshot(self):
        args = _parser().parse_args(['push', '--source', 'x', '--destination', '/y', '-H', 'a', '--dry-run', '--adaptive', '--progress'])
        self.assertTrue(args.dry_run and args.adaptive and args.progress)
        for kwargs in ({'progress_interval': 0.2}, {'adaptive': 1}, {'bastion_connect_rate': float('nan')},
                {'bastion_concurrency': 0}, {'circuit_threshold': True}, {'budget_dir': ''}):
            with self.assertRaises(ValueError):
                Options(**kwargs)
        with self.assertRaises(ValueError):
            TransferSettings(dry_run=True, verify_sha256=True)
        invocation = ScheduledInvocation('x', (Host('a'),), Options(), str(Path(tempfile.gettempdir()) / 'report'))
        data = json.loads(encode_invocation(invocation))
        fields = {'budget_dir', 'bastion_concurrency', 'bastion_connect_rate', 'bastion_memory_mib',
            'bastion_bandwidth_kib', 'adaptive', 'circuit_threshold', 'progress_interval'}
        for field in fields:
            data['options'].pop(field)
        self.assertEqual(decode_invocation(json.dumps(data)).options, Options())


class GuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_native_group_cleanup_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            options = Options(budget_dir=directory)
            process = await launch_native(sys.executable, '-c', 'import time;print("ready",flush=True);time.sleep(30)',
                options=options, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=os.name == 'posix')
            try:
                self.assertEqual((await asyncio.wait_for(process.stdout.readline(), 10)).rstrip(b'\r\n'), b'ready')
                cleanup = asyncio.create_task(_cleanup_process(process, []))
                await asyncio.sleep(0)
                cleanup.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await cleanup
                self.assertIsNotNone(process.returncode)
                self.assertEqual(await process.stdout.read(), b'')
            finally:
                await _cleanup_process(process, [])
            pool = SharedBudget(specification(options))
            self.assertEqual(pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)
            pool.close()

    async def test_exited_leader_child_holding_pipe_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            code = ('import subprocess,sys;subprocess.Popen([sys.executable,"-c",'
                '"import time;print(\\\"child\\\",flush=True);time.sleep(30)"]);'
                'print("leader",flush=True)')
            process = await launch_native(sys.executable, '-c', code, options=Options(budget_dir=directory),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=os.name == 'posix')
            try:
                output, errors = await asyncio.wait_for(process.communicate(), 10)
                self.assertEqual(process.returncode, 0, errors)
                self.assertIn(b'leader', output)
            finally:
                await _cleanup_process(process, [])

    @unittest.skipUnless(os.name == 'posix', 'SIGKILL parent identity/control pipe')
    async def test_parent_sigkill_stops_client_and_recovers_capacity_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / 'native.pid'
            calls = root / 'calls'
            child = ('import os,time;from pathlib import Path;Path('+repr(str(pidfile))+').write_text(str(os.getpid()));'
                'Path('+repr(str(calls))+').write_text("once");time.sleep(60)')
            source = ('import asyncio,sys;from swassh import Options;from swassh.infrastructure.process_guard import launch_native;'
                '\nasync def main():\n p=await launch_native(sys.executable,"-c",sys.argv[2],options=Options(budget_dir=sys.argv[1]),'
                'stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True);await p.communicate()\n'
                'asyncio.run(main())')
            parent = subprocess.Popen([sys.executable, '-c', source, directory, child], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(200):
                    if pidfile.exists():
                        break
                    await asyncio.sleep(0.025)
                self.assertTrue(pidfile.exists())
                native_pid = int(pidfile.read_text())
                parent.kill()
                await asyncio.to_thread(parent.wait)
                deadline = time.monotonic() + 2.5
                pool = SharedBudget(specification(Options(budget_dir=directory)))
                lease = pool.ticket(connections=32)
                try:
                    # Client reaping and the guardian's lease close are separate
                    # observations. Require BOTH inside the original 2.5 s
                    # recovery budget, instead of racing the final close.
                    stopped = recovered = False
                    while time.monotonic() < deadline:
                        try:
                            os.kill(native_pid, 0)
                        except ProcessLookupError:
                            stopped = True
                        if stopped:
                            recovered = lease.poll()
                            if recovered:
                                break
                        await asyncio.sleep(0.025)
                    self.assertTrue(stopped, 'native client survived parent SIGKILL')
                    self.assertTrue(recovered, 'guardian capacity was not recovered within 2.5 seconds')
                    self.assertEqual(calls.read_text(), 'once')
                finally:
                    lease.close()
                    pool.close()
            finally:
                if parent.poll() is None:
                    parent.kill()
                parent.communicate()


@unittest.skipUnless(os.name == 'posix', 'native POSIX hash commands and local protocol fixtures')
class TransferImprovementTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.write_bytes(b'payload\x00\xff' * 100)
        self.remote = self.root / 'remote file'
        self.host = Host('test')
        self.options = Options(ssh_executable=sys.executable, budget_dir=str(self.root / 'budgets'))
        candidates = ('/usr/lib/openssh/sftp-server', '/usr/libexec/openssh/sftp-server', '/usr/libexec/sftp-server')
        self.server = os.environ.get('SWASSH_TEST_SFTP_SERVER') or next(
            (p for p in candidates if Path(p).is_file()), None)
        self.commands = []

    async def remote_command(self, host, command):
        self.commands.append(command)
        if command == 'rsync --version':
            return Result(host, Status.SUCCESS, 'rsync version 3.5.0\n')
        process = await asyncio.create_subprocess_exec('/bin/sh', '-c', command,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        return Result(host, Status.SUCCESS if process.returncode == 0 else Status.FAILED,
            stdout.decode(), stderr.decode(), process.returncode)

    async def local_native(self, *argv, **kwargs):
        argv = list(argv)
        if Path(argv[0]).name == 'rsync' and argv[1:] == ['--version']:
            argv = [sys.executable, '-c', 'print("rsync version 3.5.0")']
        elif Path(argv[0]).name == 'rsync':
            index = argv.index('-e')
            del argv[index:index+2]
            argv = [arg.removeprefix('swassh-target:') for arg in argv]
        elif Path(argv[0]).name == 'sftp':
            argv = [argv[0], '-D', self.server, '-b', argv[argv.index('-b')+1]]
        return await launch_native(*argv, **kwargs)

    def client(self, direction, *, rsync=False, source=None, remote=None, **settings):
        local = source or (self.source if direction == TransferDirection.PUSH else self.root / 'downloads')
        request = FileTransfer(direction, str(local), str(remote or self.remote))
        client = NativeFileTransport(self.options, TransferSettings(rsync_executable='rsync' if rsync else 'absent', **settings), request, 1000)
        client.ssh.execute = self.remote_command
        return client

    async def test_real_sftp_verified_push_and_pull(self):
        if not self.server or not shutil.which('sftp'):
            self.skipTest('native SFTP server unavailable')
        with patch('swassh.infrastructure.transfers.launch_native', self.local_native):
            async with self.client(TransferDirection.PUSH, verify_sha256=True) as client:
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual(self.remote.read_bytes(), self.source.read_bytes())
                self.assertIn('verified', result.stdout)
                self.assertEqual(self.remote.stat().st_mode & 0o777, 0o600)
            async with self.client(TransferDirection.PULL, verify_sha256=True) as client:
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual(Path(result.transfer.local_path).read_bytes(), self.source.read_bytes())
        self.assertEqual(sum('&& mv -f' in cmd for cmd in self.commands), 1)
        self.assertEqual(list(self.root.glob('.swassh-*.part')), [])

    async def test_push_mismatch_keeps_old_destination_and_reports_temporary(self):
        self.remote.write_bytes(b'old')
        async with self.client(TransferDirection.PUSH, verify_sha256=True) as client:
            async def corrupted(host, command):
                if command == PROBE:
                    return Result(host, Status.SUCCESS, 'digest')
                return Result(host, Status.SUCCESS, '0' * 64 + '\n')
            client.ssh.execute = AsyncMock(side_effect=corrupted)
            client._run = AsyncMock(return_value=Result(self.host, Status.SUCCESS))
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
            self.assertEqual(self.remote.read_bytes(), b'old')
            self.assertIsNotNone(result.transfer.temporary_path)
            self.assertEqual(client._run.await_count, 1)
            self.assertFalse(any('mv -f' in args.args[1] for args in client.ssh.execute.await_args_list))

    async def test_pull_mismatch_keeps_old_destination(self):
        self.remote.write_bytes(b'remote-good')
        local = self.root / 'downloads' / host_directory(self.host)
        local.mkdir(parents=True)
        final = local / 'remote file'
        final.write_bytes(b'old')
        async with self.client(TransferDirection.PULL, verify_sha256=True) as client:
            async def corrupted(argv, host, *, watched=None, **kwargs):
                watched.write_bytes(b'corrupt')
                return Result(host, Status.SUCCESS)
            client._run = corrupted
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
        self.assertEqual(final.read_bytes(), b'old')
        self.assertEqual(list(local.iterdir()), [final])

    async def test_unsupported_integrity_and_ambiguous_publish_never_replayed(self):
        async with self.client(TransferDirection.PUSH, verify_sha256=True) as client:
            client.ssh.execute = AsyncMock(return_value=Result(self.host, Status.SUCCESS, 'python'))
            client._run = AsyncMock()
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
            client._run.assert_not_awaited()
        async with self.client(TransferDirection.PUSH, verify_sha256=True) as client:
            client.ssh.execute = AsyncMock(side_effect=[Result(self.host, Status.SUCCESS, 'digest'),
                Result(self.host, Status.SUCCESS, client.source_digest+'\n'), Result(self.host, Status.TIMEOUT)])
            client._run = AsyncMock(return_value=Result(self.host, Status.SUCCESS))
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.TIMEOUT)
            self.assertIn('no replay', result.error)
            self.assertEqual(client._run.await_count, 1)
            self.assertEqual(client.ssh.execute.await_count, 3)
        tree = self.root / 'tree'
        tree.mkdir()
        client = self.client(TransferDirection.PUSH, source=tree, remote=str(self.remote)+'/', verify_sha256=True)
        with self.assertRaisesRegex(ValueError, 'single files'):
            await client.__aenter__()

    async def test_preview_requires_rsync_and_existing_pull_destination(self):
        async with self.client(TransferDirection.PUSH, dry_run=True) as client:
            client._run = AsyncMock()
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
            client._run.assert_not_awaited()
        missing = self.root / 'absent'
        client = self.client(TransferDirection.PULL, source=missing, dry_run=True)
        with self.assertRaises(FileNotFoundError):
            await client.__aenter__()
        self.assertFalse(missing.exists())

    @unittest.skipUnless(shutil.which('rsync'), 'native rsync unavailable')
    async def test_real_rsync_preview_readonly_add_change_delete(self):
        source = self.root / 'tree'
        destination = self.root / 'remote-tree'
        source.mkdir()
        destination.mkdir()
        (source / 'added').write_text('new')
        (source / 'changed').write_text('different contents')
        (destination / 'changed').write_text('old')
        (destination / 'deleted').write_text('old')
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in destination.iterdir()}
        with patch('swassh.infrastructure.transfers.launch_native', self.local_native):
            async with self.client(TransferDirection.PUSH, rsync=True, source=str(source)+'/',
                    remote=str(destination)+'/', dry_run=True) as client:
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertIn('added=1', result.stdout)
                self.assertIn('changed=1', result.stdout)
                self.assertIn('deleted=1', result.stdout)
                self.assertIsNone(result.transfer.bytes_transferred)
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in destination.iterdir()}
        self.assertEqual(before, after)


@unittest.skipUnless(os.name == 'posix', 'direct POSIX guardian logic')
class GuardianLogicTests(unittest.TestCase):
    def invoke(self, *, alive=True, argv=None, held=False):
        from swassh.infrastructure.process_guard import main
        with tempfile.TemporaryDirectory() as directory:
            reader, writer = os.pipe()
            options = Options(budget_dir=directory, bastion_connect_rate=1000)
            data = {'argv': argv or [sys.executable, '-c', 'import time;time.sleep(.03)'],
                'budget': specification(options), 'connections': 1, 'bandwidth': 0,
                'parent_pid': os.getpid(), 'parent_token': None, 'parent_fd': reader, 'invocation': None}
            path = Path(directory) / 'request.json'
            path.write_text(json.dumps(data))
            signals = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
            pool = lease = timer = None
            try:
                if held:
                    import threading
                    pool = SharedBudget(specification(options))
                    lease = pool.ticket(connections=32)
                    self.assertTrue(lease.poll())
                    timer = threading.Timer(.08, lambda: os.close(writer))
                    timer.start()
                elif not alive:
                    os.close(writer)
                result = main(path)
                if (Path(directory) / 'metrics.json').exists():
                    metrics = json.loads((Path(directory) / 'metrics.json').read_text())
                    self.assertGreaterEqual(metrics['admission_wait_seconds'], 0)
                return result
            finally:
                if timer:
                    timer.join()
                if alive and not held:
                    os.close(writer)
                os.close(reader)
                if lease:
                    lease.close()
                    pool.close()
                for sig, handler in signals.items():
                    signal.signal(sig, handler)

    def test_native_success_failure_parent_loss_and_waiting_loss(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.invoke(argv=[sys.executable, '-c', 'raise SystemExit(7)']), 7)
        self.assertEqual(self.invoke(alive=False), 125)
        self.assertEqual(self.invoke(held=True), 125)
        with self.assertRaises(OSError):
            self.invoke(argv=['/nonexistent-executable'])

    def test_request_validation_and_metrics_validation(self):
        from swassh.infrastructure.process_guard import main, native_metrics, release_guardian
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request'
            for data in ('{}', 'a' * 131073):
                path.write_text(data)
                with self.assertRaises(ValueError):
                    main(path)
            class Process:
                pass
            process = Process()
            self.assertEqual(native_metrics(process), {})
            temp = tempfile.TemporaryDirectory()
            process._swassh_guardian = (None, temp)
            metrics = Path(temp.name) / 'metrics.json'
            for value in ('{}', '{"admission_wait_seconds":-1,"native_seconds":0}', 'x'*1025):
                metrics.write_text(value)
                self.assertEqual(native_metrics(process), {})
            metrics.write_text('{"admission_wait_seconds":1,"native_seconds":2}')
            self.assertEqual(native_metrics(process)['native_seconds'], 2)
            release_guardian(process)
            release_guardian(process)
            self.assertFalse(Path(temp.name).exists())


class MemoryDependentTests(unittest.TestCase):
    def test_sync_cli_boundary_and_async_context_inheritance(self):
        with tempfile.TemporaryDirectory() as directory:
            options = Options(budget_dir=directory)
            with cli_invocation_budget(options):
                identity = current_reservation()
                self.assertIsNotNone(identity)
                with cli_invocation_budget(options):
                    self.assertEqual(current_reservation(), identity)
                async def check():
                    async with invocation_budget(options):
                        self.assertEqual(current_reservation(), identity)
                asyncio.run(check())
            self.assertIsNone(current_reservation())
            with self.assertRaises(ValueError):
                with cli_invocation_budget(replace(options, memory_budget_mib=512)):
                    self.fail('oversized reservation')

    def test_memory_retained_until_last_dependent_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = SharedBudget(specification(Options(budget_dir=directory)))
            owner = pool.ticket(memory=512*1024**2)
            self.assertTrue(owner.poll())
            child = pool.ticket(parent=owner.identity)
            self.assertTrue(child.poll())
            # Model parent death: drop only its OS lock, leave persistent capacity.
            owner.lock.close()
            contender = pool.ticket(memory=1)
            try:
                self.assertFalse(contender.poll())
                self.assertIsNotNone(pool.db.execute('SELECT id FROM leases WHERE id=?', (owner.identity,)).fetchone())
                child.close()
                self.assertTrue(contender.poll())
                with self.assertRaises(ValueError):
                    pool.ticket(parent='a' * 32)
            finally:
                contender.close()
                owner.close()
                pool.close()


class Win32ContractTests(unittest.TestCase):
    """Exercise ctypes contracts off Windows; native behavior is a separate CI gate."""
    def api(self):
        import ctypes
        import types
        from swassh.infrastructure import windows
        calls = []
        state = {'attributes': 0x10, 'wait': 0x102, 'owner': 77, 'failure': None}
        class Function:
            def __init__(self, name):
                self.name = name
            def __call__(self, *args):
                calls.append((self.name, args))
                if state['failure'] == self.name:
                    return 0
                if self.name == 'CreateJobObjectW':
                    return 11
                if self.name == 'GetCurrentProcess':
                    return 22
                if self.name == 'OpenProcess':
                    return 33
                if self.name == 'WaitForSingleObject':
                    return state['wait']
                if self.name == 'GetProcessTimes':
                    args[1]._obj.dwHighDateTime = 1
                    args[1]._obj.dwLowDateTime = 2
                if self.name == 'CreateFileW':
                    return 44
                if self.name == 'GetFileInformationByHandle':
                    ctypes.cast(args[1], ctypes.POINTER(windows.wintypes.DWORD)).contents.value = state['attributes']
                if self.name == 'OpenProcessToken':
                    args[2]._obj.value = 55
                if self.name == 'GetTokenInformation':
                    args[4]._obj.value = 32
                    if args[2] is not None:
                        ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p)).contents.value = 77
                if self.name == 'GetNamedSecurityInfoW':
                    args[3]._obj.value = state['owner']
                    args[7]._obj.value = 88
                    return 0
                if self.name == 'EqualSid':
                    return args[0].value == args[1]
                if self.name == 'ConvertSidToStringSidW':
                    args[1]._obj.value = 'S-1-5-21-123'
                if self.name == 'ConvertStringSecurityDescriptorToSecurityDescriptorW':
                    args[2]._obj.value = 99
                return 1
        names = ('CreateJobObjectW', 'SetInformationJobObject', 'AssignProcessToJobObject',
            'GetCurrentProcess', 'CloseHandle', 'TerminateJobObject', 'OpenProcess',
            'GetProcessTimes', 'WaitForSingleObject', 'CreateFileW', 'GetFileInformationByHandle',
            'LocalFree', 'OpenProcessToken', 'GetTokenInformation', 'GetNamedSecurityInfoW',
            'EqualSid', 'ConvertSidToStringSidW', 'ConvertStringSecurityDescriptorToSecurityDescriptorW', 'SetFileSecurityW')
        api = types.SimpleNamespace(**{name: Function(name) for name in names})
        return windows, api, calls, state

    def test_job_join_precedes_children_and_forbids_breakaway(self):
        windows, api, calls, state = self.api()
        with patch.object(windows, 'kernel32', return_value=api):
            job = windows.KillJob()
            self.assertEqual([name for name, _ in calls][:4],
                ['CreateJobObjectW', 'SetInformationJobObject', 'GetCurrentProcess', 'AssignProcessToJobObject'])
            limits = calls[1][1][2]._obj
            self.assertEqual(limits.basic.flags, 0x2000)
            with patch('os._exit', side_effect=SystemExit), self.assertRaises(SystemExit):
                job.terminate(7)
            self.assertEqual(calls[-1][0], 'TerminateJobObject')
        state['failure'] = 'AssignProcessToJobObject'
        import ctypes
        with patch.object(windows, 'kernel32', return_value=api), patch.object(ctypes, 'WinError', side_effect=OSError('assignment failed'), create=True), patch.object(ctypes, 'get_last_error', return_value=5, create=True), self.assertRaises(OSError):
            windows.KillJob()
        self.assertEqual(calls[-1][0], 'CloseHandle')

    def test_parent_creation_identity_and_wait_handle(self):
        windows, api, calls, state = self.api()
        with patch.object(windows, 'kernel32', return_value=api):
            parent = windows.ParentProcess(1, (1 << 32) | 2)
            self.assertTrue(parent.alive())
            state['wait'] = 0
            self.assertFalse(parent.alive())
            parent.close()
            parent.close()
            with self.assertRaises(ValueError):
                windows.ParentProcess(1, 3)
            self.assertEqual(calls[-1][0], 'CloseHandle')

    def test_directory_pin_rejects_junction_and_blocks_share_delete(self):
        windows, api, calls, state = self.api()
        with patch.object(windows, 'kernel32', return_value=api):
            pinned = windows.DirectoryHandle('C:\\safe')
            create = next(args for name, args in calls if name == 'CreateFileW')
            self.assertEqual(create[1], 0x81)
            self.assertEqual(create[2], 3)
            self.assertEqual(create[5], 0x02200000)
            pinned.close()
            pinned.close()
            state['attributes'] = 0x410
            with self.assertRaises(ValueError):
                windows.DirectoryHandle('C:\\junction')

    def test_private_dacl_owned_by_current_sid_only(self):
        windows, api, calls, state = self.api()
        import ctypes
        with patch.object(windows, 'kernel32', return_value=api), patch.object(ctypes, 'WinDLL', return_value=api, create=True):
            windows.protect_directory('C:\\private')
            sddl = next(args[0] for name, args in calls if name == 'ConvertStringSecurityDescriptorToSecurityDescriptorW')
            self.assertIn('D:P', sddl)
            self.assertIn('S-1-5-21-123', sddl)
            self.assertNotIn('WD', sddl)
            state['owner'] = 123
            with self.assertRaises(ValueError):
                windows.protect_directory('C:\\someone-else')

    @unittest.skipUnless(os.name == 'posix', 'mocked file-handle ownership on POSIX')
    def test_file_entry_open_does_not_follow_reparse(self):
        windows, api, calls, state = self.api()
        import types
        fake = types.SimpleNamespace(open_osfhandle=lambda handle, flags: os.open(os.devnull, os.O_WRONLY))
        with patch.object(windows, 'kernel32', return_value=api), patch.dict(sys.modules, {'msvcrt': fake}), patch.object(os, 'O_BINARY', 0, create=True):
            state['attributes'] = 0x80
            fd = windows.open_file_without_reparse('C:\\file', os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(fd)
            state['attributes'] = 0x400
            with self.assertRaises(ValueError):
                windows.open_file_without_reparse('C:\\link', os.O_WRONLY)


@unittest.skipUnless(os.name == 'nt', 'native Windows handles and Job Object require Windows CI')
class WindowsNativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_pinned_parent_cannot_be_renamed_until_handles_close(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / 'private'
            parent.mkdir()
            with PinnedDirectory(parent, private=True):
                with self.assertRaises(OSError):
                    parent.rename(parent.with_name('moved'))
            parent.rename(parent.with_name('moved'))
            self.assertTrue(parent.with_name('moved').is_dir())

    async def test_job_cleans_descendants_after_repeated_cancel(self):
        from swassh.infrastructure.windows import ParentProcess
        with tempfile.TemporaryDirectory() as directory:
            code = ('import subprocess,sys,time;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
                'print(p.pid,flush=True);time.sleep(60)')
            process = await launch_native(sys.executable, '-c', code, options=Options(budget_dir=directory),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            child = None
            try:
                pid = int(await asyncio.wait_for(process.stdout.readline(), 10))
                child = ParentProcess(pid)
                self.assertTrue(child.alive())
                cleanup = asyncio.create_task(_cleanup_process(process, []))
                await asyncio.sleep(0)
                cleanup.cancel()
                await asyncio.sleep(0)
                cleanup.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await cleanup
                self.assertFalse(child.alive())
                self.assertEqual(await asyncio.wait_for(process.stdout.read(), 5), b'')
            finally:
                await _cleanup_process(process, [])
                if child:
                    child.close()


class RecoveryDirectoryContracts(unittest.TestCase):
    """Retain real peer locks while bounding repeated ancestry work."""

    def setUp(self):
        SharedBudgetTests.setUp(self)

    def test_recovery_pins_once_and_preserves_all_live_peer_leases(self):
        import swassh.infrastructure.bastion as bastion
        import swassh.infrastructure.filesystem as filesystem
        ready = Path(self.temp.name) / 'peer-ready.json'
        source = (
            "import json,sys;from pathlib import Path;"
            "from swassh.infrastructure.bastion import SharedBudget;"
            "p=SharedBudget(json.loads(sys.argv[1]));"
            "leases=[p.ticket(connections=1) for _ in range(3)];"
            "ready=Path(sys.argv[2]);pending=ready.with_name('peer-ready.pending');"
            "pending.write_text(json.dumps([l.identity for l in leases]));pending.replace(ready);"
            "sys.stdin.read();[l.close() for l in leases];p.close()")
        peer = subprocess.Popen([sys.executable, '-c', source,
            json.dumps(specification(self.options)), str(ready)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not ready.exists() and peer.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(ready.exists(), 'peer did not publish its real leases')
            identities = json.loads(ready.read_text())
            pinned = filesystem.PinnedDirectory
            with patch.object(filesystem, 'PinnedDirectory', wraps=pinned) as opened, \
                    patch.object(bastion, 'PinnedDirectory', opened, create=True):
                self.pool.db.execute('BEGIN IMMEDIATE')
                try:
                    self.pool._recover()
                    rows = self.pool.db.execute('SELECT id,active FROM leases').fetchall()
                    self.assertEqual(set(rows), {(identity, 0) for identity in identities})
                    self.assertEqual(opened.call_count, 1)
                finally:
                    self.pool.db.execute('ROLLBACK')
        finally:
            try:
                _, errors = peer.communicate(timeout=10)
            except BaseException:
                peer.kill()
                peer.communicate()
                raise
            self.assertEqual(peer.returncode, 0, errors.decode())


class PinnedAppendContracts(unittest.TestCase):
    """An optional parent must stay live, match exactly and retain file checks."""

    def test_live_parent_is_reused_and_remains_owned_by_the_caller(self):
        from swassh.infrastructure.filesystem import open_private_append
        with tempfile.TemporaryDirectory() as temporary:
            with PinnedDirectory(temporary) as parent:
                path = parent.path / 'private.log'
                with open_private_append(path, directory=parent) as stream:
                    stream.write('first\n')
                self.assertFalse(parent._closed)
                with open_private_append(path, directory=parent) as stream:
                    stream.write('second\n')
                self.assertEqual(path.read_text(), 'first\nsecond\n')

    def test_foreign_or_closed_parent_is_rejected_before_file_creation(self):
        from swassh.infrastructure.filesystem import open_private_append
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            other = root / 'other'
            other.mkdir()
            with PinnedDirectory(root) as parent:
                with self.assertRaisesRegex(ValueError, 'live pinned parent'):
                    open_private_append(other / 'wrong.log', directory=parent)
                self.assertFalse((other / 'wrong.log').exists())
            with self.assertRaisesRegex(ValueError, 'live pinned parent'):
                open_private_append(root / 'closed.log', directory=parent)
            self.assertFalse((root / 'closed.log').exists())

    def test_pinned_parent_still_rejects_a_hard_link(self):
        from swassh.infrastructure.filesystem import open_private_append
        with tempfile.TemporaryDirectory() as temporary:
            # Use the live canonical parent exported by the pin contract.
            root = Path(temporary).resolve()
            target = root / 'target'
            target.write_text('unchanged')
            linked = root / 'linked'
            os.link(target, linked)
            with PinnedDirectory(root) as parent:
                with self.assertRaisesRegex(ValueError, 'hard links'):
                    open_private_append(linked, directory=parent)
            self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
