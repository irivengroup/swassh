"""Regressions found during native Windows/Linux review of the recovered release."""
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swassh import Host, Options, Result, Status
from swassh.application.transfer_settings import TransferSettings
from swassh.domain.transfers import FileTransfer, TransferDirection, host_directory
from swassh.infrastructure.bastion import SharedBudget, specification
from swassh.infrastructure.filesystem import PinnedDirectory
from swassh.infrastructure.transfers import NativeFileTransport


class CounterIntegrityTests(unittest.TestCase):
    def test_stale_idle_pool_cannot_bypass_a_new_smaller_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            old = SharedBudget(specification(Options(budget_dir=directory, bastion_concurrency=4)))
            new = SharedBudget(specification(Options(budget_dir=directory, bastion_concurrency=1)))
            try:
                with self.assertRaisesRegex(ValueError, 'policy changed'):
                    old.ticket(connections=4)
                lease = new.ticket(connections=1)
                self.assertTrue(lease.poll())
                lease.close()
            finally:
                old.close()
                new.close()

    def test_dead_large_reservation_does_not_prevent_cold_policy_reduction(self):
        with tempfile.TemporaryDirectory() as directory:
            old = SharedBudget(specification(Options(budget_dir=directory, bastion_concurrency=4)))
            lease = old.ticket(connections=4)
            self.assertTrue(lease.poll())
            # Closing only the OS lock models process death, leaving its row.
            lease.lock.close()
            old.close()
            new = SharedBudget(specification(Options(budget_dir=directory, bastion_concurrency=1)))
            try:
                self.assertEqual(new.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)
                current = new.ticket(connections=1)
                try:
                    next_start = new.db.execute('SELECT next FROM policy WHERE id=1').fetchone()[0]
                    with patch('swassh.infrastructure.bastion.time.monotonic', return_value=next_start + 1):
                        self.assertTrue(current.poll())
                finally:
                    current.close()
            finally:
                new.close()

    def test_corrupt_live_counters_fail_closed_without_reclaiming_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = SharedBudget(specification(Options(budget_dir=directory)))
            lease = pool.ticket(connections=1)
            self.assertTrue(lease.poll())
            try:
                for field, value in (('connections', -1), ('memory', -1),
                                     ('bandwidth', -1), ('active', 2)):
                    with self.subTest(field=field):
                        old = pool.db.execute('SELECT '+field+' FROM leases WHERE id=?', (lease.identity,)).fetchone()[0]
                        pool.db.execute('UPDATE leases SET '+field+'=? WHERE id=?', (value, lease.identity))
                        try:
                            with self.assertRaisesRegex(ValueError, 'invalid shared budget'):
                                lease.poll()
                        finally:
                            pool.db.execute('UPDATE leases SET '+field+'=? WHERE id=?', (old, lease.identity))
            finally:
                lease.close()
                pool.close()


class TransferReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_truncated_remote_hash_cannot_report_success_or_start_data(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host('example')
            client = NativeFileTransport(Options(budget_dir=directory),
                TransferSettings(verify_sha256=True, rsync_executable='absent'),
                FileTransfer(TransferDirection.PULL, directory, '/source'), 1024)
            async with client:
                client.sftp = 'fixture'
                client.ssh.execute = AsyncMock(side_effect=[Result(host, Status.SUCCESS, 'digest'),
                    Result(host, Status.SUCCESS, 'a'*64, stdout_truncated=True)])
                client._run = AsyncMock()
                result = await client.transfer(host)
                self.assertEqual(result.status, Status.ERROR)
                client._run.assert_not_awaited()
                self.assertEqual(list(Path(directory).iterdir()), [])

    async def test_pull_preview_does_not_change_permissions_or_create_files(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host('example')
            destination = Path(directory) / host_directory(host)
            destination.mkdir()
            final = destination / 'source'
            final.write_bytes(b'keep')
            before = final.stat()
            client = NativeFileTransport(Options(budget_dir=directory),
                TransferSettings(dry_run=True, rsync_executable='absent'),
                FileTransfer(TransferDirection.PULL, directory, '/source'), 1024)
            async with client:
                client.rsync = 'fixture'
                client.ssh.execute = AsyncMock(return_value=Result(host, Status.SUCCESS, 'rsync version 3.5.0'))
                client._run = AsyncMock(return_value=Result(host, Status.SUCCESS,
                    'preview only: added=0 changed=1 deleted=0'))
                with patch('swassh.infrastructure.windows.protect_directory',
                           side_effect=AssertionError('preview altered a DACL')):
                    result = await client.transfer(host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertIn('--dry-run', client._run.await_args.args[0])
            self.assertEqual(final.read_bytes(), b'keep')
            self.assertEqual(final.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(list(destination.iterdir()), [final])


@unittest.skipUnless(os.name == 'nt', 'native Windows tests')
class NativeWindowsReviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_after_content_change_uses_consistent_handle_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.write_bytes(b'old')
            # Deliberately separate creation and change times, avoiding dependence
            # on clock granularity to reproduce CPython's lstat/fstat discrepancy.
            os.utime(source, ns=(1000000000000000000, 1000000000000000000))
            source.write_bytes(b'new')
            client = NativeFileTransport(Options(budget_dir=directory),
                TransferSettings(rsync_executable='absent'),
                FileTransfer(TransferDirection.PUSH, str(source), '/target'), 1024)
            async with client:
                self.assertEqual(Path(client.source).read_bytes(), b'new')

    async def test_stream_device_and_normalized_names_cannot_escape_literal_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            with PinnedDirectory(directory) as pinned:
                for name in ('file:stream', 'NUL', 'CON.txt', 'COM1', 'trailing.', 'trailing '):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        pinned.open(name, os.O_WRONLY | os.O_CREAT)
            self.assertEqual(list(Path(directory).iterdir()), [])

    async def test_parent_kill_terminates_child_and_reclaims_memory_without_replay(self):
        from swassh.infrastructure.windows import ParentProcess
        with tempfile.TemporaryDirectory() as directory:
            source = '''import asyncio,os,sys
from swassh import Options
from swassh.infrastructure.bastion import invocation_budget
from swassh.infrastructure.process_guard import launch_native
async def main():
    options=Options(budget_dir=sys.argv[1])
    async with invocation_budget(options):
        process=await launch_native(sys.executable,'-c',
            'import os,time;print(os.getpid(),flush=True);time.sleep(60)',
            options=options,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        line=await process.stdout.readline()
        print(line.decode().strip(),flush=True)
        await asyncio.sleep(60)
asyncio.run(main())
'''
            parent = await asyncio.create_subprocess_exec(sys.executable, '-c', source, directory,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            child = None
            try:
                line = await asyncio.wait_for(parent.stdout.readline(), 10)
                self.assertTrue(line, await parent.stderr.read() if not line else '')
                child = ParentProcess(int(line))
                self.assertTrue(child.alive())
                parent.kill()
                await asyncio.wait_for(parent.wait(), 5)
                async with asyncio.timeout(10):
                    while child.alive():
                        await asyncio.sleep(0.025)
                pool = SharedBudget(specification(Options(budget_dir=directory)))
                try:
                    self.assertEqual(pool.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0], 0)
                finally:
                    pool.close()
            finally:
                if parent.returncode is None:
                    parent.kill()
                await parent.wait()
                if child:
                    child.close()
