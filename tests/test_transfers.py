import asyncio
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from swassh import (FileSwarm, FileTransfer, Host, Options, Result, Status,
                    TransferDirection, TransferSettings, pull_to_file, push_to_file)
from swassh.application.transfers import _TransferOperation
from swassh.domain.transfers import host_directory, local_filename
from swassh.infrastructure.transfers import NativeFileTransport, _batch_quote, _modern_rsync
from swassh.interfaces import cli

SERVER = os.environ.get('SWASSH_TEST_SFTP_SERVER') or next((str(p) for p in (Path('/usr/lib/openssh/sftp-server'),
    Path('/usr/libexec/sftp-server'), Path('/usr/libexec/openssh/sftp-server')) if p.exists()), None)
CREATE = asyncio.create_subprocess_exec


class TransferDomainTests(unittest.TestCase):
    def test_paths_and_settings(self):
        for path in ('relative', '/', '/a/../b', '/a\n!rm', '/a\x00'):
            with self.assertRaises(ValueError):
                FileTransfer(TransferDirection.PUSH, 'local', path)
        for direction, local in [('push', 'x'), (TransferDirection.PUSH, ''), (TransferDirection.PUSH, 'x\x7f')]:
            with self.assertRaises(ValueError):
                FileTransfer(direction, local, '/file')
        for kwargs in ({'timeout': float('nan')}, {'timeout': True}, {'bandwidth_kib': 0},
                       {'max_file_mib': False}, {'rsync_executable': ''}, {'rsync_options': ('--inplace',)}):
            with self.assertRaises(ValueError):
                TransferSettings(**kwargs)
        request = FileTransfer(TransferDirection.PUSH, 'secret', '/remote/')
        self.assertNotIn('secret', request.descriptor)
        self.assertEqual(TransferSettings().rsync_options, ('-avzPH', '--numeric-ids', '--delete'))

    def test_collision_safe_paths_and_versions(self):
        hosts = [Host('same', p, u) for p in (22, 222) for u in ('a', 'b')]
        self.assertEqual(len({host_directory(h) for h in hosts}), 4)
        for path in ('/CON', '/a*b', '/a:b', '/a.', '/'+('Ã©'*300)):
            self.assertLessEqual(len(local_filename(path).encode()), 220)
        self.assertEqual(local_filename('/normal'), 'normal')
        for version, ok in [('rsync  version 3.5.0 protocol version 31', True),
                             ('rsync version 2.6.9', False), ('garbage', False)]:
            self.assertEqual(_modern_rsync(version), ok)
        with self.assertRaises(ValueError):
            _batch_quote('a\n')

    def test_cli_plan_and_dispatch(self):
        for direction in ('push', 'pull'):
            output = io.StringIO()
            argv = [direction, '-H', 'a', '--source', '/source/', '--destination', '/target/', '--plan-only']
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(argv), 0)
            self.assertGreater(json.loads(output.getvalue())['workers'], 0)
            argv = argv[:-1]+['-o', '/report']
            with patch.object(cli, direction+'_to_file') as operation:
                operation.return_value.ok = True
                self.assertEqual(cli.main(argv), 0)
                self.assertEqual(operation.call_args.kwargs['settings'].rsync_options,
                                 ('-avzPH', '--numeric-ids', '--delete'))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['push', '-H', 'a', '--source', '/a', '--destination', '/b', '--retries', '1']), 2)
            with self.assertRaises(SystemExit) as raised:
                cli.main(['pull', '-H', 'a', '--source', '/a', '--destination', '/b', '-c', 'bad'])
            self.assertEqual(raised.exception.code, 2)
        with patch('swassh.interfaces.transfers.asyncio.run', return_value='ok') as run:
            def finish(coroutine):
                coroutine.close()
                return 'ok'
            run.side_effect = finish
            self.assertEqual(push_to_file(['a'], '/a', '/b', '/report'), 'ok')
            self.assertEqual(pull_to_file(['a'], '/b', '/a', '/report'), 'ok')


@unittest.skipUnless(shutil.which('ssh'), 'native SSH client required')
class TransferTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root/'source file'
        self.source.write_bytes(b'payload\x00\xff'*100)
        self.options = Options(connect_rate=100000)
        self.host = Host('example', username='user')

    def client(self, direction=TransferDirection.PUSH, remote=None, **settings):
        local = self.source if direction == TransferDirection.PUSH else self.root/'downloads'
        remote_path = str(remote or self.root/'remote file')
        if os.name == 'nt':
            remote_path = '/' + remote_path.replace('\\', '/').lstrip('/')
        request = FileTransfer(direction, str(local), remote_path)
        return NativeFileTransport(self.options, TransferSettings(**settings), request, 10240)

    async def local_launch(self, *argv, **kwargs):
        kwargs.pop("options", None)
        kwargs.pop("connected", None)
        kwargs.pop("bandwidth", None)
        args = list(argv)
        # Local-only feature tests: override the capability banner, never use the
        # old rsync binary against an SSH peer. Security-floor tests are separate.
        if Path(args[0]).name == 'rsync' and '--version' in args:
            return await CREATE(sys.executable, '-c', 'print("rsync version 3.5.0")', **kwargs)
        if Path(args[0]).name == 'sftp':
            # Real native SFTP parser/protocol, without a sandbox-forbidden sshd chroot.
            args = [args[0], '-D', SERVER, '-b', args[args.index('-b')+1]]
        elif Path(args[0]).name == 'rsync' and '--version' not in args:
            self.last_argv = args[:]
            index = args.index('-e')
            del args[index:index+2]
            args = [arg.removeprefix('swassh-target:') for arg in args]
        return await CREATE(*args, **kwargs)

    async def test_snapshot_and_source_validation(self):
        client = self.client(rsync_executable='absent-rsync')
        async with client:
            self.source.write_text('changed')
            self.assertEqual(Path(client.source).read_bytes(), b'payload\x00\xff'*100)
            snapshot = Path(client.source)
        self.assertFalse(snapshot.exists())
        client = self.client()
        self.source.unlink()
        with self.assertRaises(OSError):
            await client.__aenter__()
        self.source.mkdir()
        with self.assertRaises(ValueError):
            await client.__aenter__()
        if os.name == 'posix':
            self.source.rmdir()
            self.source.symlink_to(self.root)
            with self.assertRaises(ValueError):
                await client.__aenter__()

    async def test_size_and_changed_source(self):
        self.source.write_bytes(b'x'*(1024**2+1))
        with self.assertRaises(ValueError):
            await self.client(max_file_mib=1).__aenter__()
        self.source.write_bytes(b'good')
        # Inject the fault only at observations of this source, never at an
        # unrelated connector or directory descriptor during client setup.
        identity = self.source.stat()
        expected = (identity.st_dev, identity.st_ino)
        client = self.client()
        original = os.fstat
        count = 0
        def fstat(fd):
            nonlocal count
            info = original(fd)
            if (info.st_dev, info.st_ino) != expected:
                return info
            count += 1
            if count == 2:
                self.source.write_bytes(b'changed size')
                return original(fd)
            return info
        with patch('swassh.infrastructure.transfers.os.fstat', fstat), self.assertRaises(ValueError) as rejected:
            await client.__aenter__()
        self.assertEqual(count, 2)
        self.assertEqual(self.source.read_bytes(), b'changed size')
        self.assertRegex(str(rejected.exception), r'^source changed (before|during) snapshot$')

    async def test_changed_source_rejection_survives_unrelated_descriptor_inspection(self):
        unrelated = self.root/'unrelated metadata'
        unrelated.write_bytes(b'other file')
        original = asyncio.to_thread
        observations = 0
        with unrelated.open('rb') as descriptor:
            async def inspect_then_copy(function, *args, **kwargs):
                nonlocal observations
                # Exercise real metadata while the source fault injector is active.
                os.fstat(descriptor.fileno())
                observations += 1
                return await original(function, *args, **kwargs)
            with patch('swassh.infrastructure.transfers.asyncio.to_thread', inspect_then_copy):
                await self.test_size_and_changed_source()
        self.assertGreater(observations, 0)

    async def test_runner_failure_timeout_cancellation_and_budget(self):
        client = self.client(timeout=0.1, max_file_mib=1)
        result = await client._run([sys.executable, '-c', "import time;print('start',flush=True);time.sleep(10)"], self.host)
        self.assertEqual(result.status, Status.TIMEOUT)
        result = await client._run([sys.executable, '-c', "import sys;print('x'*100000);sys.exit(9)"], self.host, timeout=3)
        self.assertEqual(result.status, Status.FAILED)
        self.assertTrue(result.stdout_truncated)
        result = await client._run(['/nonexistent-executable'], self.host, timeout=3)
        self.assertEqual(result.status, Status.ERROR)
        watched = self.root/'oversized'
        watched.write_bytes(b'x'*(1024**2+1))
        result = await client._run([sys.executable, '-c', 'import time;time.sleep(10)'], self.host, timeout=2, watched=watched)
        self.assertEqual(result.status, Status.ERROR)
        task = asyncio.create_task(client._run([sys.executable, '-c', 'import time;time.sleep(10)'], self.host, timeout=5))
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_backend_selection_no_replay(self):
        async with self.client() as client:
            client.rsync = '/rsync'
            for status in (Status.AUTH_FAILED, Status.HOST_KEY_FAILED, Status.UNREACHABLE, Status.TIMEOUT):
                client.ssh.execute = AsyncMock(return_value=Result(self.host, status))
                result = await client.transfer(self.host)
                self.assertEqual(result.status, status)
                self.assertIsNotNone(result.transfer)
            client.ssh.execute = AsyncMock(return_value=Result(self.host, Status.SUCCESS, 'rsync version 3.5.0'))
            client._run = AsyncMock(return_value=Result(self.host, Status.FAILED, stderr='rsync missing'))
            result = await client.transfer(self.host)
            self.assertEqual(result.transfer.backend, 'rsync')
            self.assertEqual(client._run.await_count, 1)
        async with self.client(rsync_executable='absent', sftp_executable='absent') as client:
            self.assertEqual((await client.transfer(self.host)).status, Status.ERROR)
        source = self.root/'tree'
        source.mkdir()
        request = FileTransfer(TransferDirection.PUSH, str(source)+'/', '/destination/')
        async with NativeFileTransport(self.options, TransferSettings(rsync_executable='absent'), request, 1) as client:
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
            self.assertIn('--delete', result.error)

    async def test_sync_api_in_loop_and_descriptor(self):
        for operation in (push_to_file, pull_to_file):
            with self.assertRaises(RuntimeError):
                operation([], '/a', '/b', '/report')
        with self.assertRaises(ValueError):
            await _TransferOperation(None, 'descriptor').execute(self.host, 'different')

    @unittest.skipUnless(shutil.which('rsync'), 'rsync unavailable')
    async def test_local_old_version(self):
        async def old(*args, **kwargs):
            return Result(self.host, Status.SUCCESS, 'rsync version 2.6.9')
        client = self.client()
        with patch.object(client, '_run', old):
            async with client:
                self.assertIsNone(client.rsync)

    @unittest.skipUnless(shutil.which('rsync') and os.name == 'posix', 'POSIX rsync unavailable')
    async def test_real_rsync_push_pull_and_directory_delete(self):
        probe = AsyncMock(return_value=Result(self.host, Status.SUCCESS, 'rsync version 3.5.0'))
        remote = self.root/'remote file'
        with patch('swassh.infrastructure.transfers.launch_native', self.local_launch):
            async with self.client(remote=remote) as client:
                client.ssh.execute = probe
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual(remote.read_bytes(), self.source.read_bytes())
                self.assertTrue(all(flag in self.last_argv for flag in ('-avzPH', '--numeric-ids', '--delete', '--safe-links', '--no-devices', '--no-specials', '--max-alloc=16M')))
            async with self.client(TransferDirection.PULL, remote) as client:
                client.ssh.execute = probe
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual(Path(result.transfer.local_path).read_bytes(), remote.read_bytes())
            source, target = self.root/'tree', self.root/'mirror'
            source.mkdir(); target.mkdir()
            (source/'keep').write_text('keep')
            (source/'link').hardlink_to(source/'keep')
            (source/'unsafe').symlink_to('/outside/tree')
            (source/'fifo').touch()
            (source/'fifo').unlink()
            os.mkfifo(source/'fifo')
            (target/'stale').write_text('delete')
            request = FileTransfer(TransferDirection.PUSH, str(source)+'/', str(target)+'/')
            async with NativeFileTransport(self.options, TransferSettings(), request, 10240) as client:
                client.ssh.execute = probe
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertFalse((target/'stale').exists())
                self.assertFalse((target/'unsafe').exists())
                self.assertFalse((target/'fifo').exists())
                self.assertEqual((target/'keep').stat().st_ino, (target/'link').stat().st_ino)
            request = FileTransfer(TransferDirection.PULL, str(self.root/'trees'), str(target)+'/')
            async with NativeFileTransport(self.options, TransferSettings(), request, 10240) as client:
                client.ssh.execute = probe
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual((Path(result.transfer.local_path)/'keep').read_text(), 'keep')

    @unittest.skipUnless(SERVER and shutil.which('sftp'), 'native SFTP server unavailable')
    async def test_real_sftp_literal_paths_atomic_push_pull(self):
        if os.name == 'posix':
            self.source.chmod(0o6755)
        for name in ('remote space', 'remote"quote', 'remote*?[x]', 'remote\\backslash'):
            remote = self.root/name
            remote.write_text('old')
            with self.subTest(name=name), patch('swassh.infrastructure.transfers.launch_native', self.local_launch):
                async with self.client(remote=remote, rsync_executable='absent') as client:
                    result = await client.transfer(self.host)
                    self.assertEqual(result.status, Status.SUCCESS, result)
                    self.assertEqual(result.transfer.backend, 'sftp')
                    self.assertEqual(remote.read_bytes(), self.source.read_bytes())
                async with self.client(TransferDirection.PULL, remote, rsync_executable='absent') as client:
                    result = await client.transfer(self.host)
                    self.assertEqual(result.status, Status.SUCCESS, result)
                    self.assertEqual(Path(result.transfer.local_path).read_bytes(), self.source.read_bytes())
                    if os.name == 'posix':
                        self.assertEqual(Path(result.transfer.local_path).stat().st_mode & 0o6000, 0)
                        self.assertEqual(remote.stat().st_mode & 0o6000, 0)

    @unittest.skipUnless(SERVER and shutil.which('sftp'), 'native SFTP server unavailable')
    async def test_sftp_failure_preserves_local_and_remote_part_report(self):
        remote = self.root/'missing'
        with patch('swassh.infrastructure.transfers.launch_native', self.local_launch):
            async with self.client(TransferDirection.PULL, remote, rsync_executable='absent') as client:
                folder = client.local/host_directory(self.host)
                folder.mkdir()
                final = folder/local_filename(str(remote))
                final.write_text('old')
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.FAILED)
                self.assertEqual(final.read_text(), 'old')
                self.assertFalse(list(folder.glob('.swassh-*')))
            async with self.client(remote=self.root/'missing-parent'/'file', rsync_executable='absent') as client:
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.FAILED)
                self.assertIn('.swassh-', result.transfer.temporary_path)

    async def test_symlink_destination_and_literal_routing(self):
        if os.name == 'posix':
            root = self.root/'downloads'
            root.symlink_to(self.root)
            with self.assertRaises(ValueError):
                await self.client(TransferDirection.PULL).__aenter__()
            root.unlink()
            async with self.client(TransferDirection.PULL, rsync_executable='absent') as client:
                (client.local/host_directory(self.host)).symlink_to(self.root)
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.ERROR)
        for remote in ('/remote*file', '/remote*/'):
            async with self.client(TransferDirection.PULL, remote) as client:
                client.rsync = '/rsync'
                client.sftp = None
                client.ssh.execute = AsyncMock(return_value=Result(self.host, Status.SUCCESS, 'rsync version 3.5.0'))
                result = await client.transfer(self.host)
                self.assertEqual(result.status, Status.ERROR)

    async def test_native_report_batches_keep_data_without_per_record_round_trips(self):
        """The real writer must opt in while its synthetic transport stays bounded."""
        from swassh.application.transfers import TransferService
        from swassh.bootstrap import dependencies
        from swassh.application.contracts import MIB, ResourcePlan
        from swassh.infrastructure.process_reporter import ProcessReportWriter
        runtime = dependencies()
        class BatchTransferTransport:
            closed = False

            async def __aenter__(inner):
                return inner

            async def __aexit__(inner, *exc):
                inner.closed = True

            async def transfer(inner, host):
                from swassh import TransferReceipt
                await asyncio.sleep(0)
                return Result(host, Status.SUCCESS, 'synthetic transfer result',
                    transfer=TransferReceipt('push', '/synthetic-local', '/synthetic-remote', 'sftp', 1))
        client, batches = BatchTransferTransport(), []
        service = TransferService(Options(concurrency=1, show_output=False), TransferSettings(),
            transport_factory=lambda *args: client, audit_factory=runtime.audit_factory,
            planner=lambda _: ResourcePlan(1, 1, 128 * MIB, 49 * MIB, 20.0),
            reporter_factory=runtime.reporter_factory, report_factory=runtime.report_factory)
        request = FileTransfer(TransferDirection.PUSH, '/synthetic-local', '/synthetic-remote')
        original = ProcessReportWriter.append
        async def append(writer, results):
            batches.append(len(results))
            return await original(writer, results)
        path = self.root / 'native-batch-report.json'
        with patch.object(ProcessReportWriter, 'append', append):
            summary = await service.run_to_file((Host(f'batch-{i}') for i in range(96)), request, path)
        data = json.loads(path.read_text())
        self.assertTrue(summary.ok)
        self.assertEqual(summary.total, 96)
        self.assertEqual(len(data['results']), 96)
        self.assertEqual({row['host']['hostname'] for row in data['results']}, {f'batch-{i}' for i in range(96)})
        self.assertEqual(sum(batches), 96)
        self.assertTrue(all(1 <= count <= 32 for count in batches))
        self.assertLess(len(batches), 96)
        self.assertGreater(summary.report_worker_pid, 0)
        self.assertNotEqual(summary.report_worker_pid, os.getpid())
        self.assertTrue(client.closed)

    async def test_receipts_reporting_bounded_fleet(self):
        from swassh.application.transfers import TransferService
        from swassh.bootstrap import dependencies
        from swassh.infrastructure.report import csv_row
        runtime = dependencies()
        active = peak = 0
        class Fake:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *exc):
                pass
            async def transfer(inner, host):
                nonlocal active, peak
                active += 1
                peak = max(active, peak)
                await asyncio.sleep(0)
                active -= 1
                from swassh import TransferReceipt
                return Result(host, Status.SUCCESS, 'transfer complete', transfer=TransferReceipt(
                    'push', '=formula', '/secret', 'rsync', 100))
        service = TransferService(Options(concurrency=12, log_file=str(self.root/'audit'), show_output=False),
            TransferSettings(bandwidth_kib=5), transport_factory=lambda *args: Fake(),
            audit_factory=runtime.audit_factory, planner=runtime.planner,
            reporter_factory=runtime.reporter_factory, report_factory=runtime.report_factory)
        request = FileTransfer(TransferDirection.PUSH, '/local', '/secret')
        report = self.root/'report.json'
        summary = await service.run_to_file((Host('host'+str(i)) for i in range(10001)), request, report)
        self.assertTrue(summary.ok)
        self.assertLessEqual(peak, 5)
        data = json.loads(report.read_text())
        self.assertEqual(len(data['results']), 10001)
        self.assertEqual(data['results'][0]['transfer']['backend'], 'rsync')
        self.assertNotIn('/secret', (self.root/'audit').read_text())
        memory = await service.run(['one', 'two'], request)
        self.assertEqual(len(memory.results), 2)
        self.assertEqual(csv_row(memory.results[0])['transfer_local_path'], "'=formula")
        self.assertLess(len(memory.to_text().splitlines()), 20)
        generator = service.iter_results(['one', 'two'], request)
        self.assertEqual((await anext(generator)).transfer.backend, 'rsync')
        await generator.aclose()

    async def test_transfer_planning_and_spool_formats(self):
        with self.assertRaises(ValueError):
            FileSwarm(Options(memory_budget_mib=16)).plan()
        probe = AsyncMock(return_value=Result(self.host, Status.FAILED, exit_code=127))
        async with self.client() as client:
            client.rsync = '/rsync'
            client.ssh.execute = probe
            client._run = AsyncMock(return_value=Result(self.host, Status.SUCCESS))
            result = await client.transfer(self.host)
            self.assertEqual(result.transfer.backend, 'sftp')
            self.assertEqual(result.transfer.fallback_reason, 'remote rsync unavailable or unsupported')
        # Failure to publish a successful download never replaces the original file.
        async with self.client(TransferDirection.PULL, rsync_executable='absent') as client:
            async def oversized(argv, host, **kwargs):
                kwargs['watched'].write_bytes(b'x'*(1024**2+1))
                return Result(host, Status.SUCCESS)
            client.settings = replace(client.settings, max_file_mib=1)
            client._run = oversized
            result = await client.transfer(self.host)
            self.assertEqual(result.status, Status.ERROR)
            self.assertFalse(list(client.local.rglob('.swassh-*')))
        # Native processes are bounded and cannot turn a quoted path into a glob.
        if SERVER and shutil.which('sftp'):
            sibling = self.root/'wildcard-match'
            sibling.write_text('must not download')
            with patch('swassh.infrastructure.transfers.launch_native', self.local_launch):
                async with self.client(TransferDirection.PULL, self.root/'wildcard-*', rsync_executable='absent') as client:
                    result = await client.transfer(self.host)
                    self.assertEqual(result.status, Status.FAILED)
        from swassh import TransferReceipt
        from swassh.infrastructure.spool import ReportStore
        from swassh.application.contracts import RunSummary
        from datetime import UTC, datetime
        now = datetime.now(UTC)
        result = Result(self.host, Status.SUCCESS, 'transfer complete', transfer=TransferReceipt('pull', '=evil', '/remote', 'sftp', 42))
        with tempfile.TemporaryDirectory() as directory:
            store = ReportStore(directory, 1024**2)
            try:
                store.append([result])
                summary = RunSummary(1, {s.value: int(s == Status.SUCCESS) for s in Status}, now, now, FileSwarm().plan(), show_output=False)
                for format in ('csv', 'json', 'text'):
                    output = Path(directory)/('report.'+format)
                    store.export(output, format, 'pull:hash', summary)
                    content = output.read_text()
                    if format == 'csv':
                        self.assertIn("'=evil", content)
                    elif format == 'json':
                        self.assertEqual(json.loads(content)['results'][0]['transfer']['bytes_transferred'], 42)
                    else:
                        self.assertNotIn('transfer complete', content)
                        self.assertIn('success', content)
                        store.export(output, format, 'pull:hash', replace(summary, show_output=True))
                        self.assertIn('  │ transfer complete', output.read_text(encoding='utf-8'))
            finally:
                store.close()
