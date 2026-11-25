"""Regression scenarios for hostile data, resource exhaustion and process cleanup."""
import asyncio
import json
import os
import runpy
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Options, Result, Status, Swarm
from swassh.application.contracts import ResourcePlan
from swassh.application.transfer_settings import TransferSettings
from swassh.domain.commands import MAX_COMMAND_BYTES, validate_command
from swassh.domain.inventory import InventoryError, normalize_hosts, parse_host
from swassh.domain.models import TransferReceipt
from swassh.domain.transfers import FileTransfer, TransferDirection
from swassh.infrastructure.audit import AuditTrail, _compress
from swassh.infrastructure.filesystem import open_private_append, private_directory
from swassh.infrastructure.inventory import load_inventory
from swassh.infrastructure.lifecycle import finish_task
from swassh.infrastructure.process_reporter import ProcessReportWriter
from swassh.infrastructure.report import csv_row, safe_text
from swassh.infrastructure.resources import _available_memory
from swassh.infrastructure.spool import ReportStore, initialize_store, store_operation
from swassh.infrastructure.ssh import _config
from swassh.infrastructure.transfers import NativeFileTransport, _modern_rsync

ROOT = Path(__file__).resolve().parents[1]


class InputHardeningTests(unittest.TestCase):
    def test_ambiguous_inventories_are_rejected(self):
        samples = {
            '.json': ['[{"hostname":"a","hostname":"b"}]', '[{"hostname":"a","port":NaN}]', '[' * 2000 + ']' * 2000],
            '.csv': ['hostname,hostname\na,b\n', 'hostname,unknown\na,x\n', 'hostname,port\na\n', 'hostname\n"unclosed\n'],
        }
        with tempfile.TemporaryDirectory() as directory:
            for extension, contents in samples.items():
                for content in contents:
                    path = Path(directory) / ('inventory' + extension)
                    path.write_text(content)
                    with self.subTest(content=content[:50]), self.assertRaises(InventoryError):
                        load_inventory(path)

    def test_duplicate_iterators_have_an_input_limit(self):
        seen = []
        def values():
            for number in range(100):
                seen.append(number)
                yield 'node'
        with patch('swassh.domain.inventory.MAX_HOSTS', 5), self.assertRaisesRegex(InventoryError, 'input records'):
            normalize_hosts(values())
        self.assertEqual(len(seen), 6)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_inventory_fifo_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.txt'
            os.mkfifo(path)
            started = time.monotonic()
            with self.assertRaisesRegex(InventoryError, 'regular file'):
                load_inventory(path)
            self.assertLess(time.monotonic() - started, 1)

    def test_hosts_are_literal_valid_addresses(self):
        for hostname in ('%h', 'node..example', '-oProxyCommand=x', 'a/b', 'a\u0085b', 'bad:ipv6', '::1%'):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                Host(hostname)
        self.assertEqual(Host('münchen.example').hostname, 'xn--mnchen-3ya.example')
        self.assertEqual(Host('fe80::1%eth0').hostname, 'fe80::1%eth0')
        self.assertEqual(len(normalize_hosts(['NODE', 'node'])), 1)
        self.assertEqual(len(normalize_hosts(['2001:0DB8:0:0::1', '2001:db8::1'])), 1)
        with self.assertRaises(InventoryError):
            parse_host('@node')

    def test_command_byte_limit_preserves_shell_text(self):
        command = "printf '%s' \"$HOME\" && cat <<'EOF'\n$(literal)\nEOF"
        self.assertEqual(validate_command(command), command)
        self.assertEqual(validate_command('x' * MAX_COMMAND_BYTES), 'x' * MAX_COMMAND_BYTES)
        self.assertEqual(validate_command('é' * (MAX_COMMAND_BYTES // 2)), 'é' * (MAX_COMMAND_BYTES // 2))
        for command in ('x' * (MAX_COMMAND_BYTES + 1), 'é' * (MAX_COMMAND_BYTES // 2 + 1), 'x\x00'):
            with self.assertRaises(ValueError):
                validate_command(command)

    def test_cli_rejects_oversized_command_before_plan(self):
        result = subprocess.run([sys.executable, '-m', 'swassh', 'run', 'x' * (MAX_COMMAND_BYTES + 1),
                                 '-H', 'node', '--plan-only'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('x' * 100, result.stderr)

    def test_config_paths_cannot_expand_or_inject(self):
        for path in ('${HOME}/key', 'a\nIdentityFile /secret', 'a\u0085b', 'x' * 4097):
            for argument in ('known_hosts', 'log_file', 'client_keys'):
                with self.subTest(argument=argument, path=path[:20]), self.assertRaises(ValueError):
                    Options(**{argument: (path,) if argument == 'client_keys' else path})
        root = Path(tempfile.gettempdir())
        text = _config(Host('fe80::1%eth0'), Options(client_keys=(str(root / 'key-%h'),), known_hosts=str(root / 'known-%n')))
        self.assertIn('HostName "fe80::1%%eth0"', text)
        escaped_root = str(root).replace('\\', '\\\\')
        separator = '\\\\' if os.name == 'nt' else '/'
        self.assertIn('IdentityFile "' + escaped_root + separator + 'key-%%h"', text)
        self.assertIn('UserKnownHostsFile "' + escaped_root + separator + 'known-%%n"', text)
        self.assertIn('PasswordAuthentication no', text)
        self.assertIn('PermitLocalCommand no', text)

    def test_invalid_results_fail_at_domain_boundary(self):
        for args in ({'status': 'success'}, {'duration': float('nan')}, {'duration': -1},
                     {'attempts': True}, {'stdout': b'bytes'}, {'exit_code': False}, {'transfer': {}}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                Result(**({'host': Host('node'), 'status': Status.SUCCESS} | args))
        for args in ({'direction': 'other'}, {'backend': 'shell'}, {'bytes_transferred': -1},
                     {'remote_path': '/x\nrm'}, {'local_path': 'x' * 4097}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                TransferReceipt(**({'direction': 'push', 'local_path': '/local', 'remote_path': '/remote'} | args))

    def test_unicode_console_and_csv_spoofing(self):
        self.assertEqual(safe_text('ok\u202eevil\u2028next\x1b[31m'), 'ok?evil?next?[31m')
        for content in ('\ufeff=1+1', '\u200b @cmd', '\t-1', '\x00+2'):
            row = csv_row(Result(Host('a'), Status.SUCCESS, stdout=content))
            self.assertEqual(row['stdout'], "'" + content)
        self.assertEqual(csv_row(Result(Host('a'), Status.SUCCESS, stdout='plain'))['stdout'], 'plain')

    def test_nested_cgroup_limits_apply(self):
        values = {'/proc/meminfo': 'MemAvailable: 1000000 kB', '/proc/self/cgroup': '0::/app/job',
                  '/sys/fs/cgroup/app/job/memory.max': '100000000',
                  '/sys/fs/cgroup/app/job/memory.current': '10000000',
                  '/sys/fs/cgroup/app/memory.max': '50000000',
                  '/sys/fs/cgroup/app/memory.current': '20000000',
                  '/sys/fs/cgroup/memory.max': 'max', '/sys/fs/cgroup/memory.current': '0'}
        def read(path, *args, **kwargs):
            key = path.as_posix()
            if key not in values:
                raise FileNotFoundError(str(path))
            return values[key]
        with patch('swassh.infrastructure.resources.sys.platform', 'linux'), patch.object(Path, 'read_text', read):
            self.assertEqual(_available_memory(), 30000000)
        values['/proc/self/cgroup'] = '0::/../../untrusted'
        with patch('swassh.infrastructure.resources.sys.platform', 'linux'), patch.object(Path, 'read_text', read):
            self.assertEqual(_available_memory(), 1024000000)

    def test_rsync_security_floor(self):
        for banner in ('rsync version 3.0.0', 'rsync version 3.4.4', 'invalid', 'rsync version 2.6.9'):
            self.assertFalse(_modern_rsync(banner), banner)
        self.assertTrue(_modern_rsync('rsync  version 3.5.0  protocol version 32'))
        self.assertTrue(_modern_rsync('rsync version 3.5.1'))


class LocalFilesHardeningTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX local filesystem required')
    def test_audit_rejects_links_and_fifo_without_modifying_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / 'secret'
            secret.write_text('original')
            for kind in ('symlink', 'hardlink', 'fifo'):
                target = root / kind
                if kind == 'symlink':
                    target.symlink_to(secret)
                elif kind == 'hardlink':
                    os.link(secret, target)
                else:
                    os.mkfifo(target)
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    open_private_append(target)
            self.assertEqual(secret.read_text(), 'original')

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions required')
    def test_staging_rejects_shared_writable_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / 'shared'
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            with self.assertRaisesRegex(ValueError, 'shared writable'):
                private_directory(shared)
            link = root / 'link'
            link.symlink_to(shared, target_is_directory=True)
            with self.assertRaises(ValueError):
                private_directory(link)
            private = root / 'private'
            private.mkdir(mode=0o755)
            private_directory(private, tighten=True)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == 'posix', 'POSIX filesystem required')
    def test_gzip_rejects_special_rotation_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                _compress(str(fifo), str(root / 'archive.gz'))
            self.assertEqual(list(root.iterdir()), [fifo])

    def test_spool_batch_rolls_back_all_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReportStore(directory, 1024**2)
            try:
                a = Result(Host('a'), Status.SUCCESS, stdout='A')
                store.append([a])
                before = store.bytes, dict(store.counts)
                with self.assertRaises(sqlite3.IntegrityError):
                    store.append([Result(Host('b'), Status.FAILED, stderr='B'), a])
                self.assertEqual((store.bytes, store.counts), before)
                self.assertEqual([result.host.hostname for result in store._results()], ['a'])
                self.assertEqual(store.db.execute('SELECT sum(count) FROM responses').fetchone()[0], 1)
            finally:
                store.close()

    def test_spool_budget_is_physical_and_transactional(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReportStore(directory, 65536)
            try:
                self.assertLessEqual(store.db.execute('PRAGMA max_page_count').fetchone()[0] * 4096, 65536)
                with self.assertRaises(ValueError):
                    store.append([Result(Host('a'), Status.SUCCESS, stdout='x' * 70000)])
                self.assertEqual(store.bytes, 0)
                self.assertFalse(any(store.counts.values()))
                self.assertFalse(list(store._results()))
                self.assertLessEqual(store.path.stat().st_size, 65536)
            finally:
                store.close()

    def test_failed_spool_initialization_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(sqlite3.Error):
                ReportStore(directory, 1)
            self.assertFalse(list(Path(directory).iterdir()))

    def test_closed_process_store_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            initialize_store(directory, 1024**2, threading.Event())
            store_operation('close')
            with self.assertRaises(RuntimeError):
                store_operation('summary')

    @unittest.skipUnless(os.name == 'posix', 'symlinks require POSIX in CI')
    def test_builders_reject_source_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'src/swassh'
            source.mkdir(parents=True)
            (root / 'pyproject.toml').write_text('[project]\nversion="0.1.0"\n')
            secret = root / 'secret'
            secret.write_text('secret')
            (source / 'leak.py').symlink_to(secret)
            backend = runpy.run_path(str(ROOT / 'build_support/swassh_build.py'))
            for name in ('build_wheel', 'build_sdist'):
                function = backend[name]
                function.__globals__['ROOT'] = root
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'symbolic links'):
                    function(root / 'dist')
            package = runpy.run_path(str(ROOT / 'scripts/package.py'))
            package['main'].__globals__['ROOT'] = root
            with self.assertRaisesRegex(ValueError, 'symbolic link'):
                package['main']()


class AsyncHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_audit_metadata_cannot_be_forged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit'
            async with AuditTrail(str(path), 'actual') as trail:
                await trail.emit('real', {'event': 'forged', 'run_id': 'forged', 'pid': -1, 'timestamp': 'forged'})
            record = json.loads(path.read_text())
            self.assertEqual((record['event'], record['run_id'], record['pid']), ('real', 'actual', os.getpid()))
            self.assertNotEqual(record['timestamp'], 'forged')

    async def test_internal_transport_cancel_becomes_result(self):
        class Transport:
            async def execute(self, host, command):
                raise asyncio.CancelledError()
        report = await asyncio.wait_for(Swarm(transport=Transport()).run(['a', 'b'], 'x'), 2)
        self.assertEqual(report.counts['error'], 1)
        self.assertEqual(report.counts['skipped'], 1)

    async def test_self_cancelled_worker_cannot_hang_fleet(self):
        class Transport:
            async def execute(self, host, command):
                asyncio.current_task().cancel()
                await asyncio.sleep(0)
        with self.assertRaisesRegex(RuntimeError, 'workers ended'):
            await asyncio.wait_for(Swarm(transport=Transport()).run(['a', 'b'], 'x'), 2)
        self.assertFalse([task for task in asyncio.all_tasks() if task.get_name().startswith('swassh-worker')])

    async def test_resource_plan_is_pinned_once(self):
        class Transport:
            async def execute(self, host, command):
                return Result(host, Status.SUCCESS)
        service = Swarm(transport=Transport())
        plan = ResourcePlan(32, 1, 128 * 1024**2, 9 * 1024**2, 20)
        with patch.object(service, '_planner', return_value=plan) as planner:
            with tempfile.TemporaryDirectory() as directory:
                summary = await service.run_to_file(['a', 'b'], 'x', Path(directory) / 'report.json')
        self.assertEqual(planner.call_count, 1)
        self.assertEqual(summary.plan, plan)

    async def test_cleanup_survives_repeated_cancellation(self):
        finished = asyncio.Event()
        async def operation():
            await asyncio.sleep(0.05)
            finished.set()
            return 7
        async def cleanup():
            task = asyncio.create_task(operation())
            return await finish_task(task)
        closing = asyncio.create_task(cleanup())
        await asyncio.sleep(0.005)
        closing.cancel()
        await asyncio.sleep(0.005)
        closing.cancel()
        self.assertEqual(await closing, 7)
        self.assertTrue(finished.is_set())

    @unittest.skipUnless(os.name == 'posix', 'POSIX process signals required')
    async def test_report_deadline_kills_stopped_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            writer = ProcessReportWriter(directory, 1024**2, operation_timeout=5)
            await writer.__aenter__()
            pid = writer.worker_pid
            writer.operation_timeout = 0.1
            os.kill(pid, signal.SIGSTOP)
            started = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    await writer.summary()
            finally:
                await writer.__aexit__(None, None, None)
            self.assertLess(time.monotonic() - started, 8)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertFalse(list(Path(directory).iterdir()))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process group verification required')
    async def test_reaped_native_leader_cannot_leave_pipe_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / 'pid'
            ready = root / 'ready'
            operation_ready = root / 'operation-ready'
            import shutil
            shell, sleeper = shutil.which('sh'), shutil.which('sleep')
            self.assertIsNotNone(shell, 'the Linux native shell fixture is required')
            self.assertIsNotNone(sleeper, 'the Linux native sleep fixture is required')
            ignored = root / 'ignored-signals'
            rendezvous = root / 'rendezvous'
            os.mkfifo(rendezvous, 0o600)
            # Exercise native descendants, rather than budgeting two unrelated
            # CPython/coverage bootstraps inside the original 0.4-second limit.
            # Static shell programs receive paths as positional arguments.
            # FIFO readiness blocks instead of competing with the child for
            # a CPU. The same deadline, signal and descendant checks apply.
            child = """trap '' TERM
while IFS=: read -r key value; do
    if [ "$key" = SigIgn ]; then printf '%s' "$value" > "$3"; fi
done < "/proc/$$/status"
printf ready > "$1"
printf 'ready\n' > "$4"
exec "$2" 30
"""
            parent = """"$1" -c "$2" swassh-descendant "$3" "$4" "$5" "$7" &
descendant=$!
printf '%s' "$descendant" > "$6"
IFS= read -r state < "$7"
[ "$state" = ready ]
printf prepared > "$8"
IFS= read -r release
[ "$release" = release ]
"""
            from swassh.infrastructure.native_budget import native_invocation_budget
            options = Options(ssh_executable=sys.executable, budget_dir=str(root / 'budget'))
            transport = NativeFileTransport(options, TransferSettings(timeout=0.4),
                FileTransfer(TransferDirection.PULL, str(root), '/remote'), 100)
            # This test witnesses cleanup of an already-created native group.
            # A readiness barrier separates unrelated guardian interpreter startup
            # from that witness. The real 0.4s transfer deadline still measures
            # native exit, descendant destruction and pipe drainage. Cold startup
            # remains inside the deadline in its separate unmodified regression.
            from swassh.infrastructure import transfers
            from swassh.infrastructure.ssh import _cleanup_process
            argv = [shell, '-c', parent, 'swassh-leader', shell, child,
                str(ready), sleeper, str(ignored), str(pidfile), str(rendezvous), str(operation_ready)]
            async with native_invocation_budget(options):
                prepared = None
                try:
                    async with asyncio.timeout(4):
                        prepared = await transfers.launch_native(*argv, options=options,
                            bandwidth=transport.bandwidth_kib, max_native_seconds=4,
                            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE, start_new_session=True, limit=65536)
                        while not operation_ready.is_file():
                            if prepared.returncode is not None:
                                self.fail('native preparation ended before its readiness witness')
                            await asyncio.sleep(0.005)
                    self.assertTrue(ready.is_file(), 'native descendant readiness is required')
                    self.assertTrue(pidfile.is_file(), 'native descendant identity is required')
                    self.assertTrue(ignored.is_file(), 'the native signal-mask witness is required')
                    self.assertIsNone(prepared.returncode)
                    async def prepared_launch(*actual_argv, **kwargs):
                        self.assertEqual(actual_argv, tuple(argv))
                        self.assertEqual(kwargs['options'], options)
                        self.assertEqual(kwargs['stdin'], asyncio.subprocess.DEVNULL)
                        self.assertEqual(kwargs['stdout'], asyncio.subprocess.PIPE)
                        self.assertEqual(kwargs['stderr'], asyncio.subprocess.PIPE)
                        # Release only this fixture's native leader after _run's
                        # original timeout has begun, then hand it the real guard.
                        prepared.stdin.write(b'release\n')
                        await prepared.stdin.drain()
                        prepared.stdin.close()
                        return prepared
                    with patch.object(transfers, 'launch_native', prepared_launch):
                        result = await transport._run(argv, Host('node'))
                finally:
                    # Preparation failures keep the same owner until cleanup;
                    # a completed _run already released this private guardian.
                    if prepared is not None and getattr(prepared, '_swassh_guardian', None):
                        await _cleanup_process(prepared, [])
            self.assertEqual(result.status, Status.SUCCESS, result)
            self.assertEqual(ready.read_text(), "ready")
            self.assertTrue(int(ignored.read_text().strip(), 16) & (1 << (signal.SIGTERM - 1)))
            pid = int(pidfile.read_text())
            proc_pid_matches = int(Path('/proc/self/stat').read_text().split()[0]) == os.getpid()
            for _ in range(200):
                try:
                    os.kill(pid, 0)  # Query the PID in our actual namespace first.
                except ProcessLookupError:
                    break
                if proc_pid_matches:
                    status = Path(f'/proc/{pid}/stat')
                    try:
                        if status.read_text().split()[2] == 'Z':
                            break
                    except FileNotFoundError:
                        break
                await asyncio.sleep(0.01)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.fail('native descendant survived cleanup')

    async def test_hidden_native_download_counts_toward_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'data'
            stage.touch()
            code = f'import pathlib,time; pathlib.Path({str(root / ".data.random")!r}).write_bytes(b"x"*2000000); time.sleep(10)'
            transport = NativeFileTransport(Options(ssh_executable=sys.executable), TransferSettings(max_file_mib=1),
                FileTransfer(TransferDirection.PULL, str(root), '/remote'), 100)
            result = await transport._run([sys.executable, '-c', code], Host('node'), watched=stage)
            self.assertEqual(result.status, Status.ERROR)
            self.assertIn('budget', result.error)


    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process group verification required')
    async def test_native_cleanup_fixture_does_not_depend_on_python_startup(self):
        """Unrelated interpreter startup cannot define a process cleanup scenario."""
        execute = NativeFileTransport._run
        calls = []
        async def slow_interpreter(transport, argv, host, **kwargs):
            calls.append(tuple(argv))
            if argv[:2] == [sys.executable, '-c']:
                # Reproduce a fixture interpreter's delayed initialization,
                # without moving or extending the actual transfer deadline.
                argv = [*argv[:2], 'import time; time.sleep(0.6)\n' + argv[2], *argv[3:]]
            return await execute(transport, argv, host, **kwargs)
        with patch.object(NativeFileTransport, '_run', slow_interpreter):
            await self.test_reaped_native_leader_cannot_leave_pipe_child()
        self.assertEqual(len(calls), 1)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process group verification required')
    async def test_native_cleanup_fixture_keeps_the_real_transfer_deadline(self):
        """A genuinely running native command must still expire at 0.4 seconds."""
        import shutil
        sleeper = shutil.which('sleep')
        self.assertIsNotNone(sleeper, 'the Linux native sleep fixture is required')
        with tempfile.TemporaryDirectory() as directory:
            transport = NativeFileTransport(Options(ssh_executable=sys.executable), TransferSettings(timeout=0.4),
                FileTransfer(TransferDirection.PULL, directory, '/remote'), 100)
            result = await asyncio.wait_for(transport._run([sleeper, '30'], Host('node')), 4)
            self.assertEqual(result.status, Status.TIMEOUT, result)
            self.assertEqual(result.error, 'transfer deadline exceeded; remote state may be partial')
            self.assertLess(result.duration, 4)


    async def test_transfer_deadline_includes_delayed_native_startup(self):
        """A prepared fixture must not exempt a cold guardian from the deadline."""
        from swassh.infrastructure import transfers
        actual = transfers.launch_native
        entered, native_started = [], []
        async def delayed(*args, **kwargs):
            entered.append(True)
            await asyncio.sleep(0.6)
            native_started.append(True)
            return await actual(*args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            transport = NativeFileTransport(Options(ssh_executable=sys.executable, budget_dir=str(Path(directory)/'budget')),
                TransferSettings(timeout=0.4), FileTransfer(TransferDirection.PULL, directory, '/remote'), 100)
            with patch.object(transfers, 'launch_native', delayed):
                result = await asyncio.wait_for(transport._run([sys.executable, '-c', 'pass'], Host('node')), 4)
            self.assertEqual(result.status, Status.TIMEOUT, result)
            self.assertEqual(result.error, 'transfer deadline exceeded; remote state may be partial')
            self.assertEqual(entered, [True])
            self.assertEqual(native_started, [])
            self.assertLess(result.duration, 4)



class WorkflowHardeningTests(unittest.TestCase):
    def test_external_actions_are_pinned_and_credentials_not_persisted(self):
        import re
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            content = path.read_text()
            for action in re.findall(r'uses:\s+(\S+)', content):
                if not action.startswith('./'):
                    self.assertRegex(action, r'^[\w/-]+@[a-f0-9]{40}$')
            self.assertIn('timeout-minutes:', content)
            if 'actions/checkout@' in content:
                self.assertIn('persist-credentials: false', content)
