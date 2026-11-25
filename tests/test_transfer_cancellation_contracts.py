"""Cancellation owns each snapshot/hash thread until staging may be removed."""
import asyncio
from contextlib import contextmanager
from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import FileTransfer,Host,Options,Result,Status,TransferDirection,TransferSettings
from swassh.infrastructure import transfers
from swassh.infrastructure import windows


class TransferCancellationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_descriptor_watchdog_keeps_size_and_hardlink_refusals_on_either_host(self):
        # Memory-only directory-fd routing exercises the POSIX strategy even
        # on Windows. Real per-entry descriptors still require fstat + close.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for outcome in ('regular', 'oversize', 'hardlink'):
                stage = root / outcome
                stage.mkdir(mode=0o700)
                watched = stage / 'data'
                if outcome == 'hardlink':
                    source = root / 'linked-source'
                    source.write_bytes(b'synthetic')
                    watched.hardlink_to(source)
                elif outcome == 'oversize':
                    with watched.open('wb') as stream:
                        stream.truncate(1024 ** 2 + 1)
                else:
                    watched.write_bytes(b'synthetic')
                client = self.client(root, pull=True)
                scanned = asyncio.Event()
                opened, closed = [], []
                def open_entry(name, flags):
                    self.assertEqual(name, 'data')
                    descriptor = os.open(watched, flags)
                    opened.append(descriptor)
                    return descriptor
                parent = SimpleNamespace(fd=41, path=stage, open=open_entry)
                port = SimpleNamespace(**vars(os))
                port.name = 'posix'
                real_scan = os.scandir
                @contextmanager
                def scan(descriptor):
                    self.assertEqual(descriptor, 41)
                    try:
                        with real_scan(stage) as entries:
                            yield entries
                    finally:
                        scanned.set()
                port.scandir = scan
                def close(descriptor):
                    closed.append(descriptor)
                    os.close(descriptor)
                port.close = close
                process = SimpleNamespace(stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=None)
                process.stdout.feed_eof()
                process.stderr.feed_eof()
                async def wait():
                    await scanned.wait()
                    process.returncode = 0
                    return 0
                process.wait = wait
                async def cleanup(native, tasks):
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    return {}
                with self.subTest(outcome=outcome), patch.object(transfers, 'os', port), \
                        patch.object(transfers, 'PinnedDirectory', return_value=nullcontext(parent)), \
                        patch.object(transfers, 'launch_native', new_callable=AsyncMock, return_value=process) as launch, \
                        patch.object(transfers, '_cleanup_process', side_effect=cleanup):
                    result = await asyncio.wait_for(client._run(['synthetic-client'], Host('one'), watched=watched), 3)
                self.assertEqual(result.status, Status.SUCCESS if outcome == 'regular' else Status.ERROR)
                self.assertTrue(scanned.is_set())
                self.assertEqual(len(opened), 1)
                self.assertEqual(closed, opened)
                launch.assert_awaited_once()

    async def test_windows_watchdog_queries_full_metadata_without_opening_live_native_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / 'private-stage'
            stage.mkdir(mode=0o700)
            watched = stage / 'data'
            watched.write_bytes(b'synthetic transfer')
            client = self.client(root, pull=True)
            scanned = asyncio.Event()
            port = SimpleNamespace(**vars(os))
            port.name = 'nt'
            parent = SimpleNamespace(fd=None, path=stage,
                open=Mock(side_effect=PermissionError('native writer denies live data readers')))
            process = SimpleNamespace(stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=None)
            process.stdout.feed_eof()
            process.stderr.feed_eof()
            async def wait():
                await scanned.wait()
                process.returncode = 0
                return 0
            process.wait = wait
            async def cleanup(native, tasks):
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                return {}
            def metadata(path):
                self.assertEqual(path, watched)
                scanned.set()
                return len(b'synthetic transfer')
            with patch.object(transfers, 'os', port), \
                    patch.object(transfers, 'PinnedDirectory', return_value=nullcontext(parent)), \
                    patch.object(windows, 'regular_file_size', side_effect=metadata, create=True) as inspect, \
                    patch.object(transfers, 'launch_native', new_callable=AsyncMock, return_value=process), \
                    patch.object(transfers, '_cleanup_process', side_effect=cleanup):
                result = await asyncio.wait_for(client._run(['synthetic-client'], Host('one'), watched=watched), 3)
            self.assertEqual(result.status, Status.SUCCESS)
            self.assertEqual(result.exit_code, 0)
            inspect.assert_called_once_with(watched)
            parent.open.assert_not_called()

    def client(self,root,*,pull=False,verify=False):
        source=root/'source';source.write_bytes(b'synthetic transfer')
        options=Options();ssh=SimpleNamespace(executable='synthetic-ssh',profiles=SimpleNamespace(for_host=lambda host:options),
            execute=AsyncMock(),_pacer=SimpleNamespace(acquire=AsyncMock()))
        request=FileTransfer(TransferDirection.PULL if pull else TransferDirection.PUSH,
            str(root/'downloads' if pull else source),'/remote')
        with patch.object(transfers,'SSHTransport',return_value=ssh),patch.object(transfers.shutil,'which',return_value=None):
            client=transfers.NativeFileTransport(options,TransferSettings(verify_sha256=verify,max_file_mib=1),request,1)
        client.sftp='synthetic-sftp';return client

    def blocked_thread_port(self,predicate):
        entered,release=threading.Event(),threading.Event();original=asyncio.to_thread
        async def to_thread(function,*args,**kwargs):
            if not predicate(function):return await original(function,*args,**kwargs)
            def owned():
                entered.set()
                if not release.wait(3):raise TimeoutError('synthetic test release was not delivered')
                return function(*args,**kwargs)
            return await original(owned)
        port=SimpleNamespace(**vars(asyncio));port.to_thread=to_thread
        return port,entered,release

    async def test_cancelled_push_snapshot_or_hash_keeps_directory_until_thread_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            for operation in ('copy','hash'):
                client=self.client(Path(directory),verify=operation=='hash')
                port,entered,release=self.blocked_thread_port(lambda function:function.__name__==('copy' if operation=='copy' else 'digest_file'))
                with patch.object(transfers,'asyncio',port):
                    task=asyncio.create_task(client.__aenter__())
                    try:
                        self.assertTrue(await asyncio.to_thread(entered.wait,3))
                        staging=Path(client._directory.name)
                        task.cancel();await asyncio.sleep(0)
                        self.assertFalse(task.done());self.assertTrue(staging.exists())
                        release.set()
                        with self.assertRaises(asyncio.CancelledError):await task
                        self.assertIsNone(client._directory);self.assertFalse(staging.exists())
                    finally:
                        release.set();await asyncio.gather(task,return_exceptions=True)

    async def test_cancelled_pull_verification_never_publishes_or_replays_remote_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);client=self.client(root,pull=True,verify=True);payload=b'synthetic download'
            digest=hashlib.sha256(payload).hexdigest()
            client.ssh.execute.side_effect=[Result(Host('one'),Status.SUCCESS,stdout='sha256sum'),
                Result(Host('one'),Status.SUCCESS,stdout=digest+'  /remote\n')]
            paths=[]
            async def download(argv,host,*,watched):
                watched.write_bytes(payload);paths.append(watched);return Result(host,Status.SUCCESS)
            port,entered,release=self.blocked_thread_port(lambda function:function.__name__=='digest_file')
            async with client:
                with patch.object(client,'_run',side_effect=download),patch.object(transfers,'asyncio',port):
                    task=asyncio.create_task(client.transfer(Host('one')))
                    try:
                        self.assertTrue(await asyncio.to_thread(entered.wait,3));stage=paths[0]
                        task.cancel();await asyncio.sleep(0)
                        self.assertFalse(task.done());self.assertTrue(stage.exists());release.set()
                        with self.assertRaises(asyncio.CancelledError):await task
                        self.assertFalse(stage.parent.exists());self.assertEqual(client.ssh.execute.await_count,2)
                        self.assertFalse(list(client.local.rglob('remote')))
                    finally:
                        release.set();await asyncio.gather(task,return_exceptions=True)

    async def test_download_watchdog_refuses_oversize_directories_and_hardlinked_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for failure in ('size','directory','hardlink'):
                folder=root/failure;folder.mkdir();watched=folder/'data'
                if failure=='directory':watched.mkdir()
                elif failure=='hardlink':
                    source=root/'hardlink-source';source.write_bytes(b'synthetic');watched.hardlink_to(source)
                else:
                    with watched.open('wb') as stream:stream.truncate(1024**2+1)
                client=self.client(root,pull=True)
                process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=None)
                process.stdout.feed_eof();process.stderr.feed_eof()
                async def wait():await asyncio.Future()
                process.wait=wait
                failures=[]
                async def cleanup(native,tasks):
                    for task in tasks:
                        if task.done() and not task.cancelled() and task.exception() is not None:failures.append(task.exception())
                        task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True);return {}
                with patch.object(transfers,'launch_native',new_callable=AsyncMock,return_value=process) as launch,\
                        patch.object(transfers,'_cleanup_process',side_effect=cleanup):
                    result=await asyncio.wait_for(client._run(['synthetic-client'],Host('one'),watched=watched),3)
                self.assertEqual(result.status,Status.ERROR);self.assertEqual(result.error,'transfer I/O or file budget error')
                self.assertIsNone(result.exit_code)
                launch.assert_awaited_once();self.assertEqual(len(failures),1)
                if failure=='size':self.assertEqual(str(failures[0]),'download exceeds file budget')
                elif failure=='hardlink':self.assertEqual(str(failures[0]),'download staging contains a link or special entry')
                else:self.assertIsInstance(failures[0],(OSError,ValueError))

    async def test_download_watchdog_accepts_a_real_private_file_after_a_complete_scan(self):
        # A held native port must survive at least one real filesystem scan.
        # Full handle metadata, including links, must decide safety.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'staging';folder.mkdir(mode=0o700)
            watched=folder/'data';watched.write_bytes(b'synthetic download')
            client=self.client(root,pull=True);scanned=asyncio.Event()
            original_scan=os.scandir;port=SimpleNamespace(**vars(os))
            @contextmanager
            def scan(path):
                with original_scan(path) as entries:
                    yield entries
                scanned.set()
            port.scandir=scan
            process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=None)
            process.stdout.feed_eof();process.stderr.feed_eof()
            async def wait():
                await scanned.wait();process.returncode=0;return 0
            process.wait=wait
            async def cleanup(native,tasks):
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True);return {}
            with patch.object(transfers,'os',port),\
                    patch.object(transfers,'launch_native',new_callable=AsyncMock,return_value=process) as launch,\
                    patch.object(transfers,'_cleanup_process',side_effect=cleanup):
                result=await asyncio.wait_for(client._run(['synthetic-client'],Host('one'),watched=watched),3)
            launch.assert_awaited_once();self.assertEqual(result.status,Status.SUCCESS)
            self.assertEqual(result.exit_code,0);self.assertIsNone(result.error)
            self.assertTrue(scanned.is_set());self.assertEqual(watched.read_bytes(),b'synthetic download')

    async def test_snapshot_owner_restoration_uses_only_opened_source_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);client=self.client(root);source_info=client.local.stat()
            original=Path.stat;port=SimpleNamespace(**vars(os));port.chown=Mock()
            def metadata(path,*args,**kwargs):
                if path.name=='source' and path.parent.name.startswith('swassh-transfer-'):
                    return SimpleNamespace(st_uid=source_info.st_uid+1,st_gid=source_info.st_gid)
                return original(path,*args,**kwargs)
            with patch.object(transfers,'os',port),patch.object(Path,'stat',metadata):
                async with client:
                    port.chown.assert_called_once_with(Path(client.source),source_info.st_uid,source_info.st_gid)
                    self.assertEqual(Path(client.source).read_bytes(),b'synthetic transfer')

    async def test_snapshot_with_matching_ownership_never_requests_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.client(Path(directory));port=SimpleNamespace(**vars(os));port.chown=Mock()
            with patch.object(transfers,'os',port):
                async with client:
                    port.chown.assert_not_called()
                    self.assertEqual(Path(client.source).read_bytes(),b'synthetic transfer')

    async def test_watchdog_rejects_special_descriptor_metadata_and_always_closes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);stage=root/'staging';stage.mkdir(mode=0o700)
            watched=stage/'data';watched.write_bytes(b'synthetic')
            client=self.client(root,pull=True);port=SimpleNamespace(**vars(os));opened=[];failures=[]
            # Exercise the descriptor strategy on either host; a separate test
            # above requires the Windows metadata strategy without data reads.
            port.name='posix'
            original=os.fstat
            def metadata(descriptor):
                value=original(descriptor);opened.append(descriptor)
                return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600,st_nlink=value.st_nlink,st_size=value.st_size)
            port.fstat=metadata;port.close=Mock(wraps=os.close)
            process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=None)
            process.stdout.feed_eof();process.stderr.feed_eof()
            async def wait():await asyncio.Future()
            process.wait=wait
            async def cleanup(native,tasks):
                for task in tasks:
                    if task.done() and not task.cancelled() and task.exception() is not None:failures.append(task.exception())
                    task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True);return {}
            with patch.object(transfers,'os',port),patch.object(transfers,'launch_native',return_value=process) as launch,\
                    patch.object(transfers,'_cleanup_process',side_effect=cleanup):
                result=await asyncio.wait_for(client._run(['synthetic-client'],Host('one'),watched=watched),3)
            self.assertEqual(result.status,Status.ERROR);self.assertEqual(len(opened),1)
            port.close.assert_called_once_with(opened[0]);launch.assert_awaited_once()
            self.assertEqual([str(error) for error in failures],['download staging contains a link or special entry'])
            self.assertEqual(watched.read_bytes(),b'synthetic')


if __name__=='__main__':unittest.main()
