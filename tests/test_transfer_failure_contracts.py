"""Private staging and native transfer ports under deterministic local faults."""
import asyncio
import hashlib
import os
import stat
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock,Mock,patch

from swassh import FileTransfer,Host,Options,Result,Status,TransferDirection,TransferSettings
from swassh.infrastructure import integrity,transfers
from swassh.infrastructure.preview import PreviewBuffer


class StagingFailureIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def transport(self,request,settings=None):
        options=Options();ssh=SimpleNamespace(profiles=SimpleNamespace(for_host=lambda host:options))
        with patch.object(transfers,'SSHTransport',return_value=ssh),patch.object(transfers.shutil,'which',return_value=None):
            return transfers.NativeFileTransport(options,settings or TransferSettings(),request,1)

    async def test_directory_shape_hash_budget_and_local_version_failure_clean_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'folder';folder.mkdir();file=root/'file';file.write_bytes(b'synthetic')
            cases=((folder,'/remote',TransferSettings(),'directory destination'),
                   (folder,'/remote/',TransferSettings(verify_sha256=True),'single files'),
                   (file,'/remote/',TransferSettings(),'file destination'))
            for source,remote,settings,message in cases:
                transport=self.transport(FileTransfer(TransferDirection.PUSH,str(source),remote),settings)
                with self.assertRaisesRegex(ValueError,message):await transport.__aenter__()
                self.assertIsNone(transport._directory)
            file.write_bytes(b'x'*(1024**2+1))
            transport=self.transport(FileTransfer(TransferDirection.PUSH,str(file),'/remote'),TransferSettings(max_file_mib=1))
            with self.assertRaisesRegex(ValueError,'source exceeds'):await transport.__aenter__()
            self.assertIsNone(transport._directory)
            for text,status in (('rsync version 3.4.0',Status.SUCCESS),('rsync version 3.5.1',Status.FAILED),('rsync version 3.5.1',Status.SUCCESS)):
                transport=self.transport(FileTransfer(TransferDirection.PUSH,str(folder)+'/', '/remote/'))
                transport.rsync='synthetic-rsync'
                with patch.object(transport,'_run',return_value=Result(Host('localhost'),status,stdout=text,exit_code=0 if status==Status.SUCCESS else 1)):
                    async with transport as opened:
                        self.assertTrue(opened.is_directory);self.assertTrue(opened.source.endswith('/'))
                        self.assertEqual(opened.rsync,'synthetic-rsync' if status==Status.SUCCESS and '3.5.1' in text else None)
                self.assertIsNone(transport._directory)

    async def test_metadata_change_and_growth_while_snapshotting_refuse_partial_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'source';file.write_bytes(b'x'*(1024**2+1))
            original_lstat=Path.lstat;original_fstat=os.fstat
            for failure in ('before-copy','during-copy','growing-file'):
                transport=self.transport(FileTransfer(TransferDirection.PUSH,str(file),'/remote'),TransferSettings(max_file_mib=2 if failure!='growing-file' else 1))
                calls=[]
                def metadata(fd):
                    value=original_fstat(fd);calls.append(fd)
                    if failure=='growing-file':return SimpleNamespace(**{name:getattr(value,name) for name in dir(value) if name.startswith('st_') and name!='st_size'},st_size=0)
                    target=(2 if os.name=='nt' else 1) if failure=='before-copy' else (3 if os.name=='nt' else 2)
                    if len(calls)==target:
                        return SimpleNamespace(**{name:getattr(value,name) for name in dir(value) if name.startswith('st_') and name!='st_mtime_ns'},st_mtime_ns=value.st_mtime_ns+1)
                    return value
                def lstat(path,*args,**kwargs):
                    value=original_lstat(path,*args,**kwargs)
                    if failure=='growing-file' and path==file:
                        return SimpleNamespace(**{name:getattr(value,name) for name in dir(value) if name.startswith('st_') and name!='st_size'},st_size=0)
                    return value
                # Restrict the metadata injector to the transfer module's OS
                # port; directory pinning continues to use real kernel data.
                fake_os=SimpleNamespace(**vars(os));fake_os.fstat=metadata
                with patch.object(transfers,'os',fake_os),patch.object(Path,'lstat',lstat),self.assertRaisesRegex(ValueError,'snapshot|budget'):
                    await transport.__aenter__()
                self.assertIsNone(transport._directory)

    async def test_native_run_exit_classes_preview_invalidity_and_private_environment(self):
        request=FileTransfer(TransferDirection.PULL,'synthetic-local','/remote')
        for code,preview in ((0,False),(7,False),(125,False),(0,True)):
            transport=self.transport(request)
            process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=None)
            process.stdout.feed_data(b'invalid itemisation\n' if preview else b'synthetic output');process.stdout.feed_eof();process.stderr.feed_eof()
            async def wait():await asyncio.sleep(0);process.returncode=code;return code
            process.wait=wait
            async def cleanup(native,tasks):
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                return {'admission_wait_seconds':1,'native_seconds':2}
            with patch.object(transfers.Authentication,'environment',return_value={'PATH':'synthetic','RSYNC_PRIVATE':'synthetic'}),patch.object(transfers,'launch_native',return_value=process) as launch,patch.object(transfers,'_cleanup_process',side_effect=cleanup):
                result=await transport._run(['synthetic','--dry-run' if preview else '--version'],Host('one'))
            self.assertEqual(result.status,Status.ERROR if code==125 or preview else Status.SUCCESS if code==0 else Status.FAILED)
            self.assertNotIn('RSYNC_PRIVATE',launch.call_args.kwargs['env'])
            self.assertEqual(launch.call_args.kwargs['connected'],preview)
            self.assertEqual((transport._admission_wait_seconds,transport._native_seconds),(1,2))

    async def test_c1_batch_controls_and_root_pull_are_refused_before_staging_use(self):
        for value in ('\x7f','\x85','\x9f'):
            with self.subTest(control=ord(value)),self.assertRaisesRegex(ValueError,'control characters'):
                transfers._batch_quote('/literal'+value)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).anchor
            transport=self.transport(FileTransfer(TransferDirection.PULL,root,'/remote/file'))
            with self.assertRaisesRegex(ValueError,'filesystem root'):await transport.__aenter__()
            self.assertIsNone(transport._directory)
            await transport.__aexit__(None,None,None)
            self.assertIsNone(transport._directory)

    async def test_opened_source_metadata_change_is_rejected_before_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.write_bytes(b'immutable synthetic source')
            transport=self.transport(FileTransfer(TransferDirection.PUSH,str(source),'/remote/file'))
            port=SimpleNamespace(**vars(os));port.name='nt';opened=[];closed=[]
            original_fstat=os.fstat;original_close=os.close
            def acquire(path,flags):
                descriptor=os.open(path,flags);opened.append(descriptor);return descriptor
            def metadata(descriptor):
                value=original_fstat(descriptor)
                return SimpleNamespace(**{**{key:getattr(value,key) for key in dir(value) if key.startswith('st_')},
                    'st_ino':value.st_ino+1}) if descriptor in opened else value
            def close(descriptor):closed.append(descriptor);return original_close(descriptor)
            port.fstat=metadata;port.close=close
            with patch.object(transfers,'os',port),patch('swassh.infrastructure.windows.open_file_without_reparse',side_effect=acquire),\
                    self.assertRaisesRegex(ValueError,'before metadata acquisition'):
                await transport.__aenter__()
            self.assertEqual(len(opened),1);self.assertIn(opened[0],closed)
            self.assertIsNone(transport._directory);self.assertEqual(source.read_bytes(),b'immutable synthetic source')

    async def test_snapshot_refuses_a_source_replaced_with_a_special_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.write_bytes(b'original')
            transport=self.transport(FileTransfer(TransferDirection.PUSH,str(source),'/remote/file'))
            original=os.fstat;port=SimpleNamespace(**vars(os));port.name='posix'
            def metadata(descriptor):
                value=original(descriptor)
                return SimpleNamespace(**{**{key:getattr(value,key) for key in dir(value) if key.startswith('st_')},
                    'st_mode':stat.S_IFIFO | 0o600})
            port.fstat=metadata
            with patch.object(transfers,'os',port),self.assertRaisesRegex(ValueError,'source changed before snapshot'):
                await transport.__aenter__()
            self.assertIsNone(transport._directory);self.assertEqual(source.read_bytes(),b'original')

    async def test_initial_special_entry_is_refused_without_opening_it(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';source.write_bytes(b'original');original=Path.lstat
            transport=self.transport(FileTransfer(TransferDirection.PUSH,str(source),'/remote/file'))
            def metadata(path,*args,**kwargs):
                value=original(path,*args,**kwargs)
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o700) if path==source else value
            with patch.object(Path,'lstat',metadata),self.assertRaisesRegex(ValueError,'regular file or directory'):
                await transport.__aenter__()
            self.assertIsNone(transport._directory);self.assertEqual(source.read_bytes(),b'original')

    async def test_posix_backend_discovery_is_separate_from_native_ssh_construction(self):
        # A policy port exposes POSIX discovery; no native process or file opens.
        port=SimpleNamespace(**vars(os));port.name='posix';ssh=Mock()
        with patch.object(transfers,'os',port),patch.object(transfers,'SSHTransport',return_value=ssh) as construct,\
                patch.object(transfers.shutil,'which',side_effect=lambda name:'located-'+name) as locate:
            client=transfers.NativeFileTransport(Options(),TransferSettings(),
                FileTransfer(TransferDirection.PUSH,'synthetic','/remote/file'),16)
        self.assertEqual(client.rsync,'located-rsync');self.assertEqual(client.sftp,'located-sftp')
        self.assertEqual([call.args[0] for call in locate.call_args_list],['rsync','sftp']);construct.assert_called_once()

    async def test_valid_preview_itemisation_is_not_reported_as_a_protocol_failure(self):
        transport=self.transport(FileTransfer(TransferDirection.PULL,'unused','/remote/file'))
        process=SimpleNamespace(stdout=asyncio.StreamReader(),stderr=asyncio.StreamReader(),returncode=0)
        process.stdout.feed_data(b'SWASSH:>f+++++++++\n');process.stdout.feed_eof();process.stderr.feed_eof()
        process.wait=AsyncMock(return_value=0)
        async def cleanup(native,tasks):
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True);return {}
        with patch.object(transfers,'launch_native',return_value=process) as launch,\
                patch.object(transfers,'_cleanup_process',side_effect=cleanup):
            result=await transport._run(['synthetic','--dry-run'],Host('one'))
        self.assertEqual(result.status,Status.SUCCESS);self.assertIsNone(result.error)
        self.assertEqual(result.stdout,'preview only: added=1 changed=0 deleted=0');launch.assert_awaited_once()


class IntegrityBoundaryTests(unittest.TestCase):
    def test_remote_hash_tool_and_response_limits_are_checked_before_parsing(self):
        output='a'*64+'  '+'p'*(8192-66)
        self.assertEqual(len(output),8192);self.assertEqual(integrity.parse_hash('sha256sum',output),'a'*64)
        for tool,response in (('unapproved',output),('sha256sum',output+'p')):
            with self.subTest(tool=tool,size=len(response)),self.assertRaisesRegex(ValueError,'invalid remote hash response'):
                integrity.parse_hash(tool,response)

    def test_special_descriptor_metadata_is_refused_without_hashing_file_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source';path.write_bytes(b'unchanged')
            port=SimpleNamespace(**vars(os));original=os.fstat
            def metadata(descriptor):
                value=original(descriptor)
                return SimpleNamespace(st_mode=stat.S_IFIFO|0o600,st_nlink=value.st_nlink,st_size=value.st_size)
            port.fstat=metadata
            with patch.object(integrity,'os',port),patch.object(integrity.hashlib,'sha256') as digest,\
                    self.assertRaisesRegex(ValueError,'bounded private regular file'):integrity.digest_file(path,1024)
            digest.assert_not_called();self.assertEqual(path.read_bytes(),b'unchanged')

    def test_hash_bounds_growth_and_metadata_changes_reject_unstable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'source';data=b'synthetic hash data';file.write_bytes(data)
            self.assertEqual(integrity.digest_file(file,len(data)),hashlib.sha256(data).hexdigest())
            with self.assertRaisesRegex(ValueError,'bounded'):integrity.digest_file(file,len(data)-1)
            original_fstat=os.fstat
            for failure in ('growth','change','hardlink'):
                seen=[]
                def metadata(fd):
                    value=original_fstat(fd);seen.append(fd)
                    overrides={'st_size':0} if failure=='growth' else {'st_nlink':2} if failure=='hardlink' else {'st_ino':value.st_ino+int(len(seen)>1)}
                    return SimpleNamespace(**{**{name:getattr(value,name) for name in dir(value) if name.startswith('st_')},**overrides})
                fake_os=SimpleNamespace(**vars(os));fake_os.fstat=metadata
                with patch.object(integrity,'os',fake_os),self.assertRaisesRegex(ValueError,'budget|changed|bounded'):
                    integrity.digest_file(file,1 if failure=='growth' else len(data))


class PreviewBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_itemisation_fragmentation_oversize_empty_and_unknown_records(self):
        for chunks,expected,invalid in (((b'SWASSH:>f+++++++++\nSWASSH:*deleting  \n',),(1,0,1),False),
                ((b'SWASSH:.f..t......',),(0,1,0),False),((b'SWASSH:.f.........\n',),(0,0,0),False),((b'\n\r\n',),(0,0,0),False),
                ((b'x'*129,b'\n'),(0,0,0),True),((b'SWASSH:?f.........\n',),(0,0,0),True),
                ((b'SWASSH:>?.........\n',),(0,0,0),True),((b'SWASSH:.d.........\n',),(0,0,0),False)):
            stream=asyncio.StreamReader()
            for chunk in chunks:stream.feed_data(chunk)
            stream.feed_eof();buffer=PreviewBuffer(32);await buffer.consume(stream)
            self.assertEqual((buffer.added,buffer.changed,buffer.deleted),expected)
            self.assertEqual(buffer.invalid,invalid);self.assertEqual(buffer.pending,b'')
            self.assertNotIn('SWASSH:',buffer.text)
