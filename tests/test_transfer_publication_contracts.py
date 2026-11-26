"""Isolated transfer publication: hash proof, literal paths and no blind replay.

Native SSH/SFTP ports are in memory; staging and atomic local publication use
private temporary directories. These tests make no claim about a real server.
"""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from swassh import FileTransfer, Host, Options, Result, Status, TransferDirection, TransferSettings
from swassh.infrastructure import transfers
from swassh.infrastructure.integrity import PROBE
from swassh.domain.transfers import host_directory


class TransferPublicationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_windows_policy_snapshots_and_publishes_via_file_ports_on_either_host(self):
        from swassh.infrastructure import windows
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        port.__dict__.pop('chown', None)
        opened = []
        def open_file(path, flags, mode=0o600):
            opened.append(str(path))
            return os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), mode)
        with tempfile.TemporaryDirectory() as directory, patch.object(transfers, 'os', port), \
                patch.object(windows, 'open_file_without_reparse', side_effect=open_file):
            root = Path(directory)
            push = self.client(root)
            async with push:
                self.assertEqual(Path(push.source).read_bytes(), b'synthetic transfer payload')
                self.assertIsNone(push.rsync)
            pull = self.client(root, pull=True)
            async with pull:
                async def data(argv, host, *, watched):
                    watched.write_bytes(b'published bytes')
                    return self.response()
                with patch.object(pull, '_run', side_effect=data) as run:
                    result = await pull.transfer(Host('one'))
                self.assertEqual(result.status, Status.SUCCESS, result)
                self.assertEqual(Path(result.transfer.local_path).read_bytes(), b'published bytes')
                run.assert_awaited_once()
            self.assertFalse(list(root.rglob('.swassh-stage-*')))
        self.assertTrue(any(path.endswith('source') for path in opened))

    def client(self, root, *, pull=False, remote='/remote/file', **settings):
        source=root/'source';source.write_bytes(b'synthetic transfer payload')
        options=Options()
        ssh=SimpleNamespace(executable='synthetic-ssh',profiles=SimpleNamespace(for_host=lambda host:options),
            execute=AsyncMock(),_pacer=SimpleNamespace(acquire=AsyncMock()))
        request=FileTransfer(TransferDirection.PULL if pull else TransferDirection.PUSH,
            str(root/'downloads' if pull else source),remote)
        with patch.object(transfers,'SSHTransport',return_value=ssh),patch.object(transfers.shutil,'which',return_value=None):
            client=transfers.NativeFileTransport(options,TransferSettings(**settings),request,128)
        client.sftp='synthetic-sftp'
        return client

    def response(self, status=Status.SUCCESS, text=''):
        return Result(Host('one'),status,stdout=text,exit_code=0 if status==Status.SUCCESS else 1)

    async def test_capability_failures_are_readonly_and_never_launch_data(self):
        with tempfile.TemporaryDirectory() as directory:
            for status in (Status.ERROR,Status.TIMEOUT,Status.INTERRUPTED,Status.AUTH_FAILED,Status.HOST_KEY_FAILED):
                client=self.client(Path(directory));client.rsync='synthetic-rsync'
                client.ssh.execute.return_value=self.response(status)
                with patch.object(client,'_run',new_callable=AsyncMock) as run:
                    value=await client.transfer(Host('one'))
                self.assertEqual(value.status,status);run.assert_not_awaited()
                self.assertEqual(client.ssh.execute.await_args.args[1],'rsync --version')
            for kwargs,remote,sftp,message in (({'dry_run':True},'/remote/file',True,'readonly preview'),
                    ({},'/remote/',True,'rsync required'),({},'/remote/file',False,'SFTP client')):
                client=self.client(Path(directory),remote=remote,**kwargs)
                if not sftp:client.sftp=None
                with patch.object(client,'_run',new_callable=AsyncMock) as run:
                    value=await client.transfer(Host('one'))
                self.assertEqual(value.status,Status.ERROR);self.assertIn(message,value.error)
                run.assert_not_awaited();client.ssh.execute.assert_not_awaited()

    async def test_literal_pull_and_preview_refuse_unsafe_rsync_glob_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            for remote,preview,sftp,message in (('/remote/*/',False,True,'glob'),
                    ('/remote/*',True,True,'literal source'),('/remote/*',False,False,'SFTP client')):
                client=self.client(Path(directory),pull=True,remote=remote,dry_run=preview)
                client.rsync='synthetic-rsync';client.sftp='synthetic-sftp' if sftp else None
                client.ssh.execute.return_value=self.response(text='rsync version 3.5.0')
                with patch.object(client,'_run',new_callable=AsyncMock) as run:
                    value=await client.transfer(Host('one'))
                self.assertEqual(value.status,Status.ERROR);self.assertIn(message,value.error);run.assert_not_awaited()

    async def test_hash_probe_and_source_proof_fail_before_data_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('unsupported','probe-status','probe-truncated','hash-status','hash-truncated','hash-malformed'):
                client=self.client(Path(directory),pull=True,verify_sha256=True)
                probe=self.response(text='sha256sum')
                check=self.response(text='a'*64+'  /remote/file\n')
                if failure=='unsupported':probe=replace(probe,stdout='untrusted-tool')
                if failure=='probe-status':probe=replace(probe,status=Status.TIMEOUT)
                if failure=='probe-truncated':probe=replace(probe,stdout_truncated=True)
                if failure=='hash-status':check=replace(check,status=Status.FAILED)
                if failure=='hash-truncated':check=replace(check,stdout_truncated=True)
                if failure=='hash-malformed':check=replace(check,stdout='not a hash')
                client.ssh.execute.side_effect=[probe,check]
                with patch.object(client,'_run',new_callable=AsyncMock) as run:
                    value=await client.transfer(Host('one'))
                self.assertIn(value.status,(Status.ERROR,Status.FAILED));run.assert_not_awaited()
                self.assertIn('no data',value.error)
                self.assertEqual(client.ssh.execute.await_args_list[0].args[1],PROBE)

    async def test_verified_push_checks_temporary_and_preserves_ambiguous_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            for failure in ('none','status','truncated','mismatch','publish'):
                client=self.client(Path(directory),verify_sha256=True)
                async with client:
                    digest=hashlib.sha256(Path(client.source).read_bytes()).hexdigest()
                    self.assertEqual(client.source_digest,digest)
                    check=self.response(text=digest+'  temporary\n')
                    if failure=='status':check=replace(check,status=Status.TIMEOUT)
                    if failure=='truncated':check=replace(check,stdout_truncated=True)
                    if failure=='mismatch':check=replace(check,stdout='a'*64+'  temporary\n')
                    client.ssh.execute.side_effect=[self.response(text='sha256sum'),check,
                        self.response(Status.TIMEOUT if failure=='publish' else Status.SUCCESS)]
                    commands=[]
                    async def data(argv,host,**kwargs):
                        commands.append(Path(argv[argv.index('-b')+1]).read_text())
                        return self.response(text='private native output')
                    with patch.object(client,'_run',side_effect=data):value=await client.transfer(Host('one'))
                    self.assertEqual(len(commands),1);self.assertNotIn('@rename',commands[0])
                    self.assertIn('.swassh-',commands[0]);self.assertIn('.part',commands[0])
                    if failure=='none':
                        self.assertEqual(value.status,Status.SUCCESS);self.assertIsNone(value.transfer.temporary_path)
                        self.assertEqual(value.stdout,'transfer complete; SHA-256 verified')
                        self.assertEqual(value.transfer.bytes_transferred,len(b'synthetic transfer payload'))
                    else:
                        self.assertEqual(value.status,Status.TIMEOUT if failure=='publish' else Status.ERROR)
                        self.assertIn('.part',value.transfer.temporary_path)
                        self.assertIn('no replay' if failure=='publish' else 'not published',value.error)
                    self.assertEqual(client.ssh.execute.await_count,3 if failure in ('none','publish') else 2)

    async def test_verified_pull_publishes_only_when_both_hashes_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=b'synthetic downloaded bytes';digest=hashlib.sha256(payload).hexdigest()
            for failure in ('none','remote-changed','local-mismatch','recheck-status','recheck-truncated','malformed'):
                client=self.client(root,pull=True,verify_sha256=True)
                client.local=root/('download-'+failure)
                async with client:
                    recheck=self.response(text=digest+'  /remote/file\n')
                    if failure=='remote-changed':recheck=replace(recheck,stdout='a'*64+'  /remote/file\n')
                    if failure=='recheck-status':recheck=replace(recheck,status=Status.TIMEOUT)
                    if failure=='recheck-truncated':recheck=replace(recheck,stdout_truncated=True)
                    if failure=='malformed':recheck=replace(recheck,stdout='invalid')
                    client.ssh.execute.side_effect=[self.response(text='sha256sum'),
                        self.response(text=digest+'  /remote/file\n'),recheck]
                    async def data(argv,host,*,watched):
                        watched.write_bytes(b'wrong bytes' if failure=='local-mismatch' else payload)
                        batch=Path(argv[argv.index('-b')+1]).read_text()
                        self.assertTrue(batch.startswith('@get -p -f '))
                        return self.response()
                    with patch.object(client,'_run',side_effect=data):value=await client.transfer(Host('one'))
                    final=Path(value.transfer.local_path)
                    if failure=='none':
                        self.assertEqual(value.status,Status.SUCCESS);self.assertEqual(final.read_bytes(),payload)
                        self.assertEqual(value.transfer.bytes_transferred,len(payload))
                    else:
                        self.assertEqual(value.status,Status.ERROR);self.assertFalse(final.exists())
                        self.assertIn('publish error' if failure=='malformed' else 'not published',value.error)
                    self.assertFalse(list(final.parent.glob('.swassh-stage-*')))

    async def test_sftp_fallback_and_failed_native_operation_never_repeat_data(self):
        with tempfile.TemporaryDirectory() as directory:
            for remote,status in (('/remote/file',Status.SUCCESS),('/remote/file',Status.FAILED),('/remote/*',Status.SUCCESS)):
                client=self.client(Path(directory),pull=True,remote=remote)
                client.local=Path(directory)/('download-'+str(status.value)+str('*' in remote))
                async with client:
                    client.rsync='synthetic-rsync'
                    client.ssh.execute.return_value=self.response(text='rsync version '+('3.5.0' if '*' in remote else '3.4.0'))
                    calls=[]
                    async def data(argv,host,*,watched):
                        calls.append(argv);watched.write_bytes(b'local result');return self.response(status)
                    with patch.object(client,'_run',side_effect=data):value=await client.transfer(Host('one'))
                    self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'synthetic-sftp')
                    self.assertEqual(value.status,status);self.assertEqual(value.transfer.backend,'sftp')
                    self.assertIsNotNone(value.transfer.fallback_reason)
                    self.assertEqual(Path(value.transfer.local_path).exists(),status==Status.SUCCESS)

    async def test_rsync_direction_directory_and_readonly_preview_keep_exact_native_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for pull in (False,True):
                for directory_source in (False,True):
                    for preview in (False,True):
                        with self.subTest(pull=pull,directory=directory_source,preview=preview):
                            local=root/f'{pull}-{directory_source}-{preview}';local.mkdir()
                            client=self.client(local,pull=pull,remote='/remote/tree/' if directory_source else '/remote/file',dry_run=preview)
                            if directory_source and not pull:
                                client.local=local/'tree';client.local.mkdir();(client.local/'keep').write_bytes(b'kept')
                                client.request=replace(client.request,local_path=str(client.local)+'/')
                            if pull and preview:
                                client.local.mkdir(mode=0o700)
                                (client.local/host_directory(Host('one'))).mkdir(mode=0o700)
                            async with client:
                                client.rsync='synthetic-rsync';client.ssh.execute.return_value=self.response(text='rsync version 3.5.0')
                                calls=[]
                                async def data(argv,host,*,watched):
                                    calls.append((argv,watched))
                                    if watched is not None:watched.write_bytes(b'local payload')
                                    return self.response(text='preview only: added=1 changed=0 deleted=0' if preview else 'native filename suppressed')
                                with patch.object(client,'_run',side_effect=data):value=await client.transfer(Host('one'))
                                self.assertEqual(value.status,Status.SUCCESS);self.assertEqual(len(calls),1)
                                argv,watched=calls[0];self.assertEqual(argv[0],'synthetic-rsync')
                                self.assertIn('--protect-args',argv);self.assertIn('--safe-links',argv)
                                self.assertIn('--no-devices',argv);self.assertIn('--no-specials',argv)
                                self.assertEqual('--dry-run' in argv,preview)
                                self.assertEqual(value.transfer.backend,'rsync');self.assertIsNone(value.transfer.fallback_reason)
                                self.assertEqual(value.stdout,'preview only: added=1 changed=0 deleted=0' if preview else 'transfer complete')
                                self.assertEqual(watched is None,not pull or directory_source or preview)
                                if pull and not directory_source and not preview:
                                    self.assertEqual(Path(value.transfer.local_path).read_bytes(),b'local payload')
                                if preview:self.assertIsNone(value.transfer.bytes_transferred)
                                self.assertEqual(argv[-2].startswith('swassh-target:'),pull)
                                self.assertEqual(argv[-1].startswith('swassh-target:'),not pull)

    async def test_password_sftp_mode_is_explicit_and_data_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.client(Path(directory))
            settings=Options(auth_method='password',askpass_executable='synthetic-provider')
            client.options=settings;client.ssh.profiles=SimpleNamespace(for_host=lambda host:settings)
            async with client:
                with patch.object(client,'_run',return_value=self.response()) as data:
                    value=await client.transfer(Host('one'))
                self.assertEqual(value.status,Status.SUCCESS);data.assert_awaited_once()
                argv=data.await_args.args[0]
                self.assertEqual(argv[:3],['synthetic-sftp','-o','BatchMode=no'])

    async def test_final_stage_hardlinks_and_oversize_never_replace_an_existing_reported_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for failure in ('hardlink','size'):
                local=root/failure;local.mkdir();client=self.client(local,pull=True,max_file_mib=1)
                async with client:
                    final=client.local/host_directory(Host('one'))/'file'
                    final.parent.mkdir(mode=0o700);final.write_bytes(b'previous complete file')
                    async def data(argv,host,*,watched):
                        if failure=='hardlink':
                            watched.unlink();watched.hardlink_to(final)
                        else:
                            with watched.open('wb') as stream:stream.truncate(1024**2+1)
                        return self.response()
                    with patch.object(client,'_run',side_effect=data):value=await client.transfer(Host('one'))
                    self.assertEqual(value.status,Status.ERROR);self.assertEqual(value.error,'transfer path or publish error')
                    self.assertEqual(final.read_bytes(),b'previous complete file')
                    self.assertFalse(list(final.parent.glob('.swassh-stage-*')))

    async def test_metrics_add_native_and_ssh_costs_without_losing_either(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.client(Path(directory));client._admission_wait_seconds=1.25;client._native_seconds=2.5
            client.ssh.metrics=Mock(return_value={'shared_admission_wait_seconds':3.75,'native_client_seconds':4.5})
            self.assertEqual(client.metrics(),{'shared_admission_wait_seconds':5.0,'native_client_seconds':7.0})
            client.ssh.metrics.assert_called_once_with()

    async def test_failed_descriptor_permissions_cannot_publish_or_replace_existing_download(self):
        # Inject a real syscall-boundary failure on every host, including older
        # Windows Pythons which do not expose fchmod. Staging remains real.
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(Path(directory), pull=True)
            async with client:
                final = client.local / host_directory(Host('one')) / 'file'
                final.parent.mkdir(mode=0o700)
                final.write_bytes(b'previous complete file')
                async def data(argv, host, *, watched):
                    watched.write_bytes(b'complete new file')
                    return self.response()
                port = SimpleNamespace(**vars(os))
                port.fchmod = Mock(side_effect=OSError('synthetic permission update failure'))
                with patch.object(transfers, 'os', port), patch.object(client, '_run', side_effect=data) as run:
                    value = await client.transfer(Host('one'))
                self.assertEqual(value.status, Status.ERROR)
                self.assertEqual(value.error, 'transfer path or publish error')
                port.fchmod.assert_called_once()
                run.assert_awaited_once()
                self.assertEqual(final.read_bytes(), b'previous complete file')
                self.assertFalse(list(final.parent.glob('.swassh-stage-*')))

    async def test_publication_without_optional_fchmod_still_syncs_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.client(Path(directory),pull=True)
            async with client:
                async def data(argv,host,*,watched):
                    watched.write_bytes(b'complete download');return self.response()
                port=SimpleNamespace(**{name:value for name,value in vars(os).items() if name!='fchmod'})
                port.fsync=Mock(wraps=os.fsync)
                with patch.object(transfers,'os',port),patch.object(client,'_run',side_effect=data):
                    result=await client.transfer(Host('one'))
                self.assertEqual(result.status,Status.SUCCESS);port.fsync.assert_called_once()
                self.assertEqual(Path(result.transfer.local_path).read_bytes(),b'complete download')


if __name__=='__main__':unittest.main()
