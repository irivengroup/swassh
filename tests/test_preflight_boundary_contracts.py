"""Read-only preflight observes metadata and never asks for a secret."""
from contextlib import nullcontext
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch

from swassh import FileTransfer,Options,TransferDirection,TransferSettings
from swassh.application.preflight import PreflightError
from swassh.application.profiles import HostProfile
from swassh.infrastructure import preflight
from swassh.infrastructure import authentication


class AuthenticationPolicyUnitTests(unittest.TestCase):
    def test_missing_provider_is_refused_without_resolving_a_default_executable(self):
        with patch.object(authentication.shutil,'which',return_value=None) as locate,\
                patch.object(authentication,'PinnedDirectory') as pin,\
                self.assertRaisesRegex(ValueError,'provider executable unavailable'):
            authentication.Authentication.provider(Options())
        locate.assert_called_once_with('');pin.assert_not_called()

    def test_posix_provider_without_shared_write_access_closes_its_metadata_descriptor(self):
        port=SimpleNamespace(**vars(os));port.name='posix'
        port.fstat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o700));port.close=Mock()
        parent=SimpleNamespace(open=Mock(return_value=41));options=Options(askpass_executable='synthetic-provider')
        expected=Path('/synthetic/provider').absolute()
        with patch.object(authentication,'os',port),patch.object(authentication.shutil,'which',return_value=str(expected)),\
                patch.object(authentication,'PinnedDirectory',return_value=nullcontext(parent)):
            self.assertEqual(authentication.Authentication.provider(options),str(expected))
        port.fstat.assert_called_once_with(41);port.close.assert_called_once_with(41)


class PreflightBoundaryTests(unittest.TestCase):
    def test_missing_root_ancestor_is_a_bounded_failure_without_creation(self):
        checker=preflight.LocalPreflight()
        with patch.object(Path,'stat',side_effect=FileNotFoundError('synthetic missing mount')) as lookup,\
                patch.object(checker,'_directory') as inspect:
            issue=checker._future_directory(Path(Path.cwd().anchor)/'missing'/'child','future')
        self.assertEqual(issue.code,'future_unavailable');inspect.assert_not_called()
        self.assertEqual(lookup.call_count,3);self.assertNotIn('synthetic',issue.message)

    def test_foreign_owned_private_key_is_observed_without_claiming_owner_permissions(self):
        checker=preflight.LocalPreflight();parent=SimpleNamespace(open=Mock(return_value=19))
        port=SimpleNamespace(**vars(os));port.name='posix';port.geteuid=lambda:1000
        port.fstat=Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1001,st_size=8))
        port.close=Mock()
        with patch.object(preflight,'os',port),patch.object(preflight,'PinnedDirectory',return_value=nullcontext(parent)),\
                patch.object(Path,'resolve',return_value=Path('/synthetic/key')):
            issue=checker._file('/synthetic/key','key',private=True)
        self.assertEqual(issue.code,'key_readable');port.close.assert_called_once_with(19)
        self.assertIn('not verified',issue.message)

    def test_default_known_hosts_gssapi_and_no_agent_are_explicitly_unverified(self):
        checker=preflight.LocalPreflight();port=SimpleNamespace(**vars(os));port.name='posix';port.environ={}
        options=Options(auth_method='gssapi',host_profiles=(HostProfile('one'),))
        with patch.object(preflight,'os',port),patch.object(preflight.shutil,'which',return_value='synthetic-ssh'),\
                patch.object(checker,'_file',return_value=preflight.CheckIssue('known','ok','controlled')) as file,\
                patch.object(checker,'_future_directory',return_value=preflight.CheckIssue('budget','ok','controlled')):
            report=checker.inspect(options)
        file.assert_called_once_with('~/.ssh/known_hosts','known_hosts')
        self.assertTrue({'gssapi_unverified','agent_unverified','identity_implicit','remote_unverified'}<={item.code for item in report.issues})

    def test_existing_regular_report_and_link_metadata_are_distinguished_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'report';output.write_bytes(b'unchanged')
            checker=preflight.LocalPreflight();options=Options(known_hosts=str(output),budget_dir=str(root/'budget'))
            for linked in (False,True):
                original=Path.is_symlink
                def is_link(path):return linked if path==output else original(path)
                with patch.object(Path,'is_symlink',is_link),patch.object(preflight.shutil,'which',return_value='synthetic-ssh'):
                    report=checker.inspect(options,output=output)
                self.assertEqual('report_target_invalid' in {item.code for item in report.issues},linked)
                self.assertEqual(output.read_bytes(),b'unchanged');self.assertFalse((root/'budget').exists())

    def test_posix_transfer_tool_preview_and_directory_observations_are_readonly(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();known=root/'known';known.write_bytes(b'synthetic')
            checker=preflight.LocalPreflight();port=SimpleNamespace(**vars(os));port.name='posix';port.environ={}
            options=Options(known_hosts=str(known),budget_dir=str(root/'budget'))
            requests=((FileTransfer(TransferDirection.PUSH,str(source),'/remote/'),TransferSettings()),
                      (FileTransfer(TransferDirection.PUSH,str(known),'/remote/file'),TransferSettings()),
                      (FileTransfer(TransferDirection.PULL,str(source),'/remote/'),TransferSettings(dry_run=True)))
            before=sorted(root.iterdir())
            for request,settings in requests:
                with patch.object(preflight,'os',port),patch.object(preflight.shutil,'which',return_value='synthetic-tool'):
                    report=checker.inspect(options,request=request,settings=settings)
                codes={item.code for item in report.issues}
                self.assertIn('transfer_tool_available',codes);self.assertNotIn('sha256_directory',codes)
                expected=('source_directory' if request.local_path==str(source) else 'source_readable') if request.direction==TransferDirection.PUSH else 'pull_destination_accessible'
                self.assertIn(expected,codes)
            self.assertEqual(sorted(root.iterdir()),before)

    def test_source_link_and_unsafe_directory_are_reported_without_traversing_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);file=root/'source';file.write_bytes(b'unchanged');known=root/'known';known.write_bytes(b'synthetic')
            checker=preflight.LocalPreflight();options=Options(known_hosts=str(known),budget_dir=str(root/'budget'))
            original=Path.lstat
            def metadata(path,*args,**kwargs):
                return SimpleNamespace(st_mode=stat.S_IFLNK|0o700) if path==file else original(path,*args,**kwargs)
            with patch.object(Path,'lstat',metadata),patch.object(preflight.shutil,'which',return_value=None):
                report=checker.inspect(options,request=FileTransfer(TransferDirection.PUSH,str(file),'/remote'),settings=TransferSettings())
            self.assertIn('source_link',{item.code for item in report.issues});self.assertEqual(file.read_bytes(),b'unchanged')
            folder=root/'folder';folder.mkdir();original_pin=preflight.PinnedDirectory
            def pin(path,*args,**kwargs):
                if Path(path)==folder:raise PermissionError('synthetic denied directory')
                return original_pin(path,*args,**kwargs)
            with patch.object(preflight,'PinnedDirectory',side_effect=pin),patch.object(preflight.shutil,'which',return_value=None):
                report=checker.inspect(options,request=FileTransfer(TransferDirection.PUSH,str(folder),'/remote/'),settings=TransferSettings())
            self.assertIn('source_directory_unsafe',{item.code for item in report.issues})
            self.assertEqual(list(folder.iterdir()),[]);self.assertFalse((root/'budget').exists())

    def test_agent_socket_observation_and_ancestor_errors_are_local_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);known=root/'known';known.write_bytes(b'synthetic')
            socket=root/'agent';checker=preflight.LocalPreflight()
            port=SimpleNamespace(**vars(os));port.name='posix'
            options=Options(known_hosts=str(known),budget_dir=str(root/'budgets'))
            original=Path.stat
            for state in ('socket','regular','missing'):
                def metadata(path,*args,**kwargs):
                    if path==socket:
                        if state=='missing':raise FileNotFoundError('synthetic agent')
                        return SimpleNamespace(st_mode=stat.S_IFSOCK if state=='socket' else stat.S_IFREG)
                    return original(path,*args,**kwargs)
                with patch.object(preflight,'os',port),patch.dict(os.environ,{'SSH_AUTH_SOCK':str(socket)}),\
                        patch.object(Path,'stat',metadata),patch.object(preflight.shutil,'which',return_value='synthetic-ssh'):
                    report=checker.inspect(options)
                self.assertIn('agent_socket_present' if state=='socket' else 'agent_socket_unavailable',
                              {item.code for item in report.issues})
            with patch.object(Path,'stat',side_effect=PermissionError('private ancestor')):
                self.assertEqual(checker._future_directory(root/'future','future').code,'future_unavailable')
            self.assertFalse((root/'budgets').exists())

    def test_file_kind_permissions_empty_and_io_failures_have_controlled_codes(self):
        checker=preflight.LocalPreflight()
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'key';file.write_bytes(b'synthetic')
            for mode,size,expected in ((stat.S_IFDIR|0o700,1,'not_regular'),
                    (stat.S_IFREG|0o600,0,'empty'),(stat.S_IFREG|0o644,1,'permissions'),
                    (stat.S_IFREG|0o600,1,'readable')):
                port=SimpleNamespace(**vars(os));port.name='posix';port.geteuid=lambda:123
                port.fstat=lambda fd:SimpleNamespace(st_mode=mode,st_size=size,st_uid=123)
                port.close=Mock();parent=SimpleNamespace(open=Mock(return_value=17))
                with patch.object(preflight,'PinnedDirectory',return_value=nullcontext(parent)),patch.object(preflight,'os',port):
                    value=checker._file(file,'key',private=True)
                self.assertEqual(value.code,'key_'+expected);port.close.assert_called_once_with(17)
            for error,code in ((PermissionError('private'), 'unreadable'),(RuntimeError('private'),'unsafe'),
                    (OSError('private'),'unsafe'),(ValueError('private'),'unsafe')):
                with patch.object(preflight,'PinnedDirectory',side_effect=error):value=checker._file(file,'key')
                self.assertEqual(value.code,'key_'+code);self.assertNotIn('private',value.message)
            self.assertEqual(checker._file(Path(directory)/'absent','key').code,'key_missing')

    def test_explicit_password_provider_and_profile_keys_are_checked_without_password_read(self):
        checker=preflight.LocalPreflight()
        profile=HostProfile('one',client_keys=('profile-key',),auth_method='password')
        options=Options(client_keys=('global-key',),host_profiles=(profile,),askpass_executable='external-provider')
        with patch.object(checker,'_file',return_value=preflight.CheckIssue('key','ok','controlled')) as file:
            for error in (None,ValueError('private provider error'),OSError('private provider error')):
                with patch.object(preflight.Authentication,'provider',side_effect=error,return_value='provider') as provider:
                    report=checker.credentials(options)
                provider.assert_called_once_with(options)
                self.assertEqual(report.ok,error is None)
                self.assertIn('password_provider_available' if error is None else 'password_provider_invalid',
                              [item.code for item in report.issues])
            self.assertEqual({call.args[1] for call in file.call_args_list},{'key_1','profile_1_key_1'})
        with patch.object(preflight.shutil,'which',return_value=None),self.assertRaises(PreflightError):checker.transport(Options())

    def test_inspection_reports_destination_and_source_faults_without_creating_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.write_bytes(b'synthetic')
            folder=root/'folder';folder.mkdir();missing=root/'missing'
            checker=preflight.LocalPreflight()
            options=Options(known_hosts=str(source),stdin_file=str(source),log_file=str(missing/'audit'),
                host_profiles=(HostProfile('one',known_hosts=str(source),auth_method='gssapi'),))
            for failure in (False,True):
                with patch.object(preflight.shutil,'which',return_value=None),patch.object(preflight.InputSnapshot,'stdin',
                        side_effect=ValueError('private') if failure else None,return_value=b'synthetic'):
                    report=checker.inspect(options,output=folder,spool=missing,state=missing)
                codes={item.code for item in report.issues}
                self.assertTrue({'report_target_invalid','spool_unavailable','ssh_missing','gssapi_unverified'}<=codes)
                self.assertIn('stdin_invalid' if failure else 'stdin_readable',codes)
            for local,remote,settings,expected in ((folder,'/remote',TransferSettings(verify_sha256=True),{'destination_shape','sha256_directory'}),
                    (missing,'/remote',TransferSettings(),{'source_metadata','source_missing'}),
                    (Path(source.anchor),'/remote',TransferSettings(),{'pull_root'})):
                pull=expected=={'pull_root'}
                request=FileTransfer(TransferDirection.PULL if pull else TransferDirection.PUSH,str(local),remote)
                with patch.object(preflight.shutil,'which',return_value=None):report=checker.inspect(options,request=request,settings=settings)
                self.assertTrue(expected<={item.code for item in report.issues})
                self.assertIn('transfer_tool_missing',{item.code for item in report.issues})
            with self.assertRaisesRegex(ValueError,'settings required'):
                checker.inspect(options,request=FileTransfer(TransferDirection.PUSH,str(source),'/remote'))
            with patch.object(preflight.os,'access',return_value=False):self.assertEqual(checker._directory(folder,'destination').code,'destination_access')
            self.assertFalse(missing.exists())


if __name__=='__main__':unittest.main()
