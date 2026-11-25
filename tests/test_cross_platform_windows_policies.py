"""Windows policy branches through memory ports on either host OS.

These tests neither call Win32 nor alter a real registry, ACL, process or key.
Native Windows integration remains a separate required qualification.
"""
from contextlib import nullcontext
import io
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from swassh import FileTransfer, Options, TransferDirection, TransferSettings
from swassh.infrastructure import audit, authentication, filesystem, installation, preflight
from test_installation import MemoryRegistry


class WindowsPolicyPortTests(unittest.TestCase):
    def test_writer_lock_uses_the_windows_nonblocking_byte_lock_and_releases_its_stream(self):
        stream = Mock()
        stream.fileno.return_value = 41
        port = SimpleNamespace(name='nt', fstat=Mock(return_value=SimpleNamespace(st_size=1)))
        kernel = SimpleNamespace(LK_NBLCK=1, locking=Mock())
        with patch.object(audit, 'os', port), patch.object(audit, '_private_open', return_value=stream), \
                patch.dict(sys.modules, {'msvcrt': kernel}):
            lock = audit._WriterLock(Path('synthetic-log'))
            lock.close()
        kernel.locking.assert_called_once_with(41, 1, 1)
        stream.close.assert_called_once()
        stream.write.assert_not_called()

    def test_provider_and_append_use_windows_metadata_without_posix_permission_claims(self):
        parent = SimpleNamespace(open=Mock(return_value=41))
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        port.fstat = Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_nlink=1))
        port.close, port.fchmod = Mock(), Mock()
        expected = Path('/synthetic/provider').absolute()
        with patch.object(authentication, 'os', port), \
                patch.object(authentication.shutil, 'which', return_value=str(expected)), \
                patch.object(authentication, 'PinnedDirectory', return_value=nullcontext(parent)):
            self.assertEqual(authentication.Authentication.provider(Options(askpass_executable='provider')), str(expected))
        port.close.assert_called_once_with(41)
        stream = io.StringIO()
        port.fdopen = Mock(return_value=stream)
        port.close.reset_mock()
        with patch.object(filesystem, 'os', port), \
                patch.object(filesystem, 'PinnedDirectory', return_value=nullcontext(parent)):
            self.assertIs(filesystem.open_private_append('/synthetic/audit'), stream)
        port.fchmod.assert_not_called()
        port.close.assert_not_called()
        stream.close()

    def test_default_registry_import_and_exe_entrypoint_lookup_are_injected_without_writes(self):
        registry = MemoryRegistry()
        with patch.dict(sys.modules, {'winreg': registry}):
            configurator = installation.WindowsPathConfigurator(r'C:\Tools\bin', '/synthetic-home')
        self.assertIs(configurator.registry, registry)
        self.assertEqual(registry.writes, [])
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        scripts = Path('/synthetic/scripts')
        with patch.object(installation, 'os', port), \
                patch.object(installation.importlib.metadata, 'distribution', return_value=SimpleNamespace(files=[])), \
                patch.object(installation.sysconfig, 'get_path', return_value=str(scripts)), \
                patch.object(Path, 'is_file', autospec=True, return_value=True) as inspect:
            self.assertEqual(installation.installed_scripts(), scripts)
        self.assertEqual(inspect.call_args.args, (scripts / 'swassh.exe',))

    def test_windows_preflight_observes_keys_and_sftp_without_probing_a_posix_agent(self):
        checker = preflight.LocalPreflight()
        port = SimpleNamespace(**vars(os))
        port.name = 'nt'
        port.environ = {'SSH_AUTH_SOCK': 'synthetic-agent-not-probed'}
        port.fstat = Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o777, st_size=8))
        port.close = Mock()
        parent = SimpleNamespace(open=Mock(return_value=41))
        with patch.object(preflight, 'os', port), patch.object(preflight, 'PinnedDirectory', return_value=nullcontext(parent)), \
                patch.object(Path, 'resolve', return_value=Path('/synthetic/key')):
            self.assertEqual(checker._file('/synthetic/key', 'key', private=True).code, 'key_readable')
        port.close.assert_called_once_with(41)
        issue = preflight.CheckIssue('metadata_only', 'ok', 'synthetic metadata')
        with patch.object(preflight, 'os', port), patch.object(checker, '_file', return_value=issue), \
                patch.object(checker, '_future_directory', return_value=issue), \
                patch.object(preflight.shutil, 'which', return_value='synthetic-tool') as locate, \
                patch.object(Path, 'is_dir', return_value=False):
            report = checker.inspect(Options(log_file=None),
                request=FileTransfer(TransferDirection.PUSH, 'synthetic-source', '/remote/file'), settings=TransferSettings())
        codes = {item.code for item in report.issues}
        self.assertIn('agent_unverified', codes)
        self.assertIn('transfer_tool_available', codes)
        self.assertNotIn('agent_socket_present', codes)
        self.assertFalse(any(call.args == ('rsync',) for call in locate.call_args_list))
