"""Pip deployment and PATH persistence without editing the operator's environment."""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from swassh.infrastructure.installation import WindowsPathConfigurator, setup_path

ROOT = Path(__file__).resolve().parents[1]


class MemoryRegistry:
    """Test registry implementing string persistence and observable writes."""
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE = 1, 1, 2
    REG_SZ, REG_EXPAND_SZ = 1, 2

    def __init__(self, value=None, kind=2):
        self.value, self.kind, self.writes = value, kind, []

    def CreateKeyEx(self, *args):
        return contextlib.nullcontext(self)

    def QueryValueEx(self, handle, name):
        if self.value is None:
            raise FileNotFoundError(name)
        return self.value, self.kind

    def SetValueEx(self, handle, name, reserved, kind, value):
        self.value, self.kind = value, kind
        self.writes.append(value)


class DeploymentTests(unittest.TestCase):
    def test_index_installation_exact_version_and_error_propagation(self):
        main = runpy.run_path(str(ROOT / 'scripts/install.py'))['main']
        with patch('sys.argv', ['install.py', '--package-version', '1.5.1rc1', '--user']), \
                patch('subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(main(), 0)
            command = run.call_args_list[0].args[0]
            self.assertEqual(command[-1], 'swassh==1.5.1rc1')
            self.assertIn('--user', command)
            self.assertNotIn('--no-index', command)
            self.assertEqual(run.call_args_list[1].args[0][-1], 'setup-path')
        with patch('sys.argv', ['install.py', '--package-version', '1.5.1']), \
                patch('subprocess.run', side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=2)]):
            self.assertEqual(main(), 2)
        for arguments in ([], ['--package-version', 'other @ https://example.org'],
                          ['--package-version', '>=1'], ['input.whl', '--package-version', '1.0']):
            with self.subTest(arguments=arguments), patch('sys.argv', ['install.py', *arguments]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 2)

    def test_already_available_path_does_not_modify_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            with patch('swassh.infrastructure.installation.installed_scripts', return_value=path), \
                    patch('sys.prefix', 'base'), patch('sys.base_prefix', 'base'), \
                    patch.dict(os.environ, {'PATH': str(path)}), \
                    patch('swassh.infrastructure.installation.PathConfigurator.configure') as configure, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                setup_path()
            configure.assert_not_called()
            self.assertIn('no change', output.getvalue())
            with patch('swassh.infrastructure.installation.installed_scripts', return_value=path), \
                    patch('sys.prefix', 'base'), patch('sys.base_prefix', 'base'), \
                    patch('shutil.which', return_value=str(path / 'different' / 'swassh')), \
                    self.assertRaisesRegex(ValueError, 'another SWASSH'):
                setup_path()

    def test_windows_path_preserves_type_backups_and_idempotence(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = MemoryRegistry(r'%USERPROFILE%\existing')
            setup = WindowsPathConfigurator(r'C:\SWASSH\Scripts', directory, registry=registry)
            backup = setup.configure()
            self.assertEqual(json.loads(backup.read_text())['value'], r'%USERPROFILE%\existing')
            self.assertEqual(registry.value, r'%USERPROFILE%\existing;C:\SWASSH\Scripts')
            self.assertEqual(registry.kind, registry.REG_EXPAND_SZ)
            self.assertIsNone(setup.configure())
            self.assertEqual(len(registry.writes), 1)
            registry.value, registry.kind = r'c:\swassh\scripts' + '\\', registry.REG_SZ
            self.assertIsNone(setup.configure())
            registry.value = None
            backup = setup.configure()
            self.assertFalse(json.loads(backup.read_text())['existed'])
            self.assertEqual(registry.value, r'C:\SWASSH\Scripts')

    def test_windows_invalid_paths_and_registry_values_fail_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = MemoryRegistry()
            for path in ('relative', '\\root-relative', 'C:\\bad;entry', 'C:\\bad\nentry', 'C:\\bad"entry'):
                with self.assertRaises(ValueError):
                    WindowsPathConfigurator(path, directory, registry=registry)
            setup = WindowsPathConfigurator(r'C:\SWASSH', directory, registry=registry)
            for value, kind in ((42, 4), ('bad\nvalue', 1), ('x' * 32767, 1)):
                registry.value, registry.kind = value, kind
                with self.assertRaises(ValueError):
                    setup.configure()
            self.assertEqual(registry.writes, [])
            registry.value, registry.kind = '', registry.REG_EXPAND_SZ
            with self.assertRaisesRegex(ValueError, 'literal percent'):
                WindowsPathConfigurator(r'C:\percent%name', directory, registry=registry).configure()

    def test_windows_existing_trailing_separator_is_preserved_without_a_new_empty_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = MemoryRegistry('C:\\existing;', kind=MemoryRegistry.REG_SZ)
            setup = WindowsPathConfigurator(r'C:\SWASSH\Scripts', directory, registry=registry)
            backup = setup.configure()
            self.assertEqual(json.loads(backup.read_text())['value'], 'C:\\existing;')
            self.assertEqual(registry.value, 'C:\\existing;C:\\SWASSH\\Scripts')
            self.assertEqual(registry.writes, [registry.value])
            self.assertNotIn(';;', registry.value)

    def test_windows_path_update_is_refused_while_the_configuration_lock_is_held(self):
        from swassh.infrastructure.bastion import FileLock
        from swassh.infrastructure.filesystem import private_directory
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = private_directory(root / '.swassh' / 'path-backups', tighten=True)
            registry = MemoryRegistry(r'C:\existing')
            lock = FileLock(folder / 'configuration.lock')
            try:
                self.assertTrue(lock.acquire())
                with self.assertRaisesRegex(ValueError, '^another SWASSH PATH configuration is in progress$'):
                    WindowsPathConfigurator(r'C:\SWASSH\Scripts', root, registry=registry).configure()
                self.assertEqual(registry.writes, [])
                self.assertEqual(list(folder.glob('*.json')), [])
            finally:
                lock.close()

    def test_windows_notification_reports_failure_without_claiming_parent_update(self):
        from swassh.infrastructure.installation import notify_windows_environment
        with patch('ctypes.WinDLL', create=True) as library:
            function = library.return_value.SendMessageTimeoutW
            function.return_value = 1
            notify_windows_environment()
            self.assertEqual(function.call_args.args[:4], (0xffff, 0x001a, 0, 'Environment'))
            function.return_value = 0
            with contextlib.redirect_stderr(io.StringIO()) as output:
                notify_windows_environment()
            self.assertIn('PATH saved', output.getvalue())
            self.assertIn('Sign out', output.getvalue())

    @unittest.skipUnless(os.name == 'nt', 'native Windows registry required')
    def test_native_registry_uses_disposable_key_and_preserves_real_path(self):
        import winreg
        key = 'Software\\SWASSH-Qualification-' + uuid.uuid4().hex
        try:
            with tempfile.TemporaryDirectory() as directory:
                setup = WindowsPathConfigurator(r'C:\SWASSH\Scripts', directory, key=key)
                backup = setup.configure()
                self.assertFalse(json.loads(backup.read_text())['existed'])
                self.assertIsNone(setup.configure())
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                    self.assertEqual(winreg.QueryValueEx(handle, 'Path')[0], r'C:\SWASSH\Scripts')
        finally:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
