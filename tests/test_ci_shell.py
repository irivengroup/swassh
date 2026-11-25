"""Real CI shell failures cannot be hidden; Windows owner checks remain strict."""
import ctypes
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('swassh_ci_shell', ROOT / 'scripts/ci_shell.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class OwnerTokenContracts(unittest.TestCase):
    def api(self, failure=None, wrong_owner=False):
        calls = []
        state = {'owner': 123}

        class Function:
            def __init__(self, name):
                self.name = name

            def __call__(self, *args):
                calls.append((self.name, args))
                if self.name == failure:
                    return 0
                if self.name == 'GetCurrentProcess':
                    return 22
                if self.name == 'OpenProcessToken':
                    args[2]._obj.value = 55
                if self.name == 'GetTokenInformation':
                    args[4]._obj.value = 32
                    if args[2] is not None:
                        sid = 77 if args[1] == 1 else state['owner']
                        ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p)).contents.value = sid
                if self.name == 'SetTokenInformation' and not wrong_owner:
                    state['owner'] = args[2]._obj.value
                if self.name == 'EqualSid':
                    return int(args[0] == args[1])
                return 1

        api = SimpleNamespace(**{name: Function(name) for name in (
            'GetCurrentProcess', 'OpenProcessToken', 'GetTokenInformation',
            'SetTokenInformation', 'EqualSid', 'CloseHandle')})
        return api, calls

    def test_only_default_owner_changes_and_the_token_always_closes(self):
        api, calls = self.api()
        CI.WindowsObjectOwner.apply(api, api)
        opened = next(args for name, args in calls if name == 'OpenProcessToken')
        self.assertEqual(opened[1], 0x88)
        changed = [args for name, args in calls if name == 'SetTokenInformation']
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0][1], 4)
        self.assertEqual(changed[0][2]._obj.value, 77)
        self.assertEqual(changed[0][3], ctypes.sizeof(ctypes.c_void_p))
        self.assertEqual([name for name, _ in calls].count('CloseHandle'), 1)
        self.assertEqual(calls[-1][0], 'CloseHandle')

    def test_refused_or_unverified_configuration_fails_instead_of_relaxing_ownership(self):
        for failure in ('OpenProcessToken', 'GetTokenInformation', 'SetTokenInformation', None):
            with self.subTest(failure=failure):
                api, calls = self.api(failure, wrong_owner=failure is None)
                with patch.object(ctypes, 'WinError', side_effect=OSError('fixture native refusal'), create=True), \
                     patch.object(ctypes, 'get_last_error', return_value=5, create=True), self.assertRaises(OSError):
                    CI.WindowsObjectOwner.apply(api, api)
                self.assertEqual([name for name, _ in calls].count('CloseHandle'),
                                 0 if failure == 'OpenProcessToken' else 1)


class ShellFailureContracts(unittest.TestCase):
    def test_quality_environment_preserves_both_frozen_lf_and_crlf_bytes(self):
        # Reproduce the corrupting checkout using a real Git configuration;
        # never rewrite an immutable oracle to match a transformed worktree.
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNotNone(shutil.which('git'), 'Git is required for CI byte-preservation QA')
            root = Path(temporary)
            seed = root / 'seed'
            seed.mkdir()
            config = root / 'global.gitconfig'
            config.write_text('[core]\n autocrlf = true\n')
            clean = {key: value for key, value in os.environ.items() if not key.startswith('GIT_CONFIG_')}
            clean.update(GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM='1')
            git = CI.ShellRunner.executable('git')

            def run(*args, env=clean):
                result = subprocess.run([git, *args], cwd=seed, env=env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)

            original = {'lf.txt': b'fixed source\n', 'crlf.txt': b'frozen oracle\r\n'}
            run('init', '--quiet')
            for name, data in original.items():
                (seed / name).write_bytes(data)
            run('-c', 'core.autocrlf=false', 'add', '.')
            run('-c', 'user.name=SWASSH CI fixture', '-c', 'user.email=ci@example.invalid',
                'commit', '--quiet', '-m', 'synthetic byte preservation fixture')
            before = root / 'before'
            run('clone', '--quiet', str(seed), str(before))
            self.assertNotEqual((before / 'lf.txt').read_bytes(), original['lf.txt'])
            lines = (ROOT / '.github/workflows/ci.yml').read_text().splitlines()
            header = lines[lines.index('  quality:'):lines.index('    steps:')]
            expected = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.autocrlf',
                        'GIT_CONFIG_VALUE_0': 'false'}
            for key, value in expected.items():
                self.assertIn('      ' + key + ': ' + ("'" + value + "'" if key != 'GIT_CONFIG_KEY_0' else value), header)
            self.assertIn('        shell: python scripts/ci_shell.py {0}', header)
            after = root / 'after'
            run('clone', '--quiet', str(seed), str(after), env=clean | expected)
            self.assertEqual({name: (after / name).read_bytes() for name in original}, original)

    def test_windows_script_keeps_strict_native_failures_and_returns_the_observed_code(self):
        observed = []

        def launch(argv, **kwargs):
            observed.append((argv, Path(argv[-1]).read_text(), kwargs))
            return SimpleNamespace(returncode=17)

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'command with spaces.tmp'
            source.write_text('Write-Output fixture\n')
            with patch.object(CI.WindowsObjectOwner, 'configure') as owner, \
                 patch.object(CI.ShellRunner, 'executable', return_value=str(source)), \
                 patch.object(CI.subprocess, 'run', side_effect=launch):
                self.assertEqual(CI.ShellRunner('nt').run(source), 17)
            owner.assert_called_once_with()
        argv, body, settings = observed[0]
        self.assertEqual(argv[1:5], ['-NoLogo', '-NoProfile', '-NonInteractive', '-File'])
        self.assertIn("$ErrorActionPreference = 'Stop'", body)
        self.assertIn('$PSNativeCommandUseErrorActionPreference = $true', body)
        self.assertIn('Write-Output fixture', body)
        self.assertEqual(settings, {'check': False})
        self.assertFalse(Path(argv[-1]).exists(), 'owned command copy leaked')

    def test_missing_shell_or_nonfile_command_refuses(self):
        with patch.object(CI.shutil, 'which', return_value=None), self.assertRaises(OSError):
            CI.ShellRunner.executable('bash')
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            CI.ShellRunner('posix').run(temporary)

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'native POSIX CI shell')
    def test_real_bash_failure_and_pipeline_failure_never_reach_later_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            command = Path(temporary) / 'command with spaces.tmp'
            marker = Path(temporary) / 'must-not-exist'
            for prefix in ('false', 'false | true'):
                command.write_text(prefix + '\nprintf unsafe > "' + str(marker) + '"\n')
                self.assertNotEqual(CI.ShellRunner().run(command), 0)
                self.assertFalse(marker.exists())
            command.write_text('exit 0\n')
            self.assertEqual(CI.ShellRunner().run(command), 0)

    @unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'native Windows CI token and PowerShell')
    def test_real_windows_child_owns_private_objects_and_cannot_hide_a_native_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command, probe = root / 'command.tmp', root / 'probe.py'
            probe.write_text("from pathlib import Path\nimport tempfile\n"
                             "from swassh.infrastructure.filesystem import private_directory\n"
                             "with tempfile.TemporaryDirectory() as d:\n"
                             " assert private_directory(Path(d),tighten=True).is_dir()\n")
            quoted = str(sys.executable).replace("'", "''")
            command.write_text("& '" + quoted + "' '" + str(probe).replace("'", "''") + "'\n")
            self.assertEqual(CI.ShellRunner().run(command), 0)
            marker = root / 'must-not-exist'
            command.write_text("& '" + quoted + "' -c 'raise SystemExit(7)'\n"
                               "Set-Content -LiteralPath '" + str(marker).replace("'", "''") + "' unsafe\nexit 0\n")
            self.assertNotEqual(CI.ShellRunner().run(command), 0)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
