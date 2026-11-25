"""Cross-platform capabilities, conservative admission and native service methods."""
import asyncio
import contextlib
import ctypes
import io
import json
import os
import runpy
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from swassh import Options
from swassh.infrastructure import resources
from swassh.infrastructure.filesystem import _open_directory, private_directory, sync_directory
from swassh.infrastructure.lifecycle import ensure_subprocess_loop

ROOT = Path(__file__).resolve().parents[1]
SERVICE = runpy.run_path(str(ROOT / 'scripts/scheduler_service.py'))


class NativeNetworkGateTests(unittest.TestCase):
    def test_missing_skipped_failed_or_incomplete_suite_never_qualifies(self):
        gate = runpy.run_path(str(ROOT/'scripts/native_network_gate.py'))['NativeNetworkGate']
        result = unittest.TestResult()
        self.assertFalse(gate.complete(result, 0))
        self.assertFalse(gate.complete(result, 1))
        result.testsRun = 1
        self.assertTrue(gate.complete(result, 1))
        result.skipped.append(('native test', 'server unavailable'))
        self.assertFalse(gate.complete(result, 1))
        result.skipped.clear()
        result.failures.append(('native test', 'failed assertion'))
        self.assertFalse(gate.complete(result, 1))


class ResourcePortabilityTests(unittest.TestCase):
    def test_non_linux_never_reads_linux_procfs(self):
        for platform in ('sunos5', 'aix7', 'darwin'):
            with self.subTest(platform=platform), patch.object(sys, 'platform', platform), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('Linux-only path read')), \
                    patch.object(os, 'sysconf', side_effect=[123, 4096], create=True):
                self.assertEqual(resources._available_memory(), 123 * 4096)

    def test_linux_probe_precedence_and_fallback(self):
        with patch.object(sys, 'platform', 'linux'), patch.object(resources, '_linux_available_memory', return_value=0), \
                patch.object(resources, '_sysconf_available_memory') as fallback:
            self.assertEqual(resources._available_memory(), 0)
            fallback.assert_not_called()
        with patch.object(sys, 'platform', 'linux'), patch.object(resources, '_linux_available_memory', return_value=None), \
                patch.object(resources, '_sysconf_available_memory', return_value=100):
            self.assertEqual(resources._available_memory(), 100)

    def test_sysconf_failure_never_uses_total_physical_memory(self):
        for error in (OSError(), ValueError(), KeyError(), AttributeError()):
            with self.subTest(error=error), patch.object(os, 'sysconf', side_effect=error, create=True) as query:
                self.assertIsNone(resources._sysconf_available_memory())
                self.assertEqual(query.call_args.args, ('SC_AVPHYS_PAGES',))
        for values in ((-1, 4096), (1, 0), (True, 4096), ('100', 4096)):
            with patch.object(os, 'sysconf', side_effect=values, create=True):
                self.assertIsNone(resources._sysconf_available_memory())
        with patch.object(os, 'sysconf', side_effect=[2**48, 4096], create=True):
            self.assertEqual(resources._sysconf_available_memory(), 2**60)

    def test_windows_memory_structure_and_probe_failures(self):
        calls = []
        class Query:
            def __call__(self, pointer):
                data = pointer._obj
                calls.append((data.length, ctypes.sizeof(data)))
                data.available_physical = 2**40
                return 1
        kernel = types.SimpleNamespace(GlobalMemoryStatusEx=Query())
        with patch.object(ctypes, 'WinDLL', return_value=kernel, create=True):
            self.assertEqual(resources._windows_available_memory(), 2**40)
        self.assertEqual(calls, [(64, 64)])
        kernel.GlobalMemoryStatusEx = types.SimpleNamespace()
        with patch.object(ctypes, 'WinDLL', side_effect=OSError('unavailable'), create=True):
            self.assertIsNone(resources._windows_available_memory())
        class Failure:
            def __call__(self, pointer):
                return 0
        kernel.GlobalMemoryStatusEx = Failure()
        with patch.object(ctypes, 'WinDLL', return_value=kernel, create=True):
            self.assertIsNone(resources._windows_available_memory())
        with patch.object(sys, 'platform', 'win32'), \
                patch.object(resources, '_windows_available_memory', return_value=128), \
                patch.object(resources, '_sysconf_available_memory', side_effect=AssertionError()):
            self.assertEqual(resources._available_memory(), 128)

    def test_posix_descriptor_listing_and_safe_absent_fallback(self):
        fake = types.SimpleNamespace(RLIMIT_NOFILE=7, RLIM_INFINITY=-1, getrlimit=lambda _: (256, 256))
        with patch.dict(sys.modules, {'resource':fake}), patch.object(sys, 'platform', 'aix7'), \
                patch.object(os, 'listdir', return_value=['0', '1', '2']) as listing:
            self.assertEqual(resources._descriptor_workers(False), (256-3-64)//4)
            self.assertEqual(listing.call_args.args, ('/dev/fd',))
        with patch.dict(sys.modules, {'resource':fake}), patch.object(os, 'listdir', side_effect=OSError()):
            self.assertEqual(resources._descriptor_workers(True), 16)
        fake.getrlimit = lambda _: (128, 128)
        with patch.dict(sys.modules, {'resource':fake}), patch.object(os, 'listdir', side_effect=OSError()), self.assertRaises(ValueError):
            resources._descriptor_workers(False)

    def test_descriptor_unsupported_and_infinite_limits(self):
        fake = types.SimpleNamespace(RLIMIT_NOFILE=7, RLIM_INFINITY=-1, getrlimit=lambda _: (-1, -1))
        with patch.dict(sys.modules, {'resource':fake}):
            self.assertEqual(resources._descriptor_workers(False), 256)
        with patch.dict(sys.modules, {'resource':types.SimpleNamespace()}):
            self.assertEqual(resources._descriptor_workers(False), 64)
        def error(_):
            raise OSError('unsupported resource')
        fake.getrlimit = error
        with patch.dict(sys.modules, {'resource':fake}):
            self.assertEqual(resources._descriptor_workers(False), 64)

    def test_unknown_memory_remains_bounded_by_explicit_budget(self):
        with patch.object(resources, '_available_memory', return_value=None), \
                patch.object(resources, '_descriptor_workers', return_value=64):
            plan = resources.resource_plan(Options(concurrency=10000))
            self.assertLessEqual(plan.workers, 14)
            self.assertEqual(plan.memory_budget_bytes, 128 * 1024**2)
        with patch.object(resources, '_available_memory', return_value=0), self.assertRaises(ValueError):
            resources.resource_plan(Options())


class LoopPortabilityTests(unittest.TestCase):
    def test_posix_has_no_windows_event_loop_dependency(self):
        for value in ('linux', 'sunos5', 'aix7', 'darwin'):
            with patch.object(sys, 'platform', value), patch.object(asyncio, 'get_running_loop', side_effect=AssertionError()):
                ensure_subprocess_loop()

    def test_windows_requires_subprocess_capable_loop_without_changing_policy(self):
        class Proactor:
            pass
        with patch.object(sys, 'platform', 'win32'), patch.object(asyncio, 'ProactorEventLoop', Proactor, create=True), \
                patch.object(asyncio, 'get_running_loop', return_value=object()), self.assertRaises(ValueError):
            ensure_subprocess_loop()
        with patch.object(sys, 'platform', 'win32'), patch.object(asyncio, 'ProactorEventLoop', Proactor, create=True), \
                patch.object(asyncio, 'get_running_loop', return_value=Proactor()):
            ensure_subprocess_loop()


@unittest.skipUnless(os.name == 'posix', 'native POSIX directory and shell primitives')
class DirectoryPortabilityTests(unittest.TestCase):
    def test_directory_descriptor_without_optional_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)/'private'
            with patch.dict(os.__dict__):
                os.__dict__.pop('O_DIRECTORY', None)
                os.__dict__.pop('O_NOFOLLOW', None)
                self.assertEqual(private_directory(folder, tighten=True), folder.resolve())
                self.assertIsInstance(sync_directory(folder), bool)
                file = folder/'file'
                file.write_bytes(b'x')
                with self.assertRaises(ValueError):
                    _open_directory(file)


class ServicePortabilityTests(unittest.TestCase):
    def test_smf_contract_credentials_literal_method_and_disabled_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            method = Path(directory)/'service %m "quoted".sh'
            name, data = SERVICE['generate']('smf', sys.executable, directory, 'swassh', method_path=method)
            self.assertEqual(name, 'swassh-scheduler-smf.xml')
            self.assertIn(b'<!DOCTYPE service_bundle SYSTEM', data)
            service = ET.fromstring(data).find('service')
            self.assertEqual(service.find('create_default_instance').get('enabled'), 'false')
            self.assertEqual(service.find("property_group/propval").get('value'), 'contract')
            self.assertEqual(service.find("exec_method[@name='start']/method_context/method_credential").get('user'), 'swassh')
            self.assertIn('%%m', service.find("exec_method[@name='start']").get('exec'))
            self.assertEqual(service.find("exec_method[@name='stop']").get('exec'), ':kill')
            with self.assertRaises(ValueError):
                SERVICE['generate']('smf', sys.executable, directory)
            with self.assertRaises(ValueError):
                SERVICE['generate']('smf', sys.executable, directory, 'bad\nuser', method_path=method)

    def test_two_file_smf_creation_and_partial_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = ['--platform','smf','--state-dir',str(root/'state'),'--output-dir',directory]
            with contextlib.redirect_stdout(io.StringIO()):
                SERVICE['main'](argv)
            method, manifest = root/'swassh-scheduler-smf.sh', root/'swassh-scheduler-smf.xml'
            self.assertTrue(method.read_bytes())
            ET.fromstring(manifest.read_bytes())
            if os.name == 'posix':
                self.assertEqual(method.stat().st_mode & 0o777, 0o700)
                self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            original = method.read_bytes()
            with self.assertRaises(FileExistsError):
                SERVICE['main'](argv)
            self.assertEqual(method.read_bytes(), original)
            method.unlink()
            with self.assertRaises(FileExistsError):
                SERVICE['main'](argv)
            self.assertFalse(method.exists())
            self.assertTrue(manifest.read_bytes())

    def test_src_foreground_and_private_mask(self):
        name, data = SERVICE['generate']('src', sys.executable, '/var/tmp/state with spaces')
        self.assertEqual(name, 'swassh-scheduler-src.sh')
        self.assertTrue(data.startswith(b'#!/bin/sh\numask 077\nexec '))
        self.assertNotIn(b' &\n', data)
        self.assertIn(b'--state-dir', data)

    @unittest.skipUnless(os.name == 'posix', 'native POSIX service method execution')
    def test_src_quotes_paths_and_executes_without_local_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root/'python fixture'
            program.write_text('#!' + sys.executable + '\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
            program.chmod(0o700)
            marker = root/'not-created'
            state = root/('state\' ; $(touch ' + str(marker) + ') %')
            script = root/'method.sh'
            script.write_bytes(SERVICE['worker_script'](str(program), str(state)))
            completed = subprocess.run(['/bin/sh',str(script)], capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout), ['-m','swassh','schedule','--worker','--state-dir',str(state)])
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == 'posix', 'native SMF method early-exit detection')
    def test_smf_method_detects_early_worker_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root/'fails'
            program.write_text('#!/bin/sh\nexit 7\n')
            program.chmod(0o700)
            script = root/'method.sh'
            script.write_bytes(SERVICE['worker_script'](str(program), directory, background=True))
            completed = subprocess.run(['/bin/sh',str(script)], capture_output=True, timeout=10)
            self.assertEqual(completed.returncode, 1)


class CertificationBridgeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = runpy.run_path(str(ROOT/'scripts/remote_portability.py'))
        self.probe = runpy.run_path(str(ROOT/'scripts/platform_gate.py'))

    def test_expected_os_and_unsupported_clients_rejected_before_probe(self):
        with patch('platform.system', return_value='Linux'), self.assertRaises(ValueError):
            self.probe['probe']('aix')
        with patch('shutil.which', return_value=None), self.assertRaises(ValueError):
            self.probe['probe']()
        with patch('shutil.which', return_value='/native/tool'), \
                patch('subprocess.run', return_value=subprocess.CompletedProcess([],0,'rsync version 3.2.7')), \
                patch('os.name','posix'), self.assertRaises(ValueError):
            self.probe['probe'](require_rsync=True)

    def test_remote_argv_literal_paths_and_complete_gate(self):
        checkout = '/srv/checkout \'; $(touch /tmp/never-created) %'
        command = self.bridge['remote_command']('aix','/opt/python with spaces',checkout)
        argv = shlex.split(command)
        self.assertEqual(argv[:2], ['/opt/python with spaces','-c'])
        compile(argv[2], '<remote-certification>', 'exec')
        self.assertIn(repr(checkout), argv[2])
        self.assertIn('source file set drift', argv[2])
        self.assertIn('validate_installation.py', argv[2])
        self.assertIn('--require-rsync', argv[2])
        self.assertLess(len(command.encode()), 65536)
        for platform, python, path in (('windows','/python','/tree'),('aix','python','/tree'),('solaris','/python','/a/../tree')):
            with self.assertRaises(ValueError):
                self.bridge['remote_command'](platform,python,path)

    def fixture(self, directory):
        root = Path(directory)/'checkout'
        root.mkdir()
        (root/'pyproject.toml').write_text('fixture project\n')
        (root/'scripts').mkdir()
        marker = Path(directory)/'gates'
        for name in ('platform_gate.py','verify.py','coverage.py','build.py','validate_installation.py','package.py'):
            (root/'scripts'/name).write_text('from pathlib import Path\np=Path(' + repr(str(marker)) + ')\n'
                'with p.open("a") as stream: stream.write(' + repr(name+'\n') + ')\n')
        self.bridge['source_manifest'].__globals__['ROOT'] = root
        code = shlex.split(self.bridge['remote_command']('aix','/opt/python',str(root).replace('\\','/') if os.name=='posix' else '/fixture'))[2]
        if os.name == 'nt':
            code = code.replace(repr('/fixture'), repr(str(root)))
        return root, marker, 'import platform\nplatform.system=lambda:"AIX"\n'+code

    def test_identical_checkout_runs_every_gate_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root, marker, code = self.fixture(directory)
            process = subprocess.run([sys.executable,'-c',code], capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertEqual(marker.read_text().splitlines(), ['platform_gate.py','verify.py','coverage.py','build.py','validate_installation.py','package.py'])
            self.assertIn('NATIVE_PORTABILITY_GATE=PASS',process.stdout)

    def test_source_drift_and_extra_modules_block_even_optimized_python(self):
        for mode in ('modified','extra'):
            with tempfile.TemporaryDirectory() as directory:
                root, marker, code = self.fixture(directory)
                path = root/'scripts/verify.py' if mode=='modified' else root/'scripts/stale.py'
                path.write_text('untrusted source\n')
                process = subprocess.run([sys.executable,'-O','-c',code], capture_output=True, text=True, timeout=15)
                self.assertNotEqual(process.returncode,0)
                self.assertIn('drift',process.stderr)
                self.assertFalse(marker.exists())

    def test_bridge_invalid_inputs_never_contact_transport(self):
        with contextlib.redirect_stderr(io.StringIO()), patch('asyncio.run') as run:
            result = self.bridge['main'](['--platform','aix','--host','invalid host',
                '--python','/python','--checkout','/tree','--report','report.json'])
        self.assertEqual(result,2)
        run.assert_not_called()


class EffectiveOpenSSHCompatibilityTests(unittest.TestCase):
    """The native probe must verify effective security settings, not only exit zero."""

    # Independent vectors derived from SWASSH's fixed configuration and native
    # Windows OpenSSH output. Other client options remain implementation-specific.
    EFFECTIVE = b"""hostname probe.invalid
port 22
batchmode yes
stricthostkeychecking true
forwardagent no
forwardx11 no
permitlocalcommand no
passwordauthentication no
kbdinteractiveauthentication no
controlmaster false
requesttty false
clearallforwardings yes
tunnel false
updatehostkeys false
verifyhostkeydns false
addkeystoagent false
connectionattempts 1
serveraliveinterval 5
serveralivecountmax 2
"""

    def _probe(self, payload):
        module = runpy.run_path(str(ROOT/'scripts/platform_gate.py'))
        scope = module['probe'].__globals__
        completed = subprocess.CompletedProcess([], 0, payload, b'')
        with patch('shutil.which', side_effect=['synthetic-ssh', 'synthetic-sftp', None]), \
                patch('subprocess.run', return_value=completed) as execute, \
                patch.dict(scope, storage_probe=unittest.mock.AsyncMock(return_value={'synthetic': True})), \
                patch.dict(scope, resource_plan=lambda *args, **kwargs: types.SimpleNamespace(to_dict=lambda: {})):
            result = module['probe']()
        self.assertTrue(result['ssh_config_native'])
        self.assertEqual(result['network_connections'], 0)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(execute.call_args.kwargs['timeout'], 10)
        self.assertEqual(execute.call_args.args[0][1], '-G')
        return result

    def test_native_zero_exit_cannot_hide_a_missing_ignored_or_ambiguous_policy(self):
        variants = [b'', b'OpenSSH-compatible client\n', self.EFFECTIVE.replace(b'stricthostkeychecking true', b'stricthostkeychecking no'),
            self.EFFECTIVE.replace(b'forwardagent no', b'forwardagent yes'),
            self.EFFECTIVE.replace(b'permitlocalcommand no', b'permitlocalcommand yes'),
            self.EFFECTIVE.replace(b'batchmode yes', b'batchmode no'),
            self.EFFECTIVE.replace(b'hostname probe.invalid', b'hostname other.invalid'),
            self.EFFECTIVE.replace(b'port 22', b'port 2222'),
            self.EFFECTIVE.replace(b'connectionattempts 1', b'connectionattempts 9'),
            self.EFFECTIVE.replace(b'serveraliveinterval 5\n', b''),
            self.EFFECTIVE + b'stricthostkeychecking true\n', self.EFFECTIVE + b'unknown\n',
            self.EFFECTIVE + b'unknown \x00hidden\n', self.EFFECTIVE + b'unknown \xff\n', b'x' * 131073]
        for payload in variants:
            with self.subTest(payload=payload[:50]), self.assertRaises(ValueError):
                self._probe(payload)

    def test_canonical_boolean_spellings_and_unrelated_options_remain_compatible(self):
        self._probe(self.EFFECTIVE)
        alternate = self.EFFECTIVE.replace(b' true', b' yes').replace(b' false', b' no')
        alternate = alternate.replace(b'\n', b'\r\n') + 'user exemple\nidentityfile chemin-été\n'.encode('utf-8')
        self._probe(alternate)

    def test_every_required_effective_option_has_a_strict_refusal_boundary(self):
        for line in self.EFFECTIVE.splitlines(keepends=True):
            key = line.split()[0]
            with self.subTest(option=key), self.assertRaises(ValueError):
                self._probe(self.EFFECTIVE.replace(line, key + b' unsupported\n'))


    def test_native_configuration_preserves_unicode_with_a_legacy_file_encoding(self):
        """A Unicode profile must reach OpenSSH as UTF-8 under every locale."""
        module = runpy.run_path(str(ROOT/'scripts/platform_gate.py'))
        scope = module['probe'].__globals__
        known_hosts = str(ROOT/'profil-漢字-été'/'known_hosts')
        config_text = scope['_config'](scope['Host']('probe.invalid'), Options(known_hosts=known_hosts))
        original_open = Path.open
        observed = []
        def legacy_open(path, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
            # Emulate a non-UTF-8 locale on POSIX too, without changing valid I/O.
            if 'b' not in mode and encoding in (None, 'locale'):
                encoding = 'cp1252'
            return original_open(path, mode, buffering, encoding, errors, newline)
        def native(command, **kwargs):
            raw = Path(command[3]).read_bytes()
            observed.append(raw)
            self.assertEqual(raw.decode('utf-8').replace('\r\n', '\n'), config_text)
            self.assertIn('profil-漢字-été'.encode('utf-8'), raw)
            return subprocess.CompletedProcess(command, 0, self.EFFECTIVE, b'')
        with patch('shutil.which', side_effect=['synthetic-ssh', 'synthetic-sftp', None]), \
                patch.object(Path, 'open', legacy_open), \
                patch('subprocess.run', side_effect=native), \
                patch.dict(scope, _config=lambda *args: config_text), \
                patch.dict(scope, storage_probe=unittest.mock.AsyncMock(return_value={'synthetic': True})), \
                patch.dict(scope, resource_plan=lambda *args, **kwargs: types.SimpleNamespace(to_dict=lambda: {})):
            result = module['probe']()
        self.assertEqual(len(observed), 1)
        self.assertTrue(result['ssh_config_native'])
        self.assertEqual(result['network_connections'], 0)
