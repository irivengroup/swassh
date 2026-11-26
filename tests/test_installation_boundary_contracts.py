"""Installation routing uses memory ports; the operator's PATH is never changed."""
import contextlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch

from swassh.infrastructure import installation,progress


class ProfilePolicyUnitTests(unittest.TestCase):
    """Profile policy with memory filesystem ports and real path-value rules."""

    class PosixValue(PurePosixPath):
        def absolute(self):
            if not self.is_absolute():
                raise AssertionError('fixture paths must already be absolute')
            return self

    class Text(io.StringIO):
        def __init__(self, text='', descriptor=41):
            super().__init__(text)
            self.descriptor = descriptor

        def fileno(self):
            return self.descriptor

    @contextlib.contextmanager
    def backend(self, original, *, mode=stat.S_IFREG | 0o600, links=1, uid=1000,
                ownership=True, chmod=True):
        profile = self.PosixValue('/synthetic-home/.profile')
        state = {'content': original, 'writes': {}, 'modes': [], 'opened': []}
        port = SimpleNamespace(**vars(os))
        port.name, port.environ = ('posix' if ownership else 'nt'), {}
        if ownership:
            port.geteuid = lambda: 1000
        elif hasattr(port, 'geteuid'):
            del port.geteuid
        def fstat(descriptor):
            if descriptor != 41:
                raise AssertionError('unexpected read descriptor')
            return SimpleNamespace(st_mode=mode, st_nlink=links,
                                   st_uid=uid, st_size=len(state['content'].encode('utf-8')))
        def fdopen(descriptor, *args, **kwargs):
            if descriptor != 41:
                raise AssertionError('unexpected read descriptor')
            return self.Text(state['content'])
        port.fstat, port.fdopen = fstat, fdopen
        if chmod:
            port.fchmod = lambda descriptor, value: state['modes'].append((descriptor, value))
        elif hasattr(port, 'fchmod'):
            del port.fchmod
        class Directory:
            def open(self, name, flags):
                state['opened'].append((name, flags))
                return 41
        @contextlib.contextmanager
        def atomic(path):
            stream = self.Text(descriptor=42)
            try:
                yield stream
                text = stream.getvalue()
                state['writes'][str(path)] = text
                if path == profile:
                    state['content'] = text
            finally:
                stream.close()
        with patch.object(installation, 'Path', self.PosixValue), \
                patch.object(installation, 'os', port), \
                patch.object(installation, 'PinnedDirectory', return_value=contextlib.nullcontext(Directory())), \
                patch.object(installation, 'AtomicOutput', side_effect=atomic):
            setup = installation.PathConfigurator('/synthetic/scripts', '/synthetic-home', '/bin/sh')
            yield setup, state, profile

    def test_unsafe_profile_metadata_is_refused_before_read_or_atomic_write(self):
        for label, fields in (('pipe', {'mode': stat.S_IFIFO | 0o600}),
                              ('linked', {'links': 2}), ('foreign-owner', {'uid': 1001}),
                              ('group-writable', {'mode': stat.S_IFREG | 0o620})):
            with self.subTest(label=label), self.backend('retained\n', **fields) as (setup, state, profile):
                with self.assertRaisesRegex(ValueError, '^profile must be a private regular file owned by this user$'):
                    setup.configure()
                self.assertEqual(state['content'], 'retained\n')
                self.assertEqual(state['writes'], {})
        content = 'x' * (1024 * 1024 + 1)
        with self.backend(content) as (setup, state, profile):
            with self.assertRaisesRegex(ValueError, '^profile must be a private regular file owned by this user$'):
                setup.configure()
            self.assertEqual(state['content'], content)
            self.assertEqual(state['writes'], {})

    def test_normal_profile_keeps_exact_backup_modes_and_idempotence(self):
        original = 'export EDITOR=vi\n'
        for ownership, chmod in ((True, True), (False, False)):
            with self.subTest(ownership=ownership, chmod=chmod), self.backend(
                    original, ownership=ownership, chmod=chmod) as (setup, state, profile):
                backups = setup.configure()
                self.assertEqual(len(backups), 1)
                self.assertEqual(state['writes'][str(backups[0])], original)
                self.assertTrue(state['content'].startswith(original))
                self.assertIn('${PATH:+${PATH}:}', state['content'])
                self.assertEqual(state['modes'], [(42, 0o600)] if chmod else [])
                before = dict(state['writes'])
                self.assertEqual(setup.configure(), [])
                self.assertEqual(state['writes'], before)

    def test_legacy_profile_block_is_migrated_with_a_verbatim_backup(self):
        original = ('\n# SWASSH PATH /synthetic/scripts\ncase ":$PATH:" in\n'
                    '  *:/synthetic/scripts:*) ;;\n'
                    '  *) export PATH="$PATH":/synthetic/scripts ;;\nesac\n')
        with self.backend(original) as (setup, state, profile):
            backups = setup.configure()
            self.assertEqual(len(backups), 1)
            self.assertEqual(state['writes'][str(backups[0])], original)
            self.assertNotIn('case ":$PATH:"', state['content'])
            self.assertIn('case ":${PATH-}:"', state['content'])
            self.assertEqual(state['content'].count('# SWASSH PATH /synthetic/scripts'), 1)

    def test_bash_without_existing_startup_files_uses_the_default_login_profile(self):
        looked_up = []
        class MissingProfilePath(self.PosixValue):
            def exists(self):
                looked_up.append(str(self))
                return False
        port = SimpleNamespace(**vars(os))
        port.name = 'posix'
        with patch.object(installation, 'Path', MissingProfilePath), patch.object(installation, 'os', port):
            setup = installation.PathConfigurator('/synthetic/scripts', '/synthetic-home', '/bin/bash')
            self.assertEqual([str(path) for path in setup.profiles()],
                             ['/synthetic-home/.profile', '/synthetic-home/.bashrc'])
        self.assertEqual(looked_up, ['/synthetic-home/.bash_profile', '/synthetic-home/.bash_login',
                                    '/synthetic-home/.profile'])


class InstallationBoundaryTests(unittest.TestCase):
    def test_stale_distribution_entry_falls_back_to_the_platform_console_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            scripts = root / 'scripts'
            scripts.mkdir()
            (scripts / 'swassh').write_text('synthetic console entry', encoding='utf-8')
            distribution = SimpleNamespace(files=[Path('swassh')],
                                           locate_file=lambda entry: root / 'removed' / entry)
            port = SimpleNamespace(**vars(os))
            port.name = 'posix'
            with patch.object(installation, 'os', port), \
                    patch.object(installation.importlib.metadata, 'distribution', return_value=distribution), \
                    patch.object(installation.sysconfig, 'get_path', return_value=str(scripts)):
                self.assertEqual(installation.installed_scripts(), scripts)

    def test_explicit_venv_scope_and_empty_path_component_do_not_modify_the_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory).resolve()
            port = SimpleNamespace(**vars(os))
            port.get_exec_path = lambda: ['', str(scripts)]
            output = io.StringIO()
            with patch.object(installation, 'os', port), \
                    patch.object(installation, 'installed_scripts', return_value=scripts), \
                    patch.object(installation.shutil, 'which', return_value=str(scripts / 'swassh')), \
                    patch.object(installation.sys, 'prefix', 'retained-application'), \
                    patch.object(installation.sys, 'base_prefix', 'base'), \
                    patch.object(installation.PathConfigurator, 'configure', side_effect=AssertionError('must not change profiles')) as posix, \
                    patch.object(installation.WindowsPathConfigurator, 'configure', side_effect=AssertionError('must not change registry')) as windows, \
                    contextlib.redirect_stdout(output):
                installation.setup_path(allow_venv=True)
            posix.assert_not_called()
            windows.assert_not_called()
            self.assertIn('already in PATH; no change required', output.getvalue())

    def test_setup_routes_to_current_platform_and_announces_only_observed_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();scripts=root/'scripts';scripts.mkdir()
            for platform,changed in (('nt',False),('nt',True),('posix',False),('posix',True)):
                port=SimpleNamespace(**vars(os));port.name=platform;port.get_exec_path=lambda:[]
                configurator=Mock();configurator.configure.return_value=(root/'backup.json' if changed else None) if platform=='nt' else ([root/'backup'] if changed else [])
                configurator.command.return_value='controlled current-shell command'
                output=io.StringIO()
                with patch.object(installation,'os',port),patch.object(installation,'installed_scripts',return_value=scripts),\
                        patch.object(installation.shutil,'which',return_value=None),patch.object(installation.Path,'home',return_value=root),\
                        patch.object(installation,'WindowsPathConfigurator',return_value=configurator) as windows,\
                        patch.object(installation,'PathConfigurator',return_value=configurator) as posix,\
                        patch.object(installation,'notify_windows_environment') as notify,\
                        patch.object(installation.sys,'prefix','base'),patch.object(installation.sys,'base_prefix','base'),\
                        contextlib.redirect_stdout(output):installation.setup_path()
                self.assertEqual(windows.call_count,int(platform=='nt'));self.assertEqual(posix.call_count,int(platform=='posix'))
                self.assertEqual(notify.call_count,int(platform=='nt' and changed))
                self.assertIn('Open a new terminal' if platform=='nt' else 'current shell',output.getvalue())
                if changed:self.assertIn('Backup:' if platform=='nt' else 'Profile backup:',output.getvalue())

    def test_installed_entrypoint_lookup_refuses_missing_package_and_absent_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();scripts=root/'scripts';scripts.mkdir()
            missing=installation.importlib.metadata.PackageNotFoundError('swassh')
            with patch.object(installation.importlib.metadata,'distribution',side_effect=missing),self.assertRaisesRegex(ValueError,'install the SWASSH wheel'):
                installation.installed_scripts()
            distribution=SimpleNamespace(files=None)
            with patch.object(installation.importlib.metadata,'distribution',return_value=distribution),\
                    patch.object(installation.sysconfig,'get_path',return_value=str(scripts)):
                with self.assertRaisesRegex(ValueError,'entrypoint not found'):installation.installed_scripts()
                name='swassh.exe' if os.name=='nt' else 'swassh';(scripts/name).write_bytes(b'synthetic')
                self.assertEqual(installation.installed_scripts(),scripts)
                distribution.files=[Path('metadata'),Path(name)]
                distribution.locate_file=lambda file:scripts/file
                self.assertEqual(installation.installed_scripts(),scripts)

    def test_virtual_environment_requires_explicit_retained_application_scope(self):
        with patch.object(installation.sys,'prefix','application'),patch.object(installation.sys,'base_prefix','base'),\
                patch.object(installation,'installed_scripts') as installed:
            with self.assertRaisesRegex(ValueError,'activate the virtual environment'):installation.setup_path()
            installed.assert_not_called()


class QualityProbeGuardIntegrationTests(unittest.TestCase):
    """Mandatory probe checks retain their frozen predicates under python -O."""

    def test_every_original_quality_predicate_and_failure_message_is_preserved(self):
        import ast
        import hashlib
        import json
        import sys
        def dump(node):
            options = {"show_empty": True} if sys.version_info >= (3, 13) else {}
            return ast.dump(node, include_attributes=False, **options)
        root = Path(__file__).resolve().parents[1]
        expected = {'scripts/benchmark.py': ['1944243da8c16dcd2655413b032003d7c3546a4d9fda721f35f121d7e5732670', '7fb8b2da9a9af29ed71408412d9268084b36684e20131cbbeaf6eb1603da22d8'], 'scripts/qualify_schedule.py': ['97444b3b6a8b82e5d3f310c710208de51438b963c9eac68ef6e5bb2ce696a289', 'e7f96dfa1b50eabcf98756af7a73a45e4e72d8cf601c149de484e34b6ae3327a', '4f0e3b506a9c7bd9d1b293124becc894b4d52a764341fa5c0b0f578e3355a5ac', '2aee6cf42a11a3cfa65f88c7958c572f20bbc70171b2a92016bd76e71aa581f7', 'a6de4214cce674802de54f963e1077655cc91ce66f1574e524dd94bfee204956', '114172717d152bad94f8b6277109e2f177e2a8fb125d5c04f5b337312edee522'], 'scripts/validate_deployment.py': ['e2a8cdc5392f78c4b1493d7a913222018f60846cdb6b2500845850a59995d5cf', '3a7b99f0950f33d4e49575b46700bffafb7dff45319f3b5865aab33b2f7e4ba3', 'cb7286b8e36e97c9e508a2a3608b6bd23a58b445349dbcb3396747e9ac8fe773', '4ed74cfba6f06ef69e4a144f1f28105fe5ccc521fced6e016e0a47bdea0e9a47', 'f1aefeec954a9fc98c6659627f9c87ee13e67a62006a2aed43cc0f87ed4325ec', '3b85ee3890861e723309ce3bf049b40d8ea6daaa2d4c2935e326a034c1fcacfc', 'f1aefeec954a9fc98c6659627f9c87ee13e67a62006a2aed43cc0f87ed4325ec'], 'scripts/validate_installation.py': ['2f98938c4f47c48e23ee6cde559f4d7fe1e3add419416867d943c1d8528d672e', 'f7170202fa1871a68b9b04f440f2d2452e1693044e15ae4dabaec815696bd799', '6da35cba9386976f10c5262d4ecd2f6e21697f2618958a66a08c5f5ab7633694', '57b66a20dfe6f3509c32312279eb8bb8d068abd309ea0667db0ea775defa22a5', '70d70769e76ac47d0c9982428402067cbada163d5a2a8a8414448d0855a33117', 'e041942e138fadc80c07e4a8726f7381fe07e705c38c9c09631c8d9bc49ee8b8', 'd3900f63b69021affcb1b43465b2cbf0281814e0bbadb0f7a0d65b6deee6b0f6', 'c81bbf126480afc033d5c382c95272993a708ff4278575096a90e025a261f85d', '1658cd1b517afec0db3703fddc3881311a70d931ab5053fc17fbee0792a8acc8', 'd4529a953147b2b5fadd6851d365b4a748920a261fe8e6e957ae82ddfa60841f', '5a634344d8177c70e97225260c7dfe45367b81843d126e17b404afa72edd95b5', '8edcaaaad778486db9a588e7e22b55e4ad5f71eb705fa80f8ef7a55e35dd03b5', '1399d0c421a43b7c941300a569485c1dc30311ac698b572eab1a14a18a987f26', '292ea37087a1965e7453eed95c57e20b97acfd69515f8bceed2ba6213f6a908a', 'aa7a08eb3b80dd314aaf4b3fd43492bafbd4ba16e48fc113c4a295ce969d40c6', 'dfea791aa68b95685eb7ccb3884b1d5137fe8172dbbb20d50c79498564a60dd5', 'f7a888ae3e30dab2a633579163e5624b14d5ea8eac5f30dd2088e09f59487d7e', '0dd3f971312b800e0fe0119ac4e563f5424f2d3c69781cdfe7d06cea578ff32b', '4eec60e962a0bda834dbe74aa1f9df7e31e87d14f900fccb25b5a7465ee8542e', 'a3a15c61cf31605026f5470882bf38d692f38b315fa340fffb926e27601889d7', '0324dce3dc7fdc13e58ffc2edc2f3f2aff87a06630d4c4ab3b1b2b4823b32f2a', 'b04333319ba23c7654ed3940d0ca5607ff2f3573c6d07433dab118f7773ebf31', 'dd3ebb062e0e91fe6403e13bd5ffe4d7af6b9d312d1648417ce27fc411338104', 'af268cac07c05d5d93d253fa8189d588aacd358dfae5f1cd036e12d224e6fb59', '2c6c991c24a03b2f6b68a98f0669af248808e870fb2aa252df9762226dbdcd94', '4461859b91ab6d916f017291236b1978b625150b8347cf224e1ecc7aea9ed44a', '67c1117208f8396200cf68660694018b3d07f0cb4f6ab55b4e17c7a7694bd018', '0166f75a6dc983618be32ba339be4507328ad1f93ddf32e814acc3ff3b3a1b3a', '0418ae07c0db2d894e70f47c43e52ffe4fb982663e08e6c602c50b6150f7e47e', '51cc5e00d1caa4a83eee077f71d48656315e07f7f2ab60a757dd3570648e94e5', '27de2a189fb811178bff91dd4b7fe6eecf53b201e4b6c99f54c5fc8a5fd5041e', 'f77d940986473183cbc178c0b3605358c9b0e82bbed867e5ea35aa6f9656a8d4', 'e6be60bcb20bcea13caa72d81091817b6c2c4142f5920d0067578ac57a2b2475', '270dbd17f93876d624f9d8da15832912a8e9c365bc4c849e8b8e9c7adb8bc701', '887eeee994983c168d67bdf14e0bbd0aa82aedf8240b53bfe671b77456982b90', '9446c9b63dfcb69fe524ad88355e8985e04022734137805ef14723752cd3ccb4', '103054b5782073083a8d32c9a990a0dba7c9709ab42d7a3010771772d8dfef76', 'ffcf1340780fe485ea32f44dc63d7cb5b51b7fc879b01300472522df28c0bfc6', '737f01923c3072bfe351af0fb62b62e2b7786e3184359a7b36248f7b57048900', 'f77d71fde47970860cddad329162b0b782f4f2020c3d3138cba27c39300af88c', '681ddaa09e210da8bf88ef17e0771df3508060a158998775e78d1332a17f5b43', '9b6121df28311fd476e2967fe7e1903488d69079f1443a4b3ab3cd5816bf0f10', '3f4cb3800f43188e9f3a2a32b5b68a4c1ea223dadf4f5df1e15ff77332e88cf6', 'd8df94d85b56dcb1b1a7d17b6eed7a3dba95befaf2fd3ae4013e1e058280e4b8', 'cbf456a29781967679e32998ac3af6069a8c68f3fc8cec31ab9d811a2fd53f72', '4076669c6db98184bac1032649fee80cd4e592c0c313c63bf72aff550752a68e', '394fe83501b835980823067b1ec6864537c52535dbfa86022d69ee69901ed222']}
        for name, fingerprints in expected.items():
            source = (root / name).read_text(encoding='utf-8')
            tree = ast.parse(source)
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)), name)
            guards = []
            for node in ast.walk(tree):
                if (isinstance(node, ast.If) and isinstance(node.test, ast.UnaryOp)
                        and isinstance(node.test.op, ast.Not) and len(node.body) == 1
                        and isinstance(node.body[0], ast.Raise)):
                    call = node.body[0].exc
                    if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                            and call.func.id == 'AssertionError'):
                        self.assertLessEqual(len(call.args), 1)
                        self.assertEqual(call.keywords, [])
                        message = dump(call.args[0]) if call.args else None
                        value = json.dumps([dump(node.test.operand), message],
                            separators=(',', ':')).encode()
                        guards.append((node.lineno, hashlib.sha256(value).hexdigest()))
            self.assertEqual([value for line, value in sorted(guards)], fingerprints, name)

    def test_optimized_benchmark_refuses_failed_incomplete_or_overcommitted_results(self):
        import json
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[1]
        # Execute the real benchmark entry with a faulty injected transport
        # result. The child performs no SSH and creates only a private temp dir.
        code = r"""
import asyncio,runpy,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'src'))
benchmark=runpy.run_path(str(root/'scripts/benchmark.py'))['benchmark']
mode=sys.argv[2]
class FaultySwarm:
    def __init__(self, options, *, transport):
        if mode=='overcommitted':transport.peak=2
    async def run_to_file(self,*args,**kwargs):
        return SimpleNamespace(ok=mode!='failed',total=3 if mode=='incomplete' else 2,
                               plan=SimpleNamespace(workers=1))
with patch.dict(benchmark.__globals__,Swarm=FaultySwarm):
    try:
        asyncio.run(benchmark(2,1,0))
    except AssertionError:
        print('QUALITY_RESULT_REFUSED')
    else:
        raise SystemExit('invalid benchmark result was accepted under optimization')
"""
        for mode in ('failed', 'incomplete', 'overcommitted'):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-I', '-B', '-O', '-c', code, str(root), mode],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), 'QUALITY_RESULT_REFUSED')


class ProgressPresentationTests(unittest.TestCase):
    def test_tty_width_final_newline_and_plain_stream_preserve_bounded_metadata_only(self):
        metrics={'completed':1,'total':4,'active':1,'skipped':0,'admission_limit':2,
                 'completed_per_second':1.25,'elapsed_seconds':0.8,'circuit_open':False}
        for tty in (False,True):
            for final in (False,True):
                for width in (5,80,1000):
                    output=io.StringIO();output.isatty=lambda:tty
                    with patch.object(progress.sys,'stderr',output),patch('shutil.get_terminal_size',return_value=SimpleNamespace(columns=width)):
                        progress.progress({**metrics,'circuit_open':final},final=final)
                    value=output.getvalue()
                    self.assertEqual(value.endswith('\n'),not tty or final)
                    if tty:self.assertEqual(len(value.removeprefix('\r').removesuffix('\n')),max(20,min(160,width-1)))
                    else:self.assertIn('circuit='+('open' if final else 'closed'),value)
                    self.assertNotIn('Host(',value);self.assertNotIn('password',value)


if __name__=='__main__':unittest.main()
