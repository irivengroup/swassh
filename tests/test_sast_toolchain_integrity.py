"""Integration regressions for scanner import hooks and unverified bytecode."""

import os
import hashlib
import json
from pathlib import Path
import runpy
import stat
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

API = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/sast_gate.py'))


class SastToolchainIntegrityTests(unittest.TestCase):
    """Reject unsafe private scanner state before starting its interpreter."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='swassh-sast-import-test-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        # A valid lock keeps a missed prelaunch refusal observable as an
        # attempted interpreter start, rather than a missing-fixture error.
        (self.root/'.github').mkdir()
        (self.root/'.github/bandit-requirements.txt').write_bytes(
            (Path(__file__).resolve().parents[1]/'.github/bandit-requirements.txt').read_bytes())
        self.prefix = self.root/'scanner'
        self.site = self.prefix/('Lib/site-packages' if os.name == 'nt' else 'lib/python3.12/site-packages')
        self.site.mkdir(parents=True)
        (self.prefix/'pyvenv.cfg').write_text('test fixture; never execute\n', encoding='utf-8')
        python = self.prefix/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        self.scanner = API['Scanner'](self.root, python, self.root/'wheels', self.root/'output')

    def assert_prelaunch_refusal(self, relative, expected):
        path = self.site/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'non-executable sentinel; never import\n')
        with patch.object(API['subprocess'], 'run', side_effect=AssertionError('interpreter must not start')) as native:
            with self.assertRaisesRegex(API['Refusal'], expected):
                self.scanner.attest_toolchain()
            native.assert_not_called()

    def test_pth_hook_is_refused_before_python_can_execute_it(self):
        self.assert_prelaunch_refusal('candidate.pth', 'uncontrolled site import hook')

    def test_sitecustomize_is_refused_before_interpreter_start(self):
        self.assert_prelaunch_refusal('sitecustomize.py', 'uncontrolled site import hook')

    def test_sourceless_bytecode_cannot_bypass_the_source_wheel_comparison(self):
        self.assert_prelaunch_refusal('hidden.pyc', 'bytecode is not an original locked wheel member')

    def test_timestamp_valid_bytecode_is_not_trusted_just_because_source_matches(self):
        self.assert_prelaunch_refusal('bandit/__pycache__/__init__.cpython-312.pyc', 'bytecode is not an original locked wheel member')

    def test_case_variant_bytecode_is_refused_before_interpreter_start(self):
        # Windows can open the canonical lowercase cache name through these
        # filesystem aliases; -B does not prevent loading existing bytecode.
        for name in ('bandit/__PYCACHE__/__init__.cpython-312.PYC', 'hidden.PyC'):
            with self.subTest(name=name):
                try:
                    self.assert_prelaunch_refusal(name, 'bytecode is not an original locked wheel member')
                finally:
                    (self.site/name).unlink()

    def test_case_variant_import_hooks_are_refused_before_interpreter_start(self):
        for name in ('candidate.PTH', 'SiteCustomize.PY', 'UserCustomize.Py'):
            with self.subTest(name=name):
                try:
                    self.assert_prelaunch_refusal(name, 'uncontrolled site import hook')
                finally:
                    (self.site/name).unlink()

    def test_non_regular_scanner_entry_is_refused_before_interpreter_start(self):
        path = self.site/'unreviewed-special-entry'
        path.write_bytes(b'owned metadata-only fixture')
        is_file, is_dir = Path.is_file, Path.is_dir
        get_stat, get_lstat = Path.stat, Path.lstat
        special = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_file_attributes=0)
        with patch.object(Path, 'is_file', autospec=True, side_effect=lambda p, *a, **k: False if p == path else is_file(p, *a, **k)), \
                patch.object(Path, 'is_dir', autospec=True, side_effect=lambda p, *a, **k: False if p == path else is_dir(p, *a, **k)), \
                patch.object(Path, 'stat', autospec=True, side_effect=lambda p, *a, **k: special if p == path else get_stat(p, *a, **k)), \
                patch.object(Path, 'lstat', autospec=True, side_effect=lambda p, *a, **k: special if p == path else get_lstat(p, *a, **k)), \
                patch.object(API['subprocess'], 'run', side_effect=AssertionError('interpreter must not start')) as native:
            with self.assertRaisesRegex(API['Refusal'], 'non-regular scanner entry'):
                self.scanner.attest_toolchain()
            native.assert_not_called()

    def test_added_plugin_metadata_cannot_inherit_an_unchanged_toolchain(self):
        # Small owned wheel/installation fixtures exercise the real attestation
        # logic. Only its native metadata query is replaced; no fixture runs.
        versions = {'bandit': '1.9.4', 'colorama': '0.4.6', 'markdown-it-py': '4.2.0',
                    'mdurl': '0.1.2', 'pygments': '2.21.0', 'pyyaml': '6.0.3',
                    'rich': '15.0.0', 'stevedore': '5.9.1'}
        wheels = self.root/'wheels'
        wheels.mkdir()
        lock = []
        for name, version in versions.items():
            distribution = name.replace('-', '_')+'-'+version+'.dist-info'
            members = {name.replace('-', '_')+'/__init__.py': b'fixture_value = 7\n',
                       distribution+'/METADATA': ('Name: '+name+'\nVersion: '+version+'\n').encode(),
                       distribution+'/RECORD': b''}
            wheel = wheels/(name.replace('-', '_')+'-'+version+'-py3-none-any.whl')
            with zipfile.ZipFile(wheel, 'w') as archive:
                for member, raw in members.items():
                    archive.writestr(member, raw)
                    target = self.site/member
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
            lock.append(name+'=='+version+' --hash=sha256:'+hashlib.sha256(wheel.read_bytes()).hexdigest())
        (self.root/'.github/bandit-requirements.txt').write_text('\n'.join(lock)+'\n', encoding='utf-8')
        output = self.root/'output'
        output.mkdir()
        runtime = self.prefix/'controlled-runtime'
        runtime.write_bytes(b'not an executable; metadata query is mocked')
        metadata = {'python': [3, 12, 0], 'site': str(self.site), 'runtime': str(runtime),
                    'platform': 'win32' if os.name == 'nt' else 'linux', 'versions': versions}
        completed = SimpleNamespace(stdout=json.dumps(metadata).encode(), returncode=0)
        with patch.object(API['subprocess'], 'run', return_value=completed) as native:
            before = self.scanner.attest_toolchain()
            self.assertEqual(set(before['wheels']), set(versions))
            added = self.site/'colorama-0.4.6.dist-info/entry_points.txt'
            added.write_bytes(b'[bandit.plugins]\nfixture = builtins:len\n')
            with self.assertRaisesRegex(API['Refusal'], 'unreviewed installed file'):
                self.scanner.attest_toolchain()
            self.assertEqual(native.call_count, 2, 'only the fixed metadata query may run')

    def test_missing_venv_is_refused_without_launch(self):
        (self.prefix/'pyvenv.cfg').unlink()
        with patch.object(API['subprocess'], 'run') as native:
            with self.assertRaisesRegex(API['Refusal'], 'private Python 3.12 virtual environment'):
                self.scanner.attest_toolchain()
            native.assert_not_called()

    def test_missing_report_keeps_the_real_exit_and_cannot_qualify_security(self):
        output = self.root/'output'
        output.mkdir()
        completed = type('Completed', (), {'returncode': 1})()
        with patch.object(API['subprocess'], 'run', return_value=completed):
            with self.assertRaises(FileNotFoundError):
                self.scanner.run()
        receipt = API['load_json']((output/'raw-exit.json').read_bytes())
        self.assertEqual(receipt['raw_exit'], 1)
        self.assertFalse((output/'security.json').exists())

    def test_timeout_is_not_fabricated_as_a_successful_exit(self):
        output = self.root/'output'
        output.mkdir()
        error = API['subprocess'].TimeoutExpired(['scanner'], 300)
        with patch.object(API['subprocess'], 'run', side_effect=error):
            with self.assertRaises(API['subprocess'].TimeoutExpired):
                self.scanner.run()
        receipt = API['load_json']((output/'raw-exit.json').read_bytes())
        self.assertIsNone(receipt['raw_exit'])
        self.assertIs(receipt['timed_out'], True)
        self.assertFalse((output/'security.json').exists())

    def test_report_digest_identifies_the_bytes_that_were_actually_parsed(self):
        output = self.root/'output'
        output.mkdir()
        original = b'{"errors":[],"generated_at":"before","metrics":{"_totals":{}},"results":[]}'
        replacement = original.replace(b'before', b'after')
        raw_path = output/'bandit-full.json'
        read_bytes = Path.read_bytes
        reads = []
        def changed_read(path):
            if path == raw_path:
                reads.append(path)
                return original if len(reads) == 1 else replacement
            return read_bytes(path)
        completed = type('Completed', (), {'returncode': 0})()
        def produce_report(*args, **kwargs):
            raw_path.write_bytes(original)
            return completed
        with patch.object(API['subprocess'], 'run', side_effect=produce_report), patch.object(Path, 'read_bytes', changed_read):
            parsed, code, digest = self.scanner.run()
        self.assertEqual(parsed['generated_at'], 'before')
        self.assertEqual(code, 0)
        self.assertEqual(digest, API['sha'](original), 'digest must not describe replacement bytes read after parsing')


class PathIdentityTests(unittest.TestCase):
    """Lexical aliases stay usable; real reparse and symlink components do not."""

    def test_real_reparse_attributes_and_symbolic_links_are_refused(self):
        boundary = Path('owned-input')
        for mode, attributes in ((stat.S_IFDIR, 0x400), (stat.S_IFLNK, 0)):
            with self.subTest(mode=mode, attributes=attributes), patch.object(Path, 'lstat', return_value=SimpleNamespace(
                    st_mode=mode, st_file_attributes=attributes)):
                self.assertTrue(API['linked_within'](boundary/'member', boundary))

    def test_normalized_spelling_is_not_a_link_detector(self):
        boundary = Path('owned-input')
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0)), \
                patch.object(Path, 'resolve', side_effect=AssertionError('spelling is not a link attribute')):
            self.assertFalse(API['linked_within'](boundary/'ordinary member', boundary))

    def test_reparse_ancestor_is_refused_before_descendant_metadata_is_touched(self):
        boundary = Path('owned-input')
        junction = boundary/'junction'
        def metadata(path):
            if path == boundary:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0)
            if path == junction:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            raise AssertionError('untrusted descendant metadata was touched')
        with patch.object(Path, 'lstat', metadata):
            self.assertTrue(API['linked_within'](junction/'outside.py', boundary))

    @unittest.skipUnless(os.name == 'nt', 'Windows short-name filesystem contract')
    def test_windows_short_alias_keeps_the_actual_prelaunch_refusal(self):
        import ctypes
        from ctypes import wintypes
        with tempfile.TemporaryDirectory(prefix='swassh-sast-alias-') as directory:
            prefix = Path(directory)/'ordinary scanner environment'
            site = prefix/'Lib/site-packages'
            site.mkdir(parents=True)
            (prefix/'pyvenv.cfg').write_bytes(b'synthetic prelaunch fixture\n')
            (site/'candidate.pth').write_bytes(b'# never execute this fixture\n')
            query = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
            query.argtypes, query.restype = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD], wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            count = query(str(prefix), buffer, len(buffer))
            self.assertTrue(0 < count < len(buffer))
            alias = Path(buffer.value)
            if alias.resolve() == alias.absolute():
                self.skipTest('filesystem does not provide a distinct short-name alias')
            scanner = API['Scanner'](alias, alias/'Scripts/python.exe', alias/'wheels', alias/'output')
            with patch.object(API['subprocess'], 'run', side_effect=AssertionError('must not launch')) as child:
                with self.assertRaisesRegex(API['Refusal'], 'uncontrolled site import hook'):
                    scanner.attest_toolchain()
                child.assert_not_called()


class CleanSourceInputTests(unittest.TestCase):
    """Unscanned root sources and prebuilt outputs cannot reuse an old review."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='swassh-sast-source-input-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for folder in ('src', 'tests', 'scripts', 'build_support', 'benchmarks', '.github', 'docs', 'examples'):
            (self.root/folder).mkdir()
        for name in ('.gitignore', 'pyproject.toml', 'README.md', 'LICENSE', 'VALIDATION.md', 'SECURITY.md'):
            (self.root/name).write_bytes(b'controlled source-input fixture\n')
        (self.root/'src/witness.py').write_bytes(b'def sample():\n    return 7\n')

    def test_complete_clean_input_hashes_all_maintained_files(self):
        snapshot = API['SourceSnapshot'].capture(self.root)
        self.assertEqual(set(snapshot), {'.gitignore', 'pyproject.toml', 'README.md', 'LICENSE',
                                        'VALIDATION.md', 'SECURITY.md', 'src/witness.py'})
        self.assertEqual(snapshot['src/witness.py'], API['sha']((self.root/'src/witness.py').read_bytes()))

    def test_added_python_root_source_is_refused_instead_of_silently_omitted(self):
        (self.root/'sitecustomize.py').write_bytes(b'print("unreviewed source fixture")\n')
        with self.assertRaisesRegex(API['Refusal'], 'unreviewed source root member: sitecustomize.py'):
            API['SourceSnapshot'].capture(self.root)

    def test_application_bytecode_cache_cannot_hide_behind_identical_source_bytes(self):
        cache = self.root/'src/__pycache__'
        cache.mkdir()
        (cache/'witness.cpython-312.pyc').write_bytes(b'unreviewed binary fixture')
        with self.assertRaisesRegex(API['Refusal'], 'compiled source cache'):
            API['SourceSnapshot'].capture(self.root)

    def test_sourceless_application_bytecode_is_refused(self):
        (self.root/'src/unreviewed.pyc').write_bytes(b'unreviewed sourceless fixture')
        with self.assertRaisesRegex(API['Refusal'], 'compiled source cache'):
            API['SourceSnapshot'].capture(self.root)

    def test_case_variant_application_caches_are_refused(self):
        for name in ('src/__PYCACHE__/witness.cpython-312.PYC', 'src/hidden.PyC'):
            with self.subTest(name=name):
                path = self.root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'unreviewed binary fixture; never execute')
                try:
                    with self.assertRaisesRegex(API['Refusal'], 'compiled source cache'):
                        API['SourceSnapshot'].capture(self.root)
                finally:
                    path.unlink()
                    if path.parent.name.casefold() == '__pycache__':
                        path.parent.rmdir()

    def test_non_regular_source_member_cannot_be_silently_omitted(self):
        path = self.root/'src/unreviewed-special-entry'
        path.write_bytes(b'owned metadata-only fixture')
        is_file, is_dir = Path.is_file, Path.is_dir
        get_stat, get_lstat = Path.stat, Path.lstat
        special = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_file_attributes=0)
        with patch.object(Path, 'is_file', autospec=True, side_effect=lambda p, *a, **k: False if p == path else is_file(p, *a, **k)), \
                patch.object(Path, 'is_dir', autospec=True, side_effect=lambda p, *a, **k: False if p == path else is_dir(p, *a, **k)), \
                patch.object(Path, 'stat', autospec=True, side_effect=lambda p, *a, **k: special if p == path else get_stat(p, *a, **k)), \
                patch.object(Path, 'lstat', autospec=True, side_effect=lambda p, *a, **k: special if p == path else get_lstat(p, *a, **k)):
            with self.assertRaisesRegex(API['Refusal'], 'non-regular source entry'):
                API['SourceSnapshot'].capture(self.root)

    def test_prebuilt_distribution_cannot_be_ignored_before_quality_builds(self):
        directory = self.root/'dist'
        directory.mkdir()
        (directory/'unreviewed.whl').write_bytes(b'synthetic prebuilt artifact; never install')
        with self.assertRaisesRegex(API['Refusal'], 'unreviewed source root member: dist'):
            API['SourceSnapshot'].capture(self.root)

    def test_generated_manifest_is_not_an_input_authority(self):
        (self.root/'MANIFEST.json').write_bytes(b'{"production_ready":true}\n')
        with self.assertRaisesRegex(API['Refusal'], 'unreviewed source root member: MANIFEST.json'):
            API['SourceSnapshot'].capture(self.root)

    def test_additional_root_configuration_cannot_change_without_review(self):
        (self.root/'setup.cfg').write_bytes(b'[synthetic fixture]\n')
        with self.assertRaisesRegex(API['Refusal'], 'unreviewed source root member: setup.cfg'):
            API['SourceSnapshot'].capture(self.root)

    def test_operator_private_directories_are_outside_the_maintained_source_set(self):
        before = API['SourceSnapshot'].capture(self.root)
        for name in ('.git', '.qa-bandit', '.qa-approved-review'):
            directory = self.root/name
            directory.mkdir()
            (directory/'metadata').write_bytes(b'operator-owned fixture metadata\n')
        self.assertEqual(API['SourceSnapshot'].capture(self.root), before)


if __name__ == '__main__':
    unittest.main()
