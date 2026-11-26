"""Repository integration contract for mandatory CI coverage in every matrix cell."""

import itertools
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]


class IsolatedUnitWorkerContracts(unittest.TestCase):
    """A parallel unit result cannot manufacture a pass or remove a case."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import sys
        previous = sys.path[:]
        try:
            sys.path.insert(0, str(ROOT/'scripts'))
            spec = importlib.util.spec_from_file_location('swassh_verify_contract', ROOT/'scripts/verify.py')
            cls.verify = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.verify)
        finally:
            sys.path[:] = previous

    def test_worker_evidence_rejects_forged_counts_sources_skips_and_outcomes(self):
        from copy import deepcopy
        identity = self.verify.worker_identity('a'*32)
        valid = identity | {'tests_run': 1, 'skipped': [], 'failures': [], 'errors': [],
                            'successful': True, 'expected_failures': [], 'unexpected_successes': []}
        self.assertEqual(self.verify.validate_worker_result(deepcopy(valid), identity, 0), valid)
        changes = [('nonce', 'b'*32), ('case', 'different.case'), ('python', []),
                   ('script_sha256', 'b'*64), ('test_sha256', 'b'*64), ('tests_run', True),
                   ('tests_run', 0), ('tests_run', 2), ('skipped', ['unavailable']),
                   ('failures', [1]), ('errors', ['synthetic failure']), ('successful', 1),
                   ('successful', False), ('expected_failures', ['not executed']),
                   ('unexpected_successes', ['unexpected'])]
        for field, value in changes:
            with self.subTest(field=field, value_type=type(value).__name__):
                altered = deepcopy(valid)
                altered[field] = value
                with self.assertRaises(ValueError):
                    self.verify.validate_worker_result(altered, identity, 0)
        for missing in valid:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                self.verify.validate_worker_result({k: v for k, v in valid.items() if k != missing}, identity, 0)
        with self.assertRaises(ValueError):
            self.verify.validate_worker_result(valid | {'extra': 1}, identity, 0)
        for returncode in (False, 1, 124):
            with self.subTest(returncode=returncode), self.assertRaises(ValueError):
                self.verify.validate_worker_result(valid, identity, returncode)
        failed = deepcopy(valid)
        failed.update(successful=False, errors=['synthetic execution failure'])
        self.assertFalse(self.verify.validate_worker_result(failed, identity, 1)['successful'])

    def test_partition_retains_every_case_and_rejects_missing_or_duplicate_worker(self):
        class NamedCase(unittest.TestCase):
            def __init__(self, label):
                super().__init__('runTest')
                self.label = label
            def id(self):
                return self.label
            def runTest(self):
                self.fail('partition must not execute test bodies')

        target = NamedCase(self.verify.ISOLATED_CASE)
        suite = unittest.TestSuite([NamedCase('one'), unittest.TestSuite([target, NamedCase('two')])])
        retained, selected = self.verify.split_isolated_case(suite)
        self.assertEqual(suite.countTestCases(), 3)
        self.assertEqual(retained.countTestCases(), 2)
        self.assertEqual(selected, [target])
        for invalid in (unittest.TestSuite([NamedCase('one')]),
                        unittest.TestSuite([NamedCase(self.verify.ISOLATED_CASE), NamedCase(self.verify.ISOLATED_CASE)])):
            with self.subTest(size=invalid.countTestCases()), self.assertRaisesRegex(ValueError, 'incomplete or ambiguous'):
                self.verify.isolated_run(invalid)


class WindowsTemporaryStorageContracts(unittest.TestCase):
    """Exercise actual CI placement, retaining workload and failure boundaries."""

    def _windows_temp_step(self):
        """Read the actual CI body, rather than duplicating its PowerShell logic."""
        lines = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8').splitlines()
        start = lines.index('  quality:') + 1
        end = next((i for i in range(start, len(lines))
                    if re.fullmatch(r'  [A-Za-z_][A-Za-z_0-9-]*:', lines[i])), len(lines))
        quality = lines[start:end]
        marker = '      - name: Use allocated ephemeral storage for Windows QA'
        self.assertEqual(quality.count(marker), 1)
        first = quality.index(marker)
        finish = next((i for i in range(first + 1, len(quality))
                       if quality[i].startswith('      - ')), len(quality))
        step = quality[first:finish]
        body = step.index('        run: |') + 1
        return quality, first, step, '\n'.join(line[10:] for line in step[body:]) + '\n'

    def test_windows_temp_placement_precedes_every_quality_command_with_same_budget(self):
        quality, position, step, body = self._windows_temp_step()
        self.assertIn('    timeout-minutes: 30', quality)
        self.assertIn("        if: runner.os == 'Windows'", step)
        self.assertIn('        shell: pwsh', step)
        self.assertNotIn('continue-on-error:', '\n'.join(step))
        for command in ('python scripts/verify.py', 'python scripts/coverage.py',
                        'python benchmarks/core.py', 'python scripts/build.py',
                        'python scripts/validate_installation.py', 'python scripts/package.py'):
            self.assertLess(position, next(i for i, line in enumerate(quality) if command in line))
        self.assertIn("@('TMPDIR', 'TEMP', 'TMP')", body)

    def _exercise_temp_step(self, directory, runner_temp):
        """Execute the extracted CI step through the real strict Windows shell."""
        _, _, _, body = self._windows_temp_step()
        script = directory / 'temp-step.ps1'
        script.write_text(body, encoding='utf-8')
        exports = directory / 'github-env'
        exports.write_text('OPERATOR_SENTINEL=retained\n', encoding='utf-8')
        shell = runpy.run_path(str(ROOT / 'scripts/ci_shell.py'))['ShellRunner']()
        with patch.dict(os.environ, RUNNER_TEMP=str(runner_temp), GITHUB_ENV=str(exports)):
            code = shell.run(script)
        return code, exports.read_text(encoding='utf-8')

    @unittest.skipUnless(os.name == 'nt', 'Windows CI environment contract')
    def test_windows_temp_step_exports_only_three_locations_and_preserves_prior_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allocated = root / 'allocated space'
            allocated.mkdir()
            previous = {name: os.environ.get(name) for name in ('TMPDIR', 'TEMP', 'TMP')}
            code, exported = self._exercise_temp_step(root, allocated)
            self.assertEqual(code, 0)
            self.assertEqual(exported.splitlines(), ['OPERATOR_SENTINEL=retained',
                'TMPDIR=' + str(allocated), 'TEMP=' + str(allocated), 'TMP=' + str(allocated)])
            self.assertEqual({name: os.environ.get(name) for name in previous}, previous)

    @unittest.skipUnless(os.name == 'nt', 'Windows CI environment contract')
    def test_windows_temp_step_refuses_invalid_location_before_writing_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, junction = root / 'junction target', root / 'junction'
            target.mkdir()
            create = root / 'create-junction.ps1'
            create.write_text('New-Item -ItemType Junction -Path $env:SWASSH_QA_LINK '
                              '-Target $env:SWASSH_QA_TARGET -ErrorAction Stop | Out-Null\n', encoding='utf-8')
            shell = runpy.run_path(str(ROOT / 'scripts/ci_shell.py'))['ShellRunner']()
            with patch.dict(os.environ, SWASSH_QA_LINK=str(junction), SWASSH_QA_TARGET=str(target)):
                self.assertEqual(shell.run(create), 0)
            self.assertTrue(junction.is_dir())
            for location in (root / 'missing', 'relative-location', '', str(root) + '\n', junction):
                with self.subTest(location=repr(location)):
                    code, exported = self._exercise_temp_step(root, location)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(exported, 'OPERATOR_SENTINEL=retained\n')


class CoverageWorkflowContracts(unittest.TestCase):
    """Keep runtime-specific coverage regressions from bypassing release validation."""

    def test_all_supported_quality_matrix_cells_require_the_coverage_gate(self):
        lines = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines.count('  quality:'), 1)
        first = lines.index('  quality:') + 1
        end = next((index for index in range(first, len(lines))
                    if re.fullmatch(r'  [A-Za-z_][A-Za-z_0-9-]*:', lines[index])), len(lines))
        quality = lines[first:end]
        self.assertIn('    steps:', quality)
        header = quality[:quality.index('    steps:')]
        axes = {}
        for line in header:
            match = re.fullmatch(r"        (os|python): \[(.+)\]", line)
            if match:
                self.assertNotIn(match[1], axes)
                axes[match[1]] = tuple(value.strip().strip("'\"") for value in match[2].split(','))
        self.assertEqual(set(axes), {'os', 'python'})
        self.assertEqual(set(axes['os']), {'ubuntu-24.04', 'windows-latest', 'macos-latest'})
        self.assertEqual(set(axes['python']), {'3.11', '3.12', '3.13', '3.14'})
        cells = set(itertools.product(axes['os'], axes['python']))
        self.assertEqual(len(cells), 12)
        # The checked-in workflow deliberately uses explicit, finite axes.
        # Filters or ignored errors would silently remove required evidence.
        self.assertFalse(any(line.strip().startswith(('if:', 'continue-on-error:', 'exclude:', 'include:'))
                             for line in header), 'quality job or matrix must not bypass required cells')
        self.assertFalse(any(line.strip().startswith('continue-on-error:') for line in quality),
                         'required quality failures must remain blocking')
        command = '      - run: python scripts/coverage.py'
        self.assertEqual(quality.count(command), 1, 'one exact, blocking five-metric gate is required')
        start = quality.index(command)
        finish = next((index for index in range(start + 1, len(quality))
                       if quality[index].startswith('      - ')), len(quality))
        step = quality[start:finish]
        self.assertFalse(any(line.strip().startswith(('if:', 'continue-on-error:')) for line in step),
                         'five-metric coverage is required in all 12 matrix cells')


class ReleaseArtifactWorkflowContracts(unittest.TestCase):
    """Bind published bytes to the artifact produced after the quality gates.

    These checks cover the repository's explicit workflow layout, rather than
    providing a general YAML interpreter. Runtime checksum behavior is also
    exercised independently with GNU coreutils and real qualified artifacts.
    """

    def _job(self, lines, name):
        marker = '  ' + name + ':'
        self.assertEqual(lines.count(marker), 1)
        start = lines.index(marker) + 1
        finish = next((index for index in range(start, len(lines))
                       if re.fullmatch(r'  [A-Za-z_][A-Za-z_0-9-]*:', lines[index])), len(lines))
        return lines[start:finish]

    def _step(self, steps, marker):
        selected = [(index, step) for index, step in enumerate(steps) if any(marker in line for line in step)]
        self.assertEqual(len(selected), 1, marker)
        return selected[0]

    def test_release_promotes_only_the_current_run_quality_artifact(self):
        lines = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8').splitlines()
        validate = self._job(lines, 'validate')
        build = self._job(lines, 'build')
        github = self._job(lines, 'github')
        pypi = self._job(lines, 'pypi')
        self.assertIn('    uses: ./.github/workflows/ci.yml', validate)
        self.assertIn('    needs: validate', build)
        self.assertIn('    needs: build', github)
        self.assertIn('    needs: [build, github]', pypi)
        for body in (validate, build, github, pypi):
            self.assertFalse(any(line.strip().startswith(('if:', 'continue-on-error:')) for line in body),
                             'required release gates must not be skipped or ignored')
        self.assertFalse(any('scripts/build.py' in line or 'scripts/package.py' in line for line in build),
                         'release must promote qualified bytes instead of rebuilding after validation')
        starts = [index for index, line in enumerate(build) if line.startswith('      - ')]
        steps = [build[start:finish] for start, finish in zip(starts, starts[1:] + [len(build)])]
        prepare_index, prepare = self._step(steps, 'run: test ! -e qualified-dist && test ! -L qualified-dist')
        download_index, download = self._step(steps,
            'uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333')
        checksum_index, checksum = self._step(steps, 'run: sha256sum --strict --check SHA256SUMS')
        upload_index, upload = self._step(steps,
            'uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9')
        self.assertLess(prepare_index, download_index)
        self.assertLess(download_index, checksum_index)
        self.assertLess(checksum_index, upload_index)
        self.assertIn('        shell: bash', prepare)
        self.assertIn('        run: test ! -e qualified-dist && test ! -L qualified-dist', prepare)
        self.assertIn('          name: distributions', download)
        self.assertIn('          path: qualified-dist', download)
        self.assertFalse(any(line.strip().startswith(('github-token:', 'repository:', 'run-id:',
            'artifact-ids:', 'pattern:', 'merge-multiple:')) for line in download),
            'qualified artifact must come from the current repository and run')
        self.assertIn('        shell: bash', checksum)
        self.assertIn('        run: sha256sum --strict --check SHA256SUMS', checksum)
        self.assertIn('        working-directory: qualified-dist', checksum)
        self.assertIn('          name: release', upload)
        self.assertIn('          path: qualified-dist/', upload)
        self.assertNotIn('          overwrite: true', upload)
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        order = [ci.index(value) for value in ('python scripts/verify.py', 'python scripts/coverage.py',
            'python scripts/build.py', 'python scripts/validate_installation.py',
            'python scripts/validate_deployment.py', 'python scripts/package.py', 'name: distributions')]
        self.assertEqual(order, sorted(order), 'quality artifact must be produced after the existing gates')


class QualityCommandIOContracts(unittest.TestCase):
    """Exercise the output and import boundaries used by the Linux quality job."""

    def test_benchmark_creates_missing_output_parent(self):
        with patch.object(sys, 'path', sys.path[:]):
            operator = runpy.run_path(str(ROOT / 'benchmarks/core.py'))
        # Keep this regression about report I/O. The workflow also runs the
        # original workload with its full set of assertions.
        measured = [{'fixture': 'benchmark output'}]
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(operator['CoreBenchmarks'], 'run', new=AsyncMock(return_value=measured)) as run:
            output = Path(temporary) / 'validation' / 'core-benchmarks.json'
            self.assertFalse(output.parent.exists())
            operator['main'](['--operations', '1', '--workers', '1', '--output', str(output)])
            result = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual((result['operations'], result['workers']), (1, 1))
            self.assertEqual(result['results'], measured)
            run.assert_awaited_once()

    @unittest.skipUnless(os.name == 'posix', 'schedule quality command requires POSIX')
    def test_schedule_registers_from_private_cwd_using_checkout_sources(self):
        operator = runpy.run_path(str(ROOT / 'scripts/qualify_schedule.py'))

        class FirstSubmissionObserved(Exception):
            """Stop before the real campaign's wait for its UTC deadline."""

        def observe(command, *, cwd, env, **kwargs):
            self.assertEqual(command[:4], [sys.executable, '-m', 'swassh', 'schedule'])
            self.assertNotEqual(cwd.resolve(), ROOT)
            self.assertEqual(Path(env['PYTHONPATH']), ROOT / 'src')
            self.assertEqual(kwargs['timeout'], 45)
            raise FirstSubmissionObserved

        workspace = operator['ProbeWorkspace']
        with patch.dict(os.environ, {'PYTHONPATH': 'src'}), tempfile.TemporaryDirectory() as temporary, \
                patch.object(workspace, '__init__', lambda obj: obj.__dict__.update(path=Path(temporary), checks=[])), \
                patch.object(workspace, '__exit__', return_value=False), \
                patch.object(operator['subprocess'], 'run', side_effect=observe):
            with self.assertRaises(FirstSubmissionObserved):
                operator['ScheduleCampaign'](1).run()


class DeploymentAliasIntegrationTests(unittest.TestCase):
    """Keep the real installed-shell and unchanged-profile checks through an alias."""

    probe_script = ROOT / 'scripts/validate_deployment.py'

    @unittest.skipUnless(os.name == 'posix', 'POSIX shell and owned symbolic-link contract')
    def test_posix_temporary_alias_retains_exact_installed_shell_and_profile_contracts(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from swassh import __version__
        with tempfile.TemporaryDirectory(prefix='swassh-deployment-alias-') as fixture:
            owner = Path(fixture).resolve(strict=True)
            actual = owner / 'actual'
            actual.mkdir(mode=0o700)
            alias = owner / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            operator = runpy.run_path(str(self.probe_script))
            # Only the probe's temporary-directory factory is replaced. Its
            # installer, wheel, venv, HTTP index, shell and assertions are real.
            # ROOT also makes a preserved predecessor executable in this case.
            port = SimpleNamespace(TemporaryDirectory=lambda **kwargs: nullcontext(str(alias)))
            with patch.dict(operator['DeploymentProbe'].run.__globals__, {'ROOT': ROOT, 'tempfile': port}):
                result = operator['DeploymentProbe']().run()
            self.assertEqual(result['version'], __version__)
            self.assertEqual(result['status'], 'EXÉCUTÉ')
            self.assertEqual(result['pip_index'], 'isolated loopback')
            for field in ('fresh_app_venv', 'installed_entrypoint', 'repeat_deployment_idempotent',
                          'pip_failure_propagated', 'posix_path_in_real_shell'):
                self.assertIs(result[field], True, field)


if __name__ == '__main__':
    unittest.main()
