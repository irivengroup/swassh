"""Integration contracts for the explicitly authorized SAST-v2 transition.

The repository uses explicit workflow jobs and steps. These tests deliberately
check that finite layout; they do not implement a general YAML interpreter.
"""

from pathlib import Path
import hashlib
import re
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MandatorySastWorkflowContracts(unittest.TestCase):
    """Security requires the full scan and an externally anchored exact review."""

    def setUp(self):
        self.lines = (ROOT/'.github/workflows/ci.yml').read_text(encoding='utf-8').splitlines()

    def _job(self, name):
        marker = '  '+name+':'
        self.assertEqual(self.lines.count(marker), 1, 'one mandatory '+name+' job is required')
        start = self.lines.index(marker)+1
        finish = next((i for i in range(start, len(self.lines))
                       if re.fullmatch(r'  [A-Za-z_][A-Za-z_0-9-]*:', self.lines[i])), len(self.lines))
        return self.lines[start:finish]

    def _step(self, job, name):
        marker = '      - name: '+name
        self.assertEqual(job.count(marker), 1, 'one exact '+name+' step is required')
        start = job.index(marker)
        finish = next((i for i in range(start+1, len(job)) if job[i].startswith('      - ')), len(job))
        return job[start:finish]

    def test_sast_is_required_before_quality_can_produce_a_release_artifact(self):
        security = self._job('security')
        quality = self._job('quality')
        self.assertIn('    needs: security', quality)
        for job in (security, quality):
            header = job[:job.index('    steps:')]
            self.assertFalse(any(line.strip().startswith(('if:', 'continue-on-error:', 'needs:'))
                                 for line in header if line != '    needs: security'))
            self.assertFalse(any(line.strip().startswith('continue-on-error:') for line in job))
        self.assertIn('    runs-on: ubuntu-24.04', security)
        self.assertIn('    timeout-minutes: 10', security)
        release = (ROOT/'.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertIn('    uses: ./.github/workflows/ci.yml', release)
        self.assertIn('    needs: validate', release)

    def test_v2_requires_external_review_and_verifier_pins_before_candidate_execution(self):
        security = self._job('security')
        step = self._step(security, 'Verified SAST v2 scan and individual qualification')
        self.assertEqual(step[:8], [
            '      - name: Verified SAST v2 scan and individual qualification',
            '        id: sast_scan', '        shell: bash',
            '        env:', '          SWASSH_SAST_REVIEW_SHA256: ${{ vars.SWASSH_SAST_REVIEW_SHA256 }}',
            '          SWASSH_SAST_GATE_SHA256: ${{ vars.SWASSH_SAST_GATE_SHA256 }}',
            "          PYTHONDONTWRITEBYTECODE: '1'", '        run: |'])
        self.assertEqual(len(step), 9)
        command = step[8]
        self.assertIn('actual=hashlib.sha256(p.read_bytes()).hexdigest();sys.exit("untrusted gate bytes") if actual!=expected else None;', command)
        self.assertIn('sys.argv=sys.argv[1:];runpy.run_path(str(p),run_name="__main__")', command)
        self.assertLess(command.index('actual!=expected'), command.index('runpy.run_path'))
        self.assertTrue(command.endswith('--output "$RUNNER_TEMP/swassh-sast-output"'))
        self.assertNotIn('||', command)
        self.assertNotIn('continue-on-error', command)
        authority = self._step(security, 'Require detached operator authority')
        self.assertIn('          REVIEW_REF: ${{ vars.SWASSH_SAST_REVIEW_REF }}', authority)
        self.assertIn("[('REVIEW_REF','[0-9a-f]{40}','SWASSH_SAST_REVIEW_REF'),('REVIEW_SHA','[0-9a-f]{64}','SWASSH_SAST_REVIEW_SHA256'),('GATE_SHA','[0-9a-f]{64}','SWASSH_SAST_GATE_SHA256')]", '\n'.join(authority))
        checkout = self._step(security, 'Read the immutable approved review revision')
        self.assertIn('          ref: ${{ vars.SWASSH_SAST_REVIEW_REF }}', checkout)
        self.assertIn('          persist-credentials: false', checkout)
        source = (ROOT/'scripts/sast_gate.py').read_text(encoding='utf-8')
        self.assertIn("SCOPE = ('src', 'tests', 'scripts', 'build_support', 'benchmarks')", source)
        self.assertIn("'--ignore-nosec', '--format', 'json', '--output', str(raw)]", source)
        for forbidden in ('--skip', '--baseline', '--severity-level', '--confidence-level', '--exclude'):
            self.assertNotIn(forbidden, source)
        self.assertIn('result.update(policy.evaluate(sources, report, raw_exit, tools))', source)

    def test_only_the_locked_qa_toolchain_is_installed_in_a_private_environment(self):
        security = self._job('security')
        install = self._step(security, 'Install hash-locked QA scanner')
        self.assertEqual(install, [
            '      - name: Install hash-locked QA scanner', '        shell: bash', '        run: |',
            '          python -I -B -m venv .qa-bandit',
            '          python -I -m pip --isolated download --require-hashes --only-binary=:all: --no-deps --requirement .github/bandit-requirements.txt --dest "$RUNNER_TEMP/swassh-qa-wheels"',
            '          .qa-bandit/bin/python -I -m pip --isolated install --require-hashes --only-binary=:all: --no-deps --no-compile --no-index --find-links "$RUNNER_TEMP/swassh-qa-wheels" --requirement .github/bandit-requirements.txt',
            '          .qa-bandit/bin/python -I -m pip check'])
        self.assertIn("          python-version: '3.12'", security)
        rows = [line for line in (ROOT/'.github/bandit-requirements.txt').read_text(encoding='utf-8').splitlines()
                if line and not line.startswith('#')]
        packages = {}
        for row in rows:
            match = re.fullmatch(r'([a-z-]+)==([0-9.]+)((?: --hash=sha256:[0-9a-f]{64})+)', row)
            self.assertIsNotNone(match, 'every dependency must be version and hash locked')
            self.assertNotIn(match[1], packages)
            packages[match[1]] = match[2]
        self.assertEqual(packages, {'bandit': '1.9.4', 'colorama': '0.4.6', 'markdown-it-py': '4.2.0',
                                   'mdurl': '0.1.2', 'pygments': '2.21.0', 'pyyaml': '6.0.3',
                                   'rich': '15.0.0', 'stevedore': '5.9.1'})
        self.assertIn('dependencies = []', (ROOT/'pyproject.toml').read_text(encoding='utf-8'))

    def test_candidate_dependencies_cannot_run_before_detached_source_authority(self):
        security = self._job('security')
        fresh = self._step(security, 'Require fresh operator-owned QA directories')
        self.assertEqual(fresh, [
            '      - name: Require fresh operator-owned QA directories', '        shell: bash', '        run: |',
            '          test ! -e .qa-bandit', '          test ! -L .qa-bandit',
            '          test ! -e .qa-approved-review', '          test ! -L .qa-approved-review'])
        preflight = self._step(security, 'Verify source and QA lock authority before installation')
        self.assertIn('          SWASSH_SAST_REVIEW_SHA256: ${{ vars.SWASSH_SAST_REVIEW_SHA256 }}', preflight)
        self.assertIn('          SWASSH_SAST_GATE_SHA256: ${{ vars.SWASSH_SAST_GATE_SHA256 }}', preflight)
        commands = [line for line in preflight if line.startswith('          python -I -B -c ')]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertLess(command.index('actual!=expected'), command.index('runpy.run_path'))
        self.assertIn('policy.verify_sources(api["SourceSnapshot"].capture(Path(os.environ["GITHUB_WORKSPACE"])))', command)
        names = ['Require fresh operator-owned QA directories', 'Require detached operator authority',
                 'Read the immutable approved review revision', 'Materialize the detached review outside candidate sources',
                 'Verify source and QA lock authority before installation', 'Install hash-locked QA scanner',
                 'Verified SAST v2 scan and individual qualification']
        order = [security.index('      - name: '+name) for name in names]
        self.assertEqual(order, sorted(order))

    def test_failure_report_is_retained_without_turning_failure_into_success(self):
        security = self._job('security')
        step = self._step(security, 'Preserve the unfiltered scan report')
        self.assertEqual(step, [
            '      - name: Preserve the unfiltered scan report',
            "        if: ${{ always() && (steps.sast_scan.outcome == 'success' || steps.sast_scan.outcome == 'failure' || steps.sast_scan.outcome == 'cancelled') }}",
            '        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2',
            '        with:', '          name: raw-bandit-report', '          path: ${{ runner.temp }}/swassh-sast-output/',
            '          if-no-files-found: error'])
        self.assertLess(security.index('      - name: Verified SAST v2 scan and individual qualification'),
                        security.index('      - name: Preserve the unfiltered scan report'))

    def test_original_v1_oracles_remain_byte_identical_and_executable(self):
        reference = ROOT/'tests/sast_v1_reference'
        hashes = {
            'pyproject.toml': '6958cb2a626d581bb39dd4f0cbd1943d93428991758b1d4233e3e2953d426179',
            '.github/bandit-requirements.txt': 'b00277e797c2149ec6ce69bfda42bb1413bb77424094c7128423343221d98460',
            '.github/workflows/ci.yml': 'dfd6abeddeaa7c138b45da01a36575addb5f76c299575208fd24dfd2fbeddff9',
            '.github/workflows/release.yml': '23951e76c3521f1ee89b297737df48e0f4299435f65d8359ec8c77943db372a0',
            'tests/test_sast_workflow_contracts.py': 'd2f130fe71f27a5c6cad196e17fca6cbac266a4109b4ed559e1a21a3a620b9e2'}
        for name, digest in hashes.items():
            self.assertEqual(hashlib.sha256((reference/name).read_bytes()).hexdigest(), digest)
        old = runpy.run_path(str(reference/'tests/test_sast_workflow_contracts.py'))
        cls = old['MandatorySastWorkflowContracts']
        cls.setUp.__globals__['ROOT'] = reference
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        self.assertEqual(suite.countTestCases(), 4)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, 4)
        self.assertFalse(result.skipped)
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)


if __name__ == '__main__':
    unittest.main()
