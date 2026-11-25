"""Integration contracts keeping raw SAST failures on the release dependency path.

The repository uses explicit workflow jobs and steps. These tests deliberately
check that finite layout; they do not implement a general YAML interpreter.
"""

from pathlib import Path
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MandatorySastWorkflowContracts(unittest.TestCase):
    """A reviewed finding remains a failure of the unfiltered release gate."""

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

    def test_raw_scan_cannot_filter_suppress_skip_or_ignore_failure(self):
        step = self._step(self._job('security'), 'Raw Bandit gate without suppressions')
        self.assertEqual(step, [
            '      - name: Raw Bandit gate without suppressions',
            '        run: .qa-bandit/bin/python -I -B -m bandit --recursive src tests scripts build_support benchmarks --ignore-nosec --format json --output bandit-full.json'])
        # No wrapper, pipeline, shell fallback or configurable severity threshold
        # may transform Bandit's actual non-zero exit into a successful job.
        args = shlex.split(step[1].partition('run: ')[2])
        self.assertEqual(args[args.index('--recursive')+1:args.index('--ignore-nosec')],
                         ['src', 'tests', 'scripts', 'build_support', 'benchmarks'])

    def test_only_the_locked_qa_toolchain_is_installed_in_a_private_environment(self):
        security = self._job('security')
        install = self._step(security, 'Install hash-locked QA scanner')
        self.assertEqual(install, [
            '      - name: Install hash-locked QA scanner', '        run: |',
            '          python -m venv .qa-bandit',
            '          .qa-bandit/bin/python -I -m pip --isolated install --require-hashes --only-binary=:all: --no-deps --requirement .github/bandit-requirements.txt',
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

    def test_failure_report_is_retained_without_turning_failure_into_success(self):
        security = self._job('security')
        step = self._step(security, 'Preserve the unfiltered scan report')
        self.assertEqual(step, [
            '      - name: Preserve the unfiltered scan report',
            '        if: always()',
            '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2',
            '        with:', '          name: raw-bandit-report', '          path: bandit-full.json',
            '          if-no-files-found: error'])
        self.assertLess(security.index('      - name: Raw Bandit gate without suppressions'),
                        security.index('      - name: Preserve the unfiltered scan report'))


if __name__ == '__main__':
    unittest.main()
