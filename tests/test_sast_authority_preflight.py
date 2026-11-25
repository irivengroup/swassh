"""Exercise the reported CI defects against a preserved or corrected checkout."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReportedWorkflowRegression(unittest.TestCase):
    """Observe preflight refusals; check the finite artifact-retention policy."""

    def setUp(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.security = text.split('  security:\n', 1)[1]

    def step(self, name):
        section = self.security.split('      - name: ' + name + '\n', 1)[1]
        return section.split('\n      - ', 1)[0]

    def test_missing_authority_names_every_repository_variable_without_values(self):
        section = self.step('Require detached operator authority')
        command = ' '.join(line.strip() for line in section.split('        run: >-\n', 1)[1].splitlines())
        arguments = shlex.split(command)
        self.assertEqual(arguments[:4], ['python', '-I', '-B', '-c'])
        mapping = {'REVIEW_REF': 'SWASSH_SAST_REVIEW_REF',
                   'REVIEW_SHA': 'SWASSH_SAST_REVIEW_SHA256',
                   'GATE_SHA': 'SWASSH_SAST_GATE_SHA256'}
        valid = {'REVIEW_REF': 'a' * 40, 'REVIEW_SHA': 'b' * 64, 'GATE_SHA': 'c' * 64}
        cases = [({}, set(mapping))]
        for key in mapping:
            for value in ('', ' ', 'A' * len(valid[key]), valid[key][:-1], valid[key] + '\n'):
                cases.append((valid | {key: value}, {key}))
        cases.append((valid, set()))
        for values, invalid in cases:
            with self.subTest(invalid=sorted(invalid), lengths={k: len(v) for k, v in values.items()}):
                environment = {k: v for k, v in os.environ.items() if k not in mapping}
                environment.update(values)
                result = subprocess.run([sys.executable, *arguments[1:]], env=environment,
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 1 if invalid else 0)
                self.assertEqual(result.stdout, '')
                for key, public in mapping.items():
                    self.assertEqual(public in result.stderr, key in invalid)
                for value in valid.values():
                    self.assertNotIn(value, result.stderr)

    def test_raw_report_is_required_after_success_failure_or_cancellation_only(self):
        scan = self.step('Verified SAST v2 scan and individual qualification')
        upload = self.step('Preserve the unfiltered scan report')
        self.assertIn('        id: sast_scan\n', scan)
        condition = next(line.strip()[4:] for line in upload.splitlines() if line.strip().startswith('if:'))
        self.assertEqual(condition, "${{ always() && (steps.sast_scan.outcome == 'success' || steps.sast_scan.outcome == 'failure' || steps.sast_scan.outcome == 'cancelled') }}")
        # Finite documented Actions outcomes: a skipped/unstarted scan has no raw
        # evidence. An attempted failed scan must still preserve its evidence.
        accepted = re.findall(r"steps\.sast_scan\.outcome == '([a-z]+)'", condition)
        for outcome in ('success', 'failure', 'cancelled', 'skipped', ''):
            self.assertEqual(outcome in accepted, outcome in {'success', 'failure', 'cancelled'})
        self.assertIn('          if-no-files-found: error', upload)
        self.assertNotIn('continue-on-error', self.security)


if __name__ == '__main__':
    unittest.main(verbosity=2)
