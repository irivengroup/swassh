"""Observe original Windows idle-relay failures without modifying their assertions."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--review', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve(strict=True)
output = args.output.resolve()
output.mkdir(exist_ok=False)
review_data = args.review.read_bytes()
assert hashlib.sha256(review_data).hexdigest() == '98f2161a4507d3112c8ec06de4b7b8b50de85f283b813898e6e146c06c5a0c29'
review = json.loads(review_data)
gate = root / 'scripts/sast_gate.py'
assert hashlib.sha256(gate.read_bytes()).hexdigest() == 'e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803'
api = runpy.run_path(str(gate))
before = api['SourceSnapshot'].capture(root)
assert before == review['source_files'] and all(row['approved'] for row in review['records'])
owner = root / 'scripts/ci_shell.py'
assert hashlib.sha256(owner.read_bytes()).hexdigest() == '028c81193228dcdd43bd3e0c9e8238e5fc7ba2c76ac08bdbe35fab8d9c112005'
runpy.run_path(str(owner))['WindowsObjectOwner'].configure()
sys.path[:0] = [str(root / 'src'), str(root / 'tests')]
from test_bandwidth import RelayIntegrationTests

original = subprocess.Popen
observations = []
children = []
current_sample = None


class ObservedProcess(original):
    """Record process status/output only; the child's bytes and clocks are original."""
    def __init__(self, *arguments, **keywords):
        self.diagnostic_started = time.monotonic()
        self.diagnostic_sample = current_sample
        super().__init__(*arguments, **keywords)
        children.append(self)

    def communicate(self, *arguments, **keywords):
        stdout, stderr = super().communicate(*arguments, **keywords)
        observations.append({'sample': self.diagnostic_sample, 'pid': self.pid, 'returncode': self.returncode,
                             'elapsed': time.monotonic() - self.diagnostic_started,
                             'stdout_bytes': len(stdout or b''),
                             'stderr': (stderr or b'').decode('utf-8', errors='backslashreplace')[:8192]})
        return stdout, stderr


class DiagnosticResult(unittest.TextTestResult):
    def addFailure(self, test, error):
        states = []
        for process in children:
            code = process.poll()
            state = {'pid': process.pid, 'returncode_at_assertion': code,
                     'elapsed': time.monotonic() - process.diagnostic_started}
            if code is not None:
                try:
                    process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    state['output_capture_timed_out'] = True
            states.append(state)
        observations.append({'sample': current_sample, 'assertion_failure_process_states': states})
        super().addFailure(test, error)


results = []
with patch.object(subprocess, 'Popen', ObservedProcess), (output / 'tests.log').open('x', encoding='utf-8') as log:
    for index in range(20):
        current_sample = index
        children.clear()
        suite = unittest.TestSuite([RelayIntegrationTests('test_idle_deadline_uses_the_guardian_prepared_policy')])
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=DiagnosticResult).run(suite)
        results.append({'sample': index, 'tests': result.testsRun, 'failures': len(result.failures),
                        'errors': len(result.errors), 'skips': len(result.skipped)})
        assert api['SourceSnapshot'].capture(root) == before
        (output / 'partial.json').write_text(json.dumps({'results': results, 'observations': observations}, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(results[-1]), flush=True)
receipt = {'diagnostic_only': True, 'publication_authorized': False, 'python': sys.version,
           'source_files': before, 'source_unchanged': True, 'results': results, 'observations': observations,
           'child_program_argv_and_deadlines_unchanged': True,
           'approved_review_sha256': hashlib.sha256(review_data).hexdigest()}
(output / 'receipt.json').open('x', encoding='utf-8').write(json.dumps(receipt, indent=2) + '\n')
raise SystemExit(0 if all(not row['failures'] and not row['errors'] and not row['skips'] for row in results) else 1)
