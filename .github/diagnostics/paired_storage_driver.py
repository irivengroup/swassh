"""Run the exact 50,000-host test twice, on two QA temp locations on one VM."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time


def main():
    source = Path(os.environ['SWASSH_DIAG_SOURCE']).resolve(strict=True)
    output = Path(os.environ['SWASSH_DIAG_OUTPUT']).resolve()
    output.mkdir()
    observer = Path(__file__).with_name('fleet_storage_observer.py')
    assert hashlib.sha256(observer.read_bytes()).hexdigest() == os.environ['SWASSH_DIAG_OBSERVER_SHA256']
    review_bytes = Path(os.environ['SWASSH_DIAG_REVIEW']).read_bytes()
    assert hashlib.sha256(review_bytes).hexdigest() == '62e93faf3de43884f6fa8b0c2e0fe7dc7a3ad78d9958130a42967f74649e60f6'
    review = json.loads(review_bytes)
    gate = source / 'scripts/sast_gate.py'
    assert hashlib.sha256(gate.read_bytes()).hexdigest() == 'e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803'
    capture = runpy.run_path(str(gate))['SourceSnapshot'].capture
    assert capture(source) == review['source_files']
    sys.path.insert(0, str(source / 'src'))
    runpy.run_path(str(source / 'scripts/ci_shell.py'))['WindowsObjectOwner'].configure()
    from swassh.infrastructure.windows import KillJob
    job = KillJob()  # Retained until this operator process exits, as documented.
    outcomes = []
    for label in ('default', 'allocated'):
        environment = os.environ.copy()
        environment['SWASSH_DIAG_OUTPUT'] = str(output / label)
        if label == 'allocated':
            temp = Path(environment['RUNNER_TEMP']).resolve(strict=True)
            for name in ('TMPDIR', 'TEMP', 'TMP'):
                environment[name] = str(temp)
        started = time.perf_counter()
        timed_out = False
        with (output / (label + '-tests.log')).open('xb') as stream:
            try:
                completed = subprocess.run([sys.executable, '-B', str(observer)],
                    cwd=source, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=900)
                code = completed.returncode
            except subprocess.TimeoutExpired:
                timed_out, code = True, None
        receipt_path = output / label / 'receipt.json'
        child = json.loads(receipt_path.read_bytes()) if receipt_path.is_file() else None
        successful = code == 0 and not timed_out and child is not None and child['successful'] and child['source_unchanged']
        outcomes.append({'label': label, 'returncode': code, 'timed_out': timed_out,
            'observer_seconds': time.perf_counter() - started, 'successful': successful,
            'child_receipt': child})
        (output / (label + '-outcome.json')).open('x', encoding='utf-8').write(json.dumps(outcomes[-1], indent=2) + '\n')
        print(json.dumps(outcomes[-1]), flush=True)
    assert capture(source) == review['source_files']
    result = {'source_unchanged': True, 'source_commit': '5ee5b56572e9fc92d64bc1f3447a93678bd18bfd',
        'runtime': sys.version, 'same_runner': True, 'original_workload': 50000, 'runs': outcomes,
        'source_or_SQLite_settings_changed': False, 'profile_overhead_in_both_runs': True,
        'only_temp_location_changed': True, 'order': ['default', 'allocated'],
        'one_full_pair_only_order_effect_not_excluded': True,
        'successful': all(r['successful'] for r in outcomes), 'publication_authorized': False}
    (output / 'paired-receipt.json').open('x', encoding='utf-8').write(json.dumps(result, indent=2) + '\n')
    return 0 if result['successful'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
