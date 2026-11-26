"""Retain native timing evidence without changing the original test assertions."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


class NativeClockObservation:
    """Compare both clocks at the actual admitted interval boundaries."""

    @staticmethod
    def peak(intervals):
        rows = sorted((stamp, event, index) for index, pair in enumerate(intervals)
                      for stamp, event in zip(pair, ('start', 'stop')))
        active = maximum = 0
        for _, event, _ in rows:
            active += 1 if event == 'start' else -1
            maximum = max(active, maximum)
        assert active == 0
        return maximum

    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--root', type=Path, required=True)
        parser.add_argument('--review', type=Path, required=True)
        parser.add_argument('--output', type=Path, required=True)
        args = parser.parse_args()
        args.output.mkdir()
        source = args.root.resolve()
        review_bytes = args.review.read_bytes()
        assert hashlib.sha256(review_bytes).hexdigest() == 'faae6790c3ab0bbc1f0bb1eb4a449897e15f657b0d6bce6da2476b711a0242b7'
        expected = json.loads(review_bytes)['source_files']
        assert all(hashlib.sha256((source / name).read_bytes()).hexdigest() == sha for name, sha in expected.items())
        # Reuse the approved QA token-creation policy; never relax ownership.
        runpy.run_path(str(source / 'scripts/ci_shell.py'))['WindowsObjectOwner'].configure()
        sys.path[:0] = [str(source / 'src'), str(source / 'tests')]
        # Child interpreters need the same explicit source path as the CI QA.
        os.environ['PYTHONPATH'] = str(source / 'src')
        spec = importlib.util.spec_from_file_location('original_budget_tests', source / 'tests/test_improvements.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        records = []
        original_popen = subprocess.Popen
        original_temporary = tempfile.TemporaryDirectory
        for sample in range(3):
            folder = args.output / ('sample-' + str(sample))
            folder.mkdir()
            retained = folder / 'intervals'

            class RetainedTemporary(original_temporary):
                def cleanup(self):
                    if Path(self.name).is_dir() and not retained.exists():
                        shutil.copytree(self.name, retained)
                    super().cleanup()

            def observed_popen(argv, *positional, **keywords):
                argv = list(argv)
                assert argv[1] == '-c'
                original = 'start=time.monotonic();time.sleep(.08);end=time.monotonic()'
                assert argv[2].count(original) == 1
                argv[2] = argv[2].replace(original,
                    'start=time.monotonic();probe_start=time.perf_counter_ns();time.sleep(.08);probe_end=time.perf_counter_ns();end=time.monotonic()')
                marker = 'l.close();p.close()'
                assert argv[2].count(marker) == 1
                argv[2] = argv[2].replace(marker,
                    "with open(sys.argv[2]+'.trace','w') as f: json.dump({'monotonic':[start,end],'perf_ns':[probe_start,probe_end],'pid':__import__('os').getpid()},f)\n" + marker)
                return original_popen(argv, *positional, **keywords)

            case = module.SharedBudgetTests('test_ten_independent_processes_respect_shared_limit')
            with patch.object(module.tempfile, 'TemporaryDirectory', RetainedTemporary), patch.object(module.subprocess, 'Popen', observed_popen):
                with (folder / 'original-test.log').open('w', encoding='utf-8') as stream:
                    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite([case]))
            traces = [json.loads((retained / ('events-' + str(index) + '.trace')).read_bytes()) for index in range(10)]
            records.append({'sample': sample, 'tests': result.testsRun, 'failures': len(result.failures),
                            'errors': len(result.errors), 'skips': len(result.skipped),
                            'original_monotonic_peak': self.peak([row['monotonic'] for row in traces]),
                            'independent_perf_ns_peak': self.peak([row['perf_ns'] for row in traces]),
                            'traces': traces})
        with patch('swassh.infrastructure.bastion.time.monotonic', return_value=100.0):
            case = module.SharedBudgetTests('test_poll_yields_before_busy_peers_release_and_restores_connection_timeout')
            with (args.output / 'frozen-pacing-original-test.log').open('w', encoding='utf-8') as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite([case]))
        unchanged = all(hashlib.sha256((source / name).read_bytes()).hexdigest() == sha for name, sha in expected.items())
        receipt = {'source_commit': '335d68af15471ff1fe07974a13f2312d5fb3f70d',
                   'python': sys.version, 'clock_info': {name: vars(time.get_clock_info(name)) for name in ('monotonic', 'perf_counter')},
                   'samples': records, 'frozen_pacing_original': {'tests': result.testsRun, 'failures': len(result.failures),
                   'errors': len(result.errors), 'skips': len(result.skipped)},
                   'all_original_assertions_preserved': True, 'source_unchanged': unchanged,
                   'source_files': expected, 'publication_authorized': False}
        (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        assert unchanged
        print(json.dumps({key: value for key, value in receipt.items() if key != 'source_files'}))


if __name__ == '__main__':
    NativeClockObservation().run()
