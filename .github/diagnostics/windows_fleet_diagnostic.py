"""Observe the unchanged 50,000-host test in the parent and real spool worker.

The profiler adds overhead; its results locate work and do not certify a
production latency. No workload, assertion, memory limit or deadline is changed.
"""
from __future__ import annotations

import cProfile
import hashlib
import json
import os
from pathlib import Path
import platform
import pstats
import runpy
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
WORK = HERE.parents[1]
SOURCE = Path(os.environ['SWASSH_DIAG_SOURCE']).resolve(strict=True)
OUTPUT = Path(os.environ['SWASSH_DIAG_OUTPUT']).resolve()
sys.dont_write_bytecode = True
sys.path[:0] = [str(SOURCE / 'src'), str(SOURCE / 'tests')]


class WorkerObserver:
    """Profile the actual serialized operations without replacing their effects."""

    profile = None
    counts = {}
    elapsed = {}

    @classmethod
    def call(cls, operation, *arguments):
        from swassh.infrastructure.spool import store_operation
        if cls.profile is None:
            cls.profile = cProfile.Profile()
        before = time.perf_counter()
        cls.profile.enable()
        try:
            return store_operation(operation, *arguments)
        finally:
            cls.profile.disable()
            cls.counts[operation] = cls.counts.get(operation, 0) + 1
            cls.elapsed[operation] = cls.elapsed.get(operation, 0.0) + time.perf_counter() - before
            if operation == 'close':
                cls.profile.dump_stats(str(OUTPUT / 'worker.prof'))
                with (OUTPUT / 'worker.txt').open('x', encoding='utf-8') as stream:
                    pstats.Stats(cls.profile, stream=stream).strip_dirs().sort_stats('cumulative').print_stats(50)
                (OUTPUT / 'worker.json').open('x', encoding='utf-8').write(json.dumps({
                    'pid': os.getpid(), 'calls': cls.counts, 'seconds_by_operation': cls.elapsed,
                    'original_store_operation_used': True}, indent=2) + '\n')


def main():
    """Run exactly the original unittest, including setup, teardown and tracing."""
    review_bytes = Path(os.environ['SWASSH_DIAG_REVIEW']).read_bytes()
    assert hashlib.sha256(review_bytes).hexdigest() == '62e93faf3de43884f6fa8b0c2e0fe7dc7a3ad78d9958130a42967f74649e60f6'
    review = json.loads(review_bytes)
    assert len(review['records']) == 181 and all(row['approved'] for row in review['records'])
    gate = SOURCE / 'scripts/sast_gate.py'
    assert hashlib.sha256(gate.read_bytes()).hexdigest() == 'e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803'
    capture = runpy.run_path(str(gate))['SourceSnapshot'].capture
    assert capture(SOURCE) == review['source_files']
    inputs = {'sha256': '2b4ebbd8672d07c278b4acf4b813e0543e56a2ce27e701baebe645cac9746014',
              'source_files': review['source_files']}
    def unchanged():
        return all(hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() == digest
                   for name, digest in inputs['source_files'].items())
    assert unchanged()
    OUTPUT.mkdir()
    runpy.run_path(str(SOURCE / 'scripts/ci_shell.py'))['WindowsObjectOwner'].configure()
    from swassh.infrastructure import process_reporter
    import test_application
    assert test_application.__file__ == str(SOURCE / 'tests/test_application.py')
    # Spawn imports this observer module by name; the original initializer and
    # all real SQLite operations, process limits and RPC timeouts remain intact.
    process_reporter.store_operation = WorkerObserver.call
    suite = unittest.TestSuite([test_application.ApplicationTests('test_50000_fleet')])
    profile = cProfile.Profile()
    started = time.perf_counter()
    cpu = time.process_time()
    profile.enable()
    try:
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        profile.disable()
        profile.dump_stats(str(OUTPUT / 'parent.prof'))
        with (OUTPUT / 'parent.txt').open('x', encoding='utf-8') as stream:
            pstats.Stats(profile, stream=stream).strip_dirs().sort_stats('cumulative').print_stats(60)
    assert unchanged() and capture(SOURCE) == review['source_files']
    receipt = {'source_archive_sha256': inputs['sha256'], 'source_unchanged': True,
        'python': sys.version, 'platform': platform.platform(), 'seconds': time.perf_counter() - started,
        'parent_cpu_seconds': time.process_time() - cpu, 'tests': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors), 'skips': len(result.skipped),
        'successful': result.wasSuccessful(), 'original_test_used_without_changes': True,
        'profile_overhead_included': True, 'production_sources_modified': False,
        'publication_authorized': False}
    (OUTPUT / 'receipt.json').open('x', encoding='utf-8').write(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
