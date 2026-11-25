"""Standard-library CI gates: syntax, imports, security rules and unittest."""

import ast
import compileall
import sys
import os
import unittest
from pathlib import Path
from import_policy import guarded_stdlib_import

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")


def static_checks():
    count = 0
    for folder in ("src", "tests", "scripts", "build_support", "benchmarks"):
        for path in (ROOT / folder).rglob("*.py"):
            content = path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(path))
            parents={child:parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            if any(
                line.rstrip() != line or "\t" in line for line in content.splitlines()
            ):
                raise ValueError(f"formatting violation: {path}")
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = (
                        [item.name for item in node.names]
                        if isinstance(node, ast.Import)
                        else [node.module or ""]
                    )
                    if isinstance(node, ast.ImportFrom) and node.level:
                        continue
                    for name in names:
                        module = name.split(".")[0]
                        # Test/qualification harnesses may share checked-in
                        # siblings; this never admits an external dependency.
                        local_module = folder in {'scripts', 'tests'} and (ROOT / folder / (module + '.py')).is_file()
                        if (
                            module
                            and module not in sys.stdlib_module_names
                            and module != "swassh"
                            and not local_module
                            and not guarded_stdlib_import(module,node,tree,parents)
                        ):
                            raise ValueError(
                                f"non-standard dependency: {name} in {path}"
                            )
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in {
                        "eval",
                        "exec",
                    }:
                        raise ValueError(f"dynamic code execution forbidden: {path}")
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "shell"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value
                        ):
                            raise ValueError(f"shell=True forbidden: {path}")
            count += 1
    if not compileall.compile_dir(ROOT / "src", quiet=1):
        raise ValueError("syntax compilation failed")
    print(
        f"Static gates PASS: {count} modules, standard-library imports only", flush=True
    )


# The Windows 3.12 debug runner spends substantial time capturing stacks for
# this large integration case. Run it once in an independent process while the
# remaining cases run normally. Debug mode, assertions and the outer 900-second
# qualification budget are unchanged; every discovered case must be accounted.
ISOLATED_CASE = 'test_transfers.TransferTests.test_receipts_reporting_bounded_fleet'
WORKER_LOG_LIMIT = 8 * 1024**2


class PrefixedStream:
    """Retain complete sub-run output without ambiguous top-level summaries."""
    def __init__(self, stream, prefix):
        self.stream, self.prefix, self.start = stream, prefix, True

    def write(self, text):
        for part in text.splitlines(keepends=True):
            if self.start:
                self.stream.write(self.prefix)
            self.stream.write(part)
            self.start = part.endswith('\n')
        return len(text)

    def flush(self):
        self.stream.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def split_isolated_case(suite):
    """Partition without executing or discarding any discovered test."""
    retained, isolated = unittest.TestSuite(), []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            remaining, selected = split_isolated_case(item)
            if remaining.countTestCases():
                retained.addTest(remaining)
            isolated.extend(selected)
        elif item.id() == ISOLATED_CASE:
            isolated.append(item)
        else:
            retained.addTest(item)
    return retained, isolated


def worker_identity(nonce):
    """Bind a worker result to the exact script, case source and interpreter."""
    import hashlib
    return {'nonce': nonce, 'case': ISOLATED_CASE, 'python': list(sys.version_info[:3]),
            'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'test_sha256': hashlib.sha256((ROOT/'tests/test_transfers.py').read_bytes()).hexdigest()}


def validate_worker_result(value, identity, returncode):
    """Reject absent, foreign, incomplete or inconsistent worker evidence."""
    fields = set(identity) | {'tests_run', 'skipped', 'failures', 'errors', 'successful',
                              'expected_failures', 'unexpected_successes'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('isolated test result schema mismatch')
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in identity.items()):
        raise ValueError('isolated test result provenance mismatch')
    if type(value['tests_run']) is not int or value['tests_run'] != 1:
        raise ValueError('isolated test did not execute exactly once')
    for field in ('skipped', 'failures', 'errors', 'expected_failures', 'unexpected_successes'):
        if not isinstance(value[field], list) or any(not isinstance(item, str) for item in value[field]):
            raise ValueError('isolated test result type mismatch')
    if value['skipped']:
        raise ValueError('required isolated test was skipped')
    if value['expected_failures'] or value['unexpected_successes']:
        raise ValueError('required isolated test cannot use expected-failure semantics')
    successful = not value['failures'] and not value['errors']
    if type(value['successful']) is not bool or value['successful'] is not successful:
        raise ValueError('isolated test outcome contradicts its evidence')
    if type(returncode) is not int or returncode != (0 if successful else 1):
        raise ValueError('isolated test exit code contradicts its evidence')
    return value


def isolated_worker(nonce, destination):
    """Execute the original test and its fixtures once, with normal debug mode."""
    import json
    if len(nonce) != 32 or any(char not in '0123456789abcdef' for char in nonce):
        raise ValueError('invalid isolated test nonce')
    sys.path.insert(0, str(ROOT/'tests'))
    suite = unittest.defaultTestLoader.loadTestsFromName(ISOLATED_CASE)
    _, selected = split_isolated_case(suite)
    if suite.countTestCases() != 1 or len(selected) != 1:
        raise ValueError('required isolated test is missing or duplicated')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    payload = worker_identity(nonce) | {
        'tests_run': result.testsRun, 'skipped': [reason for _, reason in result.skipped],
        'failures': [trace for _, trace in result.failures], 'errors': [trace for _, trace in result.errors],
        'expected_failures': [trace for _, trace in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        'successful': result.wasSuccessful()}
    with Path(destination).open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=True)
        stream.write('\n')
    return 0 if result.wasSuccessful() else 1


def isolated_run(suite):
    """Run two bounded test processes; aggregate only verified actual results."""
    import json
    import secrets
    import subprocess
    import tempfile
    import threading
    import time
    from swassh.infrastructure.windows import KillJob

    expected = suite.countTestCases()
    retained, selected = split_isolated_case(suite)
    if len(selected) != 1 or retained.countTestCases() + 1 != expected:
        raise ValueError('full suite partition is incomplete or ambiguous')
    cls = type(selected[0])
    if (cls.setUpClass.__func__ is not unittest.TestCase.setUpClass.__func__
            or cls.tearDownClass.__func__ is not unittest.TestCase.tearDownClass.__func__):
        raise ValueError('isolated case requires independent class fixtures')
    module = sys.modules[cls.__module__]
    if hasattr(module, 'setUpModule') or hasattr(module, 'tearDownModule'):
        raise ValueError('isolated case requires independent module fixtures')
    # Retain the kill-on-close job for this process lifetime. A terminated parent
    # cannot leave an isolated test or its descendants beyond the original gate.
    job = KillJob()
    started = time.monotonic()
    nonce = secrets.token_hex(16)
    identity = worker_identity(nonce)
    outcome, infrastructure_error = None, None
    result = unittest.TestResult()
    with tempfile.TemporaryDirectory(prefix='swassh-unit-worker-') as directory:
        result_path, log_path = Path(directory)/'result.json', Path(directory)/'worker.log'
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--isolated-case', nonce, str(result_path)]
        with log_path.open('xb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            stopped = threading.Event()
            monitor_error = []

            def monitor():
                while not stopped.wait(.05) and process.poll() is None:
                    try:
                        if log_path.stat().st_size > WORKER_LOG_LIMIT:
                            raise ValueError('isolated test log exceeds its bounded budget')
                        if time.monotonic() - started >= 900:
                            raise TimeoutError('isolated test exceeded the unchanged 900-second gate')
                    except (OSError, ValueError, TimeoutError) as error:
                        monitor_error.append(error)
                        process.kill()
                        return

            watcher = threading.Thread(target=monitor, daemon=True)
            watcher.start()
            try:
                result = unittest.TextTestRunner(stream=PrefixedStream(sys.stderr, '[main] '), verbosity=2).run(retained)
                returncode = process.wait(timeout=max(.001, 900 - (time.monotonic()-started)))
                if monitor_error:
                    raise monitor_error[0]
                if log_path.stat().st_size > WORKER_LOG_LIMIT:
                    raise ValueError('isolated test log exceeds its bounded budget')
                if result_path.stat().st_size > 2 * 1024**2:
                    raise ValueError('isolated test result exceeds its bounded budget')
                outcome = validate_worker_result(json.loads(result_path.read_bytes()), identity, returncode)
            except (OSError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                infrastructure_error = type(error).__name__ + ': ' + str(error)
            finally:
                stopped.set()
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                watcher.join(timeout=2)
                if watcher.is_alive():
                    raise RuntimeError('isolated test monitor did not stop')
        PrefixedStream(sys.stderr, '[isolated] ').write(log_path.read_text(encoding='utf-8', errors='backslashreplace'))
    total = result.testsRun + (outcome['tests_run'] if outcome is not None else 0)
    failures = len(result.failures) + (len(outcome['failures']) if outcome is not None else 0)
    errors = len(result.errors) + (len(outcome['errors']) if outcome is not None else 1)
    skipped = len(result.skipped)
    successful = (result.wasSuccessful() and outcome is not None and outcome['successful']
                  and not result.expectedFailures and total == expected and infrastructure_error is None)
    for test, _ in result.errors:
        print('ERROR: ' + test.id(), file=sys.stderr)
    for test, _ in result.failures:
        print('FAIL: ' + test.id(), file=sys.stderr)
    if outcome is not None and (outcome['errors'] or outcome['failures']):
        print('ERROR: ' + ISOLATED_CASE, file=sys.stderr)
    if infrastructure_error:
        print('ERROR: isolated test evidence: ' + infrastructure_error, file=sys.stderr)
    if result.expectedFailures:
        print('ERROR: required unit suite contains expected failures', file=sys.stderr)
    print(f'\nRan {total} tests in {time.monotonic()-started:.3f}s\n', file=sys.stderr)
    if successful:
        print('OK' + (f' (skipped={skipped})' if skipped else ''), file=sys.stderr)
    else:
        print(f'FAILED (failures={failures}, errors={errors}, skipped={skipped}, expected failures={len(result.expectedFailures)})', file=sys.stderr)
    return 0 if successful else 1


def main():
    if sys.argv[1:]:
        if len(sys.argv) != 4 or sys.argv[1] != '--isolated-case':
            raise ValueError('invalid internal unit worker arguments')
        return isolated_worker(sys.argv[2], sys.argv[3])
    static_checks()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    if os.name == 'nt' and sys.version_info[:2] == (3, 12):
        return isolated_run(suite)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
