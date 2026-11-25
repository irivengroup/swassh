"""Require every authenticated SSH/ProxyJump integration test, without skips."""
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeNetworkGate:
    """Distinguish missing native prerequisites from executed network evidence."""

    @staticmethod
    def complete(result, expected):
        """A successful unittest result alone can hide an entirely skipped suite."""
        return (expected > 0 and result.testsRun == expected and
                result.wasSuccessful() and not result.skipped)

    def run(self, pattern='test_native_ssh.py'):
        sys.path.insert(0, str(ROOT/'src'))
        os.environ['PYTHONPATH'] = str(ROOT/'src') + os.pathsep + os.environ.get('PYTHONPATH', '')
        suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'), pattern=pattern)
        expected = suite.countTestCases()
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        complete = self.complete(result, expected)
        print(json.dumps({'status': 'executed' if complete else 'incomplete',
                          'expected': expected, 'run': result.testsRun,
                          'skipped': len(result.skipped), 'errors': len(result.errors),
                          'failures': len(result.failures)}))
        return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(NativeNetworkGate().run('test_native_auth.py' if sys.argv[1:] == ['--authentication'] else 'test_native_ssh.py'))
