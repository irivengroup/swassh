"""Runtime warnings remain visible evidence without changing application tests."""
import contextlib
import io
import json
import logging
from pathlib import Path
import runpy
import unittest

RuntimeDiagnostics=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/coverage_diagnostics.py'))['RuntimeDiagnostics']


class DiagnosticTests(unittest.TestCase):
    def test_runtime_record_is_retained_and_application_stderr_unchanged(self):
        logger=logging.getLogger('asyncio')
        before=list(logger.handlers),logger.propagate,logger.level
        journal,application=io.StringIO(),io.StringIO()
        with contextlib.redirect_stderr(application),RuntimeDiagnostics(journal) as capture:
            logger.warning('synthetic framework warning %s','x'*1024)
            application.write('swassh: application progress\n')
        self.assertEqual(application.getvalue(),'swassh: application progress\n')
        self.assertEqual(json.loads(journal.getvalue())['message'],'synthetic framework warning '+'x'*1024)
        self.assertEqual(capture.records,1)
        self.assertEqual((list(logger.handlers),logger.propagate,logger.level),before)

    def test_budget_and_application_exceptions_are_never_swallowed(self):
        logger=logging.getLogger('asyncio')
        before=list(logger.handlers),logger.propagate
        with self.assertRaisesRegex(ValueError,'budget exceeded'):
            with RuntimeDiagnostics(io.StringIO(),max_bytes=1): logger.warning('retained failure')
        self.assertEqual((list(logger.handlers),logger.propagate),before)
        with self.assertRaisesRegex(RuntimeError,'application failure'):
            with RuntimeDiagnostics(io.StringIO()): raise RuntimeError('application failure')
        self.assertEqual((list(logger.handlers),logger.propagate),before)
