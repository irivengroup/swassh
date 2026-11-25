"""Only real control-transfer instruction events may credit their statements."""
import ast
import importlib.util
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
ExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_metrics.py'))['ExecutionCoverage']
SourceExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_source.py'))['SourceExecutionCoverage']
ChildCampaign = runpy.run_path(str(ROOT / 'scripts/coverage_processes.py'))['ChildCampaign']
PATH = ROOT / 'tests/control_cases/decisions.py'


class ControlInstructionTests(unittest.TestCase):
    def observe(self, operation, factory=ExecutionCoverage):
        observer = factory(PATH.parent)
        spec = importlib.util.spec_from_file_location('control_instruction_oracle', PATH)
        module = importlib.util.module_from_spec(spec)
        with observer:
            spec.loader.exec_module(module)
            operation(module)
        return observer.report()

    def test_executed_continue_and_break_have_distinct_instruction_hits(self):
        report = self.observe(lambda module: self.assertEqual(module.iterate([0, -1, 7], []), []))
        absent = [list(item) for item in report['modules'][0]['missing_statements']]
        self.assertFalse(any(row[-1] in {'Continue', 'Break'} for row in absent))
        self.assertIn([9, 8, 9, 28, 'Expr'], absent)

    def test_body_execution_does_not_credit_skipped_break_or_continue(self):
        report = self.observe(lambda module: self.assertEqual(module.iterate([1, 2], []), [1, 2]))
        missing = {row[-1] for row in report['modules'][0]['missing_statements']}
        self.assertIn('Continue', missing)
        self.assertIn('Break', missing)
        self.assertNotIn([9, 8, 9, 28, 'Expr'], [list(item) for item in report['modules'][0]['missing_statements']])

    def test_bare_reraise_requires_the_actual_reraise_instruction(self):
        events = []
        def execute(module):
            with self.assertRaisesRegex(ValueError, '^synthetic oracle$'):
                module.raise_again(True, events)
        row = self.observe(execute)['modules'][0]
        self.assertEqual(events, ['caught'])
        self.assertFalse(any(item[0] == 19 and item[-1] == 'Raise' for item in row['missing_statements']))
        self.assertTrue(any(item[0] == 16 and item[-1] == 'Return' for item in row['missing_statements']))

    def test_normal_return_does_not_credit_unexecuted_reraise(self):
        row = self.observe(lambda module: self.assertEqual(module.raise_again(False, []), 'normal'))['modules'][0]
        self.assertIn([19, 8, 19, 13, 'Raise'], [list(item) for item in row['missing_statements']])

    def test_same_line_guard_does_not_credit_its_unexecuted_raise(self):
        row = self.observe(lambda module: self.assertEqual(module.guarded_raise(False), 17))['modules'][0]
        self.assertIn([22, 13, 22, 40, 'Raise'], [list(item) for item in row['missing_statements']])

    def test_repeated_calls_retain_exact_statement_identity(self):
        def execute(module):
            self.assertEqual(module.iterate([0, -1], []), [])
            self.assertEqual(module.iterate([0, -1], []), [])
        row = self.observe(execute)['modules'][0]
        self.assertFalse(any(item[-1] in {'Continue', 'Break'} for item in row['missing_statements']))
        self.assertIn([9, 8, 9, 28, 'Expr'], [list(item) for item in row['missing_statements']])

    def test_source_and_raw_denominators_and_statement_observations_remain_independent_of_line_hits(self):
        before = SourceExecutionCoverage(PATH.parent).report()
        report = self.observe(lambda module: self.assertEqual(module.iterate([0, -1], []), []), SourceExecutionCoverage)
        for metric in before['global']:
            self.assertEqual(before['global'][metric]['total'], report['global'][metric]['total'])
            self.assertEqual(before['raw_python']['global'][metric]['total'], report['raw_python']['global'][metric]['total'])
        expected = sum(isinstance(node, ast.stmt) for node in ast.walk(ast.parse(PATH.read_bytes())))
        self.assertEqual(report['global']['statements']['total'], expected)
        self.assertEqual(report['global']['statements'], report['raw_python']['global']['statements'])
        self.assertFalse(any(item[-1] in {'Continue', 'Break'} for item in [list(item) for item in report['modules'][0]['missing_statements']]))

    def test_eager_child_journal_preserves_executed_control_transfers_even_at_abrupt_exit(self):
        code = ('import importlib.util,os,sys;'
                's=importlib.util.spec_from_file_location("control_child",sys.argv[1]);'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                'assert m.iterate([0,-1,7],[])==[];'
                'print(os.getpid(),flush=True);os._exit(17)')
        for factory in (ExecutionCoverage, SourceExecutionCoverage):
            with self.subTest(factory=factory.__name__), tempfile.TemporaryDirectory() as directory:
                observer = factory(PATH.parent)
                campaign = ChildCampaign(observer, directory)
                with campaign:
                    child = subprocess.run([sys.executable, '-c', code, str(PATH)], capture_output=True, timeout=20)
                self.assertEqual(child.returncode, 17, child.stderr.decode('utf-8', 'replace'))
                children = campaign.merge()['children']
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0]['pid'], int(child.stdout))
                row = observer.report()['modules'][0]
                self.assertFalse(any(item[-1] in {'Continue', 'Break'} for item in row['missing_statements']))
                self.assertIn([9, 8, 9, 28, 'Expr'], [list(item) for item in row['missing_statements']])

