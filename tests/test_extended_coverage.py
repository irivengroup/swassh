"""Extended jump prefixes must not replace the tested value's source span."""
import dis
import importlib.util
from pathlib import Path
import runpy
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
ExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_metrics.py'))['ExecutionCoverage']
SourceExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_source.py'))['SourceExecutionCoverage']
ChildCampaign = runpy.run_path(str(ROOT / 'scripts/coverage_processes.py'))['ChildCampaign']


class ExtendedJumpOracles(unittest.TestCase):
    def check_observations(self, factory, *, complete):
        path = ROOT / 'tests/extended_cases/decisions.py'
        spec = importlib.util.spec_from_file_location('extended_jump_oracle', path)
        module = importlib.util.module_from_spec(spec)
        observer = factory(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.extended(False, True, []), [])
            if complete:
                self.assertEqual(module.extended(True, False, []), [])
                self.assertEqual(module.extended(True, True, []), list(range(20)))
        self.assertTrue(any(item.opname == 'EXTENDED_ARG' for item in dis.get_instructions(module.extended)))
        report = observer.report()
        row = report['modules'][0]
        self.assertEqual(row['metrics']['boolean_conditions']['total'], 4)
        self.assertEqual(row['metrics']['boolean_conditions']['covered'], 4 if complete else 1)
        self.assertEqual(row['metrics']['branches']['total'], 4)
        self.assertEqual(row['metrics']['branches']['covered'], 4 if complete else 1)
        if factory is SourceExecutionCoverage:
            self.assertTrue(report['source_mapping_complete'], report['unmapped_source_decisions'])
            self.assertEqual([unit['observed'] for unit in row['source_boolean_units']],
                             [[False, True], [False, True]] if complete else [[False], []])

    def test_raw_extended_jumps_keep_both_elementary_conditions(self):
        self.check_observations(ExecutionCoverage, complete=True)

    def test_raw_extended_short_circuit_never_credits_the_second_input(self):
        self.check_observations(ExecutionCoverage, complete=False)

    def test_source_extended_jumps_keep_both_elementary_conditions(self):
        self.check_observations(SourceExecutionCoverage, complete=True)

    def test_source_extended_short_circuit_never_credits_the_second_input(self):
        self.check_observations(SourceExecutionCoverage, complete=False)

    def test_child_extended_short_circuit_survives_abrupt_exit_without_inferred_hits(self):
        path = ROOT / 'tests/extended_cases/decisions.py'
        code = ('import importlib.util,os,sys;'
                's=importlib.util.spec_from_file_location("extended_child",sys.argv[1]);'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                'assert m.extended(False,True,[])==[];'
                'print(os.getpid(),flush=True);os._exit(17)')
        for factory in (ExecutionCoverage, SourceExecutionCoverage):
            with self.subTest(factory=factory.__name__), tempfile.TemporaryDirectory() as directory:
                observer = factory(path.parent)
                campaign = ChildCampaign(observer, directory)
                with campaign:
                    child = subprocess.run([sys.executable, '-c', code, str(path)],
                                           capture_output=True, timeout=20)
                self.assertEqual(child.returncode, 17, child.stderr.decode('utf-8', 'replace'))
                children = campaign.merge()['children']
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0]['pid'], int(child.stdout))
                row = observer.report()['modules'][0]
                self.assertEqual(row['metrics']['branches']['total'], 4)
                self.assertEqual(row['metrics']['branches']['covered'], 1)
                self.assertEqual(row['metrics']['boolean_conditions']['covered'], 1)
                self.assertTrue(any(value[-1] == 'Expr' for value in row['missing_statements']))
