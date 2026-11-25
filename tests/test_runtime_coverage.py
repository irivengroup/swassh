"""Hand-enumerated independent decisions for inlined-comprehension runtimes."""
import importlib.util
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SourceExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_source.py'))['SourceExecutionCoverage']


class RuntimeLoopOracles(unittest.TestCase):
    def observe(self, name, values):
        path = ROOT / 'tests/runtime_cases/decisions.py'
        spec = importlib.util.spec_from_file_location('independent_loop_oracle', path)
        module = importlib.util.module_from_spec(spec)
        observer = SourceExecutionCoverage(path.parent)
        events = []
        with observer:
            spec.loader.exec_module(module)
            result = getattr(module, name)(values, events)
        self.assertIs(result, events)
        self.assertEqual(events, ([7] if values else []))
        report = observer.report()
        self.assertTrue(report['source_mapping_complete'], report['unmapped_source_decisions'])
        row = report['modules'][0]
        start = getattr(module, name).__code__.co_firstlineno
        units = [unit for unit in row['source_branch_units'] if start < unit['site'][0] <= start + 4]
        self.assertEqual(len(units), 2, 'both source loops must remain inventoried')
        self.assertTrue(all(unit['kind'] == 'iteration' for unit in units))
        self.assertEqual(row['metrics']['boolean_conditions']['total'], 0)
        return [unit['observed'] for unit in units]

    def test_inner_completion_does_not_credit_outer_exhaustion_after_break(self):
        self.assertEqual(self.observe('first', [7]), [[True], [False, True]])

    def test_empty_comprehension_does_not_credit_either_body(self):
        self.assertEqual(self.observe('first', []), [[False], [False]])

    def test_normal_outer_completion_requires_both_actual_exhaustions(self):
        self.assertEqual(self.observe('complete', [7]), [[False, True], [False, True]])

    def test_empty_normal_loop_does_not_credit_body_observations(self):
        self.assertEqual(self.observe('complete', []), [[False], [False]])


if __name__ == '__main__':
    unittest.main()
