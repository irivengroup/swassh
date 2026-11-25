"""Hand-enumerated contracts, independent of the bytecode counter's totals."""
import asyncio
import copy
from contextlib import nullcontext
import importlib.util
import inspect
from pathlib import Path
import runpy
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SOURCE_TOOLS = runpy.run_path(str(ROOT / 'scripts/coverage_source.py'))
SourceExecutionCoverage, gate = SOURCE_TOOLS['SourceExecutionCoverage'], SOURCE_TOOLS['gate']
ExecutionCoverage = runpy.run_path(str(ROOT / 'scripts/coverage_metrics.py'))['ExecutionCoverage']
ChildCampaign = runpy.run_path(str(ROOT / 'scripts/coverage_processes.py'))['ChildCampaign']


class SourceOracleTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'tests/source_cases/decisions.py'
        spec = importlib.util.spec_from_file_location('source_oracle', self.path)
        self.module = importlib.util.module_from_spec(spec)
        self.observer = SourceExecutionCoverage(self.path.parent)
        with self.observer:
            spec.loader.exec_module(self.module)

    def units(self, function):
        lines, start = inspect.getsourcelines(getattr(self.module, function))
        row = self.observer.report()['modules'][0]
        return [unit for unit in row['source_branch_units'] if start <= unit['site'][0] < start + len(lines)]

    def assert_units(self, function, outcomes, kinds=None):
        units = self.units(function)
        self.assertEqual([unit['observed'] for unit in units], outcomes, units)
        if kinds is not None:
            self.assertEqual([unit['kind'] for unit in units], kinds)
        lines, start = inspect.getsourcelines(getattr(self.module, function))
        booleans = [unit for unit in self.observer.report()['modules'][0]['source_boolean_units']
                    if start <= unit['site'][0] < start + len(lines)]
        expected_boolean = [expected for unit, expected in zip(units, outcomes) if unit['kind'] == 'truth']
        self.assertEqual([unit['observed'] for unit in booleans], expected_boolean)

    def test_short_circuit_does_not_invent_an_unobserved_second_value(self):
        with self.observer:
            self.assertEqual(self.module.choose(False, True), 'no')
        self.assert_units('choose', [[False], []])
        with self.observer:
            self.assertEqual(self.module.choose(True, False), 'no')
            self.assertEqual(self.module.choose(True, True), 'yes')
        self.assert_units('choose', [[False, True], [False, True]])

    def test_truth_conversion_is_never_repeated_and_failures_invent_no_outcome(self):
        class Truth:
            calls = 0
            def __bool__(self):
                self.calls += 1
                return False
        first = Truth()
        with self.observer:
            self.assertEqual(self.module.choose(first, True), 'no')
        self.assertEqual(first.calls, 1)
        self.assert_units('choose', [[False], []])
        class Broken:
            def __bool__(self):
                raise ValueError('truth failed')
        with self.observer, self.assertRaisesRegex(ValueError, '^truth failed$'):
            self.module.never_called(Broken())
        self.assert_units('never_called', [[]])

    def test_chain_comparisons_have_distinct_observations(self):
        with self.observer:
            self.assertEqual(self.module.between(2, 1, 3), 'outside')
            self.assertEqual(self.module.between(0, 2, 1), 'outside')
        self.assert_units('between', [[False, True], [False]])
        with self.observer:
            self.assertEqual(self.module.between(0, 1, 2), 'inside')
        self.assert_units('between', [[False, True], [False, True]])

    def test_while_compiler_copies_merge_only_the_same_source_tests(self):
        with self.observer:
            self.assertEqual(self.module.advance(1, 3), 3)
            self.assertEqual(self.module.advance(0, 3), 0)
        self.assert_units('advance', [[False, True], [False, True]])

    def test_none_predicate_truth_retains_source_polarity(self):
        with self.observer:
            self.assertEqual(self.module.optional(None), 'missing')
        self.assert_units('optional', [[True], []])
        with self.observer:
            self.assertEqual(self.module.optional(7), 'present')
        self.assert_units('optional', [[False, True], [True]])

    def test_value_preserving_boolean_does_not_test_the_returned_last_operand(self):
        first, second = [], object()
        with self.observer:
            self.assertIs(self.module.value_boolean(first, second), second)
        self.assert_units('value_boolean', [[False]])
        with self.observer:
            self.assertEqual(self.module.value_boolean(7, second), 7)
        self.assert_units('value_boolean', [[False, True]])

    def test_value_preserving_not_retains_the_elementary_operand_truth(self):
        with self.observer:
            self.assertIs(self.module.preserving_not(False, object()), True)
        self.assert_units('preserving_not', [[False]])
        alternative = object()
        with self.observer:
            self.assertIs(self.module.preserving_not(True, alternative), alternative)
        self.assert_units('preserving_not', [[False, True]])

    def test_negated_type_check_in_generator_does_not_invert_a_valid_member(self):
        with self.observer:
            self.assertFalse(self.module.invalid_members([{'one': 1}]))
        # The explicit type predicate was True for the valid mapping. Its
        # negated result is a value-preserving or operand in the generator.
        units = self.units('invalid_members')
        self.assertEqual([unit['observed'] for unit in units if unit['kind'] == 'truth'], [[True]])

    def test_double_negation_preserves_truth_and_calls_the_operand_once(self):
        class Truth:
            calls = 0
            def __bool__(self):
                self.calls += 1
                return True
        value = Truth()
        with self.observer:
            self.assertIs(self.module.preserving_double_not(value, object()), True)
        self.assertEqual(value.calls, 1)
        self.assert_units('preserving_double_not', [[True]])

    def test_compiler_any_reduction_does_not_credit_a_false_source_comparison(self):
        with self.observer:
            self.assertTrue(self.module.invalid_range([17]))
        # 0 <= 17 was True. The final <= 9 comparison produces the generator
        # value; any's internal truth branch is not another source comparison.
        units = self.units('invalid_range')
        self.assertEqual([unit['observed'] for unit in units if unit['kind'] == 'truth'], [[True]])

    def test_assignment_boundary_keeps_its_own_truth_conversion(self):
        class Alternating:
            calls = 0
            def __bool__(self):
                self.calls += 1
                return self.calls == 1
        value = Alternating()
        with self.observer:
            self.assertIsNone(self.module.assignment_test(value, object()))
        self.assertEqual(value.calls, 2)
        # Both tests exist: the or operand was True, the assigned value False.
        self.assert_units('assignment_test', [[False], [True]])

    def test_fused_value_operands_are_not_merged_with_other_loaded_names(self):
        with self.observer:
            self.assertEqual(self.module.fused_value(9, 0), (9, 17))
        self.assert_units('fused_value', [[False]])
        with self.observer:
            self.assertEqual(self.module.fused_value(0, 9), (0, 9))
        self.assert_units('fused_value', [[False, True]])

    def test_nested_generator_and_containing_comprehension_keep_two_iterations(self):
        with self.observer:
            self.assertEqual(self.module.nested_generator([2, 3]), {2: 2, 3: 3})
        self.assert_units('nested_generator', [[False, True], [False, True]], ['iteration', 'iteration'])

    def test_nested_comprehension_does_not_credit_an_unentered_inner_body(self):
        with self.observer:
            self.assertEqual(self.module.nested_iteration([[]]), [])
        self.assert_units('nested_iteration', [[False, True], [False]], ['iteration', 'iteration'])

    def test_generator_helper_can_contain_a_distinct_inlined_comprehension(self):
        with self.observer:
            self.assertEqual(self.module.generator_with_inlined_comprehension([[]]), ({},))
        self.assert_units('generator_with_inlined_comprehension', [[False], [False, True]], ['iteration', 'iteration'])

    def test_for_over_comprehension_does_not_merge_the_two_exhaustion_decisions(self):
        with self.observer:
            self.assertEqual(self.module.loop_over_comprehension([7]), 17)
        self.assert_units('loop_over_comprehension', [[True], [False, True]], ['iteration', 'iteration'])

    def test_inlined_comprehension_none_predicate_retains_its_source_truth(self):
        with self.observer:
            self.assertEqual(self.module.filtered_optional([7]), [7])
        units = self.units('filtered_optional')
        self.assertEqual([unit['observed'] for unit in units if unit['kind'] == 'truth'], [[True]])
        with self.observer:
            self.assertEqual(self.module.filtered_optional([None]), [])
        units = self.units('filtered_optional')
        self.assertEqual([unit['observed'] for unit in units if unit['kind'] == 'truth'], [[False, True]])

    def test_not_uses_the_elementary_operand_without_reevaluation(self):
        with self.observer:
            self.assertEqual(self.module.inverted(False), 'false')
        self.assert_units('inverted', [[False]])
        with self.observer:
            self.assertEqual(self.module.inverted(True), 'true')
        self.assert_units('inverted', [[False, True]])

    def test_iteration_has_two_outcomes_separate_from_truth_tests(self):
        with self.observer:
            self.assertEqual(self.module.count([True, False]), 1)
            self.assertEqual(self.module.count([]), 0)
        self.assert_units('count', [[False, True], [False, True]], ['iteration', 'truth'])

    def test_comprehension_filter_is_distinct_from_iteration(self):
        with self.observer:
            self.assertEqual(self.module.filtered([0, 2]), [2])
        self.assert_units('filtered', [[False, True], [False, True]], ['iteration', 'truth'])

    def test_generator_builtin_dispatch_stays_raw_and_never_credits_application_truth(self):
        with self.observer:
            self.assertEqual(self.module.packed([1, 2]), (1, 2))
            self.assertEqual(self.module.packed([]), ())
            self.assertEqual(self.module.any_value([False]), 'none')
        self.assert_units('packed', [[False, True]], ['iteration'])
        self.assert_units('any_value', [[False, True], [False]], ['iteration', 'truth'])
        self.assertTrue(self.observer.report()['raw_python_gate_failures'])

    def test_inline_any_cannot_credit_a_false_call_from_an_earlier_false_item(self):
        with self.observer:
            self.assertEqual(self.module.any_value([False, True]), 'some')
        units = self.units('any_value')
        self.assertEqual([unit['observed'] for unit in units if unit['kind'] == 'truth'], [[True]])

    def test_exception_dispatch_and_context_suppression_are_preserved_in_raw_counters(self):
        def fail():
            raise ValueError('expected')
        with self.observer:
            self.assertEqual(self.module.recover(lambda: 3), 3)
            self.assertEqual(self.module.recover(fail), 'recovered')
            self.assertEqual(self.module.managed(nullcontext()), 17)
        self.assert_units('recover', [])
        self.assert_units('managed', [])
        raw = self.observer.report()['raw_python']['global']['branches']
        self.assertGreater(raw['total'], self.observer.report()['global']['branches']['total'])

    def test_literal_guard_is_not_a_runtime_decision_and_uncalled_test_is_not_removed(self):
        with self.observer:
            self.assertEqual(self.module.constant(), 7)
        self.assert_units('constant', [])
        self.assert_units('never_called', [[]])
        self.assertTrue(gate(self.observer.report()))

    def test_opcode_fallback_has_the_same_hand_enumerated_outcomes(self):
        with patch.object(sys, 'monitoring', None, create=True), self.observer:
            self.assertEqual(self.module.choose(False, True), 'no')
            self.assertEqual(self.module.choose(True, False), 'no')
            self.assertEqual(self.module.choose(True, True), 'yes')
        self.assert_units('choose', [[False, True], [False, True]])

    def test_async_iteration_is_required_and_cannot_silently_disappear(self):
        async def values():
            yield 7
        with self.observer:
            self.assertEqual(asyncio.run(self.module.asynchronous(values())), [7])
        self.assert_units('asynchronous', [[False, True]], ['iteration'])
        self.assertTrue(self.observer.report()['source_mapping_complete'])

    def test_async_empty_iteration_does_not_invent_a_body_observation(self):
        async def empty():
            return
            yield
        with self.observer:
            self.assertEqual(asyncio.run(self.module.asynchronous(empty())), [])
        self.assert_units('asynchronous', [[False]], ['iteration'])

    def test_async_break_does_not_invent_exhaustion(self):
        async def values():
            yield 7
            yield 9
        with self.observer:
            self.assertEqual(asyncio.run(self.module.asynchronous_break(values())), [7])
        self.assert_units('asynchronous_break', [[True]], ['iteration'])

    def test_async_iterator_failure_is_not_exhaustion_even_when_recovered(self):
        async def broken():
            yield 7
            raise LookupError('source fixture failure')
        with self.observer:
            self.assertEqual(asyncio.run(self.module.asynchronous_recover(broken())), 'failed')
        self.assert_units('asynchronous_recover', [[True]], ['iteration'])
        self.assertFalse(self.observer.async_pending)

    def test_async_opcode_fallback_observes_only_actual_completion(self):
        async def values():
            yield 7
        with patch.object(sys, 'monitoring', None, create=True), self.observer:
            self.assertEqual(asyncio.run(self.module.asynchronous(values())), [7])
        self.assert_units('asynchronous', [[False, True]], ['iteration'])

    def test_child_source_observations_use_the_exact_bound_catalog(self):
        code = (
            'import asyncio,importlib.util;'
            's=importlib.util.spec_from_file_location("child_source",' + repr(str(self.path)) + ');'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
            'assert m.choose(False,True)=="no";'
            'asyncio.run(m.asynchronous(Values()))'
        )
        # Define the source iterator outside the measured module. Its values
        # and protocol remain ordinary Python; only the application is observed.
        prefix = ('class Values:\n'
                  ' def __init__(self):self.remaining=1\n'
                  ' def __aiter__(self):return self\n'
                  ' async def __anext__(self):\n'
                  '  if not self.remaining:raise StopAsyncIteration\n'
                  '  self.remaining=0\n'
                  '  return 7\n')
        with tempfile.TemporaryDirectory() as directory:
            campaign = ChildCampaign(self.observer, directory)
            with campaign:
                result = subprocess.run([sys.executable, '-c', prefix + code], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertTrue(campaign.merge()['children'])
        self.assert_units('choose', [[False], []])
        self.assert_units('asynchronous', [[False, True]], ['iteration'])

    def test_raw_python_counters_are_identical_to_the_preserved_observer(self):
        raw = ExecutionCoverage(self.path.parent)
        spec = importlib.util.spec_from_file_location('raw_identity_oracle', self.path)
        module = importlib.util.module_from_spec(spec)
        with raw, self.observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.choose(True, False), 'no')
            self.assertEqual(module.count([True, False]), 1)
            self.assertEqual(module.packed([1, 2]), (1, 2))
        self.assertEqual(self.observer.report()['raw_python'], raw.report())


class DeclarationLineContracts(unittest.TestCase):
    """Source-line adoption never turns an unexecuted implementation into a hit."""

    # Mirror SDK modules: deferred annotations separate the multiline signature
    # from executable annotation evaluation, which must remain in line scope.
    SOURCE = ('from __future__ import annotations\n'
              'from typing import Protocol\n'
              'class Port(Protocol):\n'
              ' def required(\n'
              '  self\n'
              ' ) -> int: ...\n'
              'def actual(value):\n'
              ' return value + 1\n')

    def observe(self, source=None, exercise=True):
        import typing
        sdk_metadata_contract = source is None
        source = (self.SOURCE if source is None else source).encode('utf-8')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'contract.py'
            path.write_bytes(source)
            observer = SourceExecutionCoverage(path.parent)
            # The same importer as checked-in observer fixtures; source is
            # fixed test data in an owned module, never an application input.
            spec = importlib.util.spec_from_file_location('declaration_line_contract', path)
            module = importlib.util.module_from_spec(spec)
            namespace = vars(module)
            with observer:
                spec.loader.exec_module(module)
                if sdk_metadata_contract:
                    self.assertEqual(typing.get_type_hints(namespace['Port'].required), {'return': int})
                if exercise and 'actual' in namespace:
                    self.assertEqual(namespace['actual'](2), 3)
            return observer, observer.report()

    def test_multiline_protocol_contract_keeps_raw_counters_and_requires_a_verified_projection(self):
        observer, report = self.observe()
        self.assertEqual(report['schema_version'], 6)
        self.assertEqual(gate(report), [])
        row, raw = report['modules'][0], report['raw_python']['modules'][0]
        self.assertEqual(row['metrics']['lines']['percent'], 100.0)
        self.assertEqual(report['raw_python']['schema_version'], 4)
        self.assertEqual(report['line_projection_runtime'], list(sys.version_info[:3]))
        self.assertEqual(row['line_projection']['contract'], 'source-implementation-lines-v1')
        self.assertEqual(row['metrics']['statements'], raw['metrics']['statements'])
        self.assertEqual(row['metrics']['functions'], raw['metrics']['functions'])
        if sys.version_info[:2] == (3, 11):
            self.assertEqual(row['line_projection']['declaration_only_lines'], [6])
            self.assertEqual(raw['missing_lines'], [6])
            self.assertLess(raw['metrics']['lines']['percent'], 98)
        else:
            self.assertEqual(row['line_projection']['declaration_only_lines'], [])
        self.assertEqual(report['raw_python'], ExecutionCoverage.report(observer))

    def test_unexecuted_ordinary_empty_function_and_default_method_still_refuse(self):
        for declaration in ('def unfinished():\n pass\n',
                'def unfinished():\n ...\n',
                'class Port(Protocol):\n def unfinished(self):\n  return 7\n',
                'class Port(Protocol):\n def unfinished(self):\n  raise NotImplementedError\n'):
            with self.subTest(source=declaration):
                observer, report = self.observe('from typing import Protocol\n' + declaration, False)
                self.assertTrue(any('functions below 98%' in failure for failure in gate(report)))
                self.assertEqual(report['modules'][0]['line_projection']['declaration_code_entries'], [])
                self.assertEqual(set(report['modules'][0]['line_projection']['implementation_lines']),
                                 next(iter(observer.rows.values()))['line_total'])
                self.assertTrue(report['modules'][0]['missing_functions'])

    def test_eager_annotation_work_is_not_hidden_as_a_declaration_body(self):
        source = self.SOURCE.removeprefix('from __future__ import annotations\n')
        observer, report = self.observe(source)
        self.assertEqual(report['modules'][0]['line_projection']['declaration_only_lines'], [])
        if sys.version_info[:2] == (3, 14):
            self.assertTrue(any('lines below 98%' in failure for failure in gate(report)))

    def test_aliases_decorators_async_docstrings_and_shared_lines_preserve_the_contract(self):
        cases = [
            ('from typing import Protocol as P\nclass Port(P):\n def required(self):\n  ...\n', 'Port.required'),
            ('import typing as t\nclass Port(t.Protocol):\n def required(self):\n  ...\n', 'Port.required'),
            ('from typing import Protocol\nfrom abc import abstractmethod\nclass Port(Protocol):\n @abstractmethod\n def required(self):\n  ...\n', 'Port.required'),
            ('from typing import Protocol\nclass Port(Protocol):\n async def required(self):\n  ...\n', 'Port.required'),
            ('from typing import Protocol\nclass Port(Protocol):\n def required(self):\n  "contract"\n  ...\n', 'Port.required'),
            ('from typing import Protocol\nclass Port(Protocol):\n def required(self, value=7): ...\n', 'Port.required'),
        ]
        for source, name in cases:
            with self.subTest(source=source):
                observer, report = self.observe(source, False)
                self.assertEqual(gate(report), [])
                row = report['modules'][0]
                self.assertEqual(row['metrics']['lines']['percent'], 100.0)
                self.assertEqual([entry['qualname'] for entry in row['line_projection']['declaration_code_entries']], [name])

    def test_shadowed_protocol_alias_never_hides_an_ordinary_method(self):
        source = ('from typing import Protocol\nProtocol = object\n'
                  'class Port(Protocol):\n def unfinished(self):\n  ...\n')
        observer, report = self.observe(source, False)
        self.assertEqual(report['modules'][0]['line_projection']['declaration_code_entries'], [])
        self.assertTrue(any('functions below 98%' in failure for failure in gate(report)))

    def test_redefined_method_retains_the_real_implementation(self):
        source = ('from typing import Protocol\nclass Port(Protocol):\n'
                  ' def same(self):\n  ...\n def same(self):\n  return 7\n')
        observer, report = self.observe(source, False)
        self.assertTrue(any('functions below 98%' in failure for failure in gate(report)))
        self.assertEqual(report['modules'][0]['missing_functions'], [('Port.same', 5)])
        self.assertEqual(len(report['modules'][0]['line_projection']['declaration_code_entries']), 1)

    def test_projection_evidence_is_required_and_cannot_claim_arbitrary_exclusions(self):
        observer, report = self.observe()
        row = report['modules'][0]
        for field, value in (('line_projection', None), ('line_projection', {})):
            tampered = copy.deepcopy(report)
            tampered['modules'][0][field] = value
            self.assertTrue(gate(tampered))
        for field, value in (('implementation_lines', []), ('declaration_only_lines', [1]),
                ('declaration_code_entries', []), ('contract', 'unknown'), ('source_b64', '%%%'),
                ('source_b64', True)):
            with self.subTest(field=field):
                tampered = copy.deepcopy(report)
                tampered['modules'][0]['line_projection'][field] = value
                self.assertTrue(gate(tampered))
        tampered = copy.deepcopy(report)
        tampered['modules'][0]['sha256'] = tampered['raw_python']['modules'][0]['sha256'] = '1' * 64
        self.assertTrue(gate(tampered))

    def test_uncovered_implementation_cannot_be_forged_as_covered_or_removed(self):
        observer, report = self.observe(exercise=False)
        self.assertTrue(gate(report))
        row = report['modules'][0]
        self.assertIn(8, row['missing_lines'])
        for transformation in ('credit', 'remove'):
            tampered = copy.deepcopy(report)
            metric = tampered['modules'][0]['metrics']['lines']
            if transformation == 'credit':
                metric['covered'] = metric['total']
                metric['percent'] = 100.0
                tampered['modules'][0]['missing_lines'] = []
            else:
                tampered['modules'][0]['line_projection']['implementation_lines'].remove(8)
            self.assertTrue(any('line projection' in failure for failure in gate(tampered)))

    def test_observations_aggregates_runtime_and_schema_cannot_be_forged(self):
        observer, report = self.observe()
        for target in ('global', 'component'):
            tampered = copy.deepcopy(report)
            metric = tampered['global'] if target == 'global' else next(iter(tampered['components'].values()))
            metric['lines'] = {'covered': 1, 'total': 1, 'percent': 100.0}
            self.assertTrue(any('source line aggregate mismatch' in failure for failure in gate(tampered)))
            tampered = copy.deepcopy(report)
            raw_metric = tampered['raw_python']['global'] if target == 'global' else next(iter(tampered['raw_python']['components'].values()))
            raw_metric['lines'] = {'covered': 1, 'total': 1, 'percent': 100.0}
            self.assertTrue(any('raw line aggregate mismatch' in failure for failure in gate(tampered)))
        for missing in ([True], [99999], [1, 1], None):
            tampered = copy.deepcopy(report)
            tampered['raw_python']['modules'][0]['missing_lines'] = missing
            self.assertTrue(gate(tampered))
        for runtime in (None, [], [True, 1, 1], [3, 0, 0]):
            tampered = copy.deepcopy(report)
            tampered['line_projection_runtime'] = runtime
            self.assertTrue(gate(tampered))
        tampered = copy.deepcopy(report)
        tampered['schema_version'] = 7
        self.assertTrue(gate(tampered))
        tampered = copy.deepcopy(report)
        tampered['modules'].append(copy.deepcopy(tampered['modules'][0]))
        self.assertTrue(gate(tampered))

    def test_ledger_mutation_cannot_change_the_observers_inventory(self):
        observer, report = self.observe()
        report['modules'][0]['line_projection']['declaration_code_entries'][0]['lines'].clear()
        self.assertEqual(gate(observer.report()), [])


class SourceGateTests(unittest.TestCase):
    @staticmethod
    def report():
        metrics = {name: {'covered': 98, 'total': 100, 'percent': 98.0}
                   for name in ('statements', 'branches', 'functions', 'lines', 'boolean_conditions')}
        raw = {'schema_version': 4, 'global': copy.deepcopy(metrics),
               'components': {'sample': copy.deepcopy(metrics)},
               'modules': [{'module': 'sample/module.py', 'sha256': '0' * 64, 'metrics': copy.deepcopy(metrics)}]}
        report = copy.deepcopy(raw)
        report.update(schema_version=5, source_mapping_complete=True, unmapped_source_decisions=[], raw_python=raw)
        return report

    def test_each_original_gate_remains_independently_blocking(self):
        self.assertEqual(gate(self.report()), [])
        for scope in ('global', 'component', 'module'):
            for metric in self.report()['global']:
                report = self.report()
                metrics = report['global'] if scope == 'global' else (
                    report['components']['sample'] if scope == 'component' else report['modules'][0]['metrics'])
                metrics[metric] = {'covered': 97999, 'total': 100000, 'percent': 98.0}
                with self.subTest(scope=scope, metric=metric):
                    self.assertTrue(any(metric + ' below 98%' in failure for failure in gate(report)))

    def test_missing_invalid_and_unmapped_metrics_are_never_admitted(self):
        for value in (None, False, 'true'):
            report = self.report()
            report['source_mapping_complete'] = value
            self.assertIn('source decision mapping incomplete or absent', gate(report))
        for value in (None, {}, {'covered': True, 'total': 1}, {'covered': 2, 'total': 1}):
            report = self.report()
            report['global']['branches'] = value
            self.assertTrue(gate(report))
        for field in ('components', 'modules'):
            report = self.report()
            report[field] = {} if field == 'components' else []
            self.assertTrue(gate(report))

    def test_raw_counter_evidence_cannot_be_lost_or_changed_by_source_projection(self):
        for value in (None, {}, {'schema_version': 3}):
            report = self.report()
            report['raw_python'] = value
            self.assertTrue(gate(report))
        report = self.report()
        report['raw_python']['global']['branches'] = {'covered': 3, 'total': 2}
        self.assertTrue(gate(report))
        report = self.report()
        report['raw_python']['global']['lines']['covered'] = 99
        self.assertIn('source/raw observation mismatch: lines in global', gate(report))
        for scope in ('component', 'module'):
            report = self.report()
            metrics = report['components']['sample'] if scope == 'component' else report['modules'][0]['metrics']
            metrics['lines']['covered'] = 99
            self.assertTrue(any('source/raw observation mismatch: lines in ' in value for value in gate(report)))
        report = self.report()
        report['raw_python']['modules'][0]['sha256'] = '1' * 64
        self.assertIn('source/raw module identity mismatch', gate(report))
        report = self.report()
        report['unmapped_source_decisions'] = [('unmapped', 1)]
        self.assertIn('source decision mapping incomplete or absent', gate(report))


class UnsupportedSourceTests(unittest.TestCase):
    def test_value_preserved_negated_chain_refuses_without_inventing_a_false_first_comparison(self):
        path = ROOT / 'tests/source_unsupported_cases/decisions.py'
        spec = importlib.util.spec_from_file_location('compound_value_oracle', path)
        module = importlib.util.module_from_spec(spec)
        observer = SourceExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertIs(module.negated_chain_value(0, 2, 1, object()), True)
        report = observer.report()
        units = report['modules'][0]['source_boolean_units']
        self.assertEqual(len(units), 2, 'both elementary source comparisons must remain inventoried')
        self.assertEqual(units[0]['observed'], [True])
        self.assertFalse(report['source_mapping_complete'])
        self.assertIn('source decision mapping incomplete or absent', gate(report))


if __name__ == '__main__':
    unittest.main()
