"""Validate the coverage observer and the strict five-metric admission gate."""
import copy
import dis
import json
import importlib.util
import os
from pathlib import Path
import runpy
import sys
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOLS = runpy.run_path(str(ROOT / 'scripts/coverage_metrics.py'))
ExecutionCoverage = TOOLS['ExecutionCoverage']
gate = TOOLS['gate']
METRICS = TOOLS['METRICS']
ChildCampaign=runpy.run_path(str(ROOT/'scripts/coverage_processes.py'))['ChildCampaign']


class CoverageObserverTests(unittest.TestCase):
    """The fixture contains known decisions, independent from reported counts."""

    @staticmethod
    def fixture():
        path = ROOT / 'tests/coverage_cases/choice.py'
        spec = importlib.util.spec_from_file_location('coverage_choice_oracle', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def load_definition_fixture(self,relative,exercise):
        path=ROOT/'tests'/relative
        spec=importlib.util.spec_from_file_location('coverage_definition_oracle',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            exercise(module)
        return observer.report()

    def test_class_body_does_not_invent_a_function(self):
        report=self.load_definition_fixture('coverage_class_cases/declaration.py',
            lambda module:self.assertEqual(module.Marker.__name__,'Marker'))
        self.assertEqual(report['global']['functions'],{'covered':0,'total':0,'percent':None})
        self.assertEqual(report['global']['statements']['percent'],100.0)
        self.assertEqual(report['legacy_nested_code_entries']['global']['total'],1)

    def test_compiler_builtin_identity_is_not_a_user_boolean_outcome(self):
        path=ROOT/'tests/coverage_compiler_cases/dispatch.py'
        spec=importlib.util.spec_from_file_location('coverage_compiler_oracle',path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        class FalseOnly:
            calls=0
            def __bool__(self):self.calls+=1;return False
        value=FalseOnly()
        observer=ExecutionCoverage(path.parent)
        with observer:
            self.assertEqual(module.pack([]),())
            self.assertEqual(module.pack([1,2]),(1,2))
            self.assertFalse(module.choose([value]))
        self.assertEqual(value.calls,1,'measurement must never evaluate application truth twice')
        # Python 3.14 inlines any/tuple with a built-in identity dispatch. The
        # independent value observed above has never returned True. Older
        # runtimes execute any's C loop, outside this Python-code observer.
        inlined=any(item.opname=='LOAD_COMMON_CONSTANT' for item in dis.get_instructions(module.choose))
        expected={'covered':1,'total':2,'percent':50.0} if inlined else {'covered':0,'total':0,'percent':None}
        report=observer.report()
        self.assertEqual(report['global']['boolean_conditions'],expected)
        self.assertTrue(gate(report),'untested code/branch outcomes must still fail admission')
        if inlined:
            self.assertEqual(report['legacy_all_bytecode_boolean_conditions']['global'],
                             {'covered':3,'total':4,'percent':75.0})
            self.assertTrue(any('branches below' in failure for failure in gate(report)),
                            'compiler bytecode branches still participate in the unchanged strict branch gate')

    def test_explicit_source_identity_is_not_removed_as_compiler_dispatch(self):
        def exercise(module):
            self.assertTrue(module.identity(tuple));self.assertFalse(module.identity(None))
        report=self.load_definition_fixture('coverage_source_identity_cases/identity.py',exercise)
        self.assertEqual(report['global']['boolean_conditions'],{'covered':2,'total':2,'percent':100.0})
        self.assertEqual(report['global']['branches'],{'covered':2,'total':2,'percent':100.0})

    def test_child_compiler_dispatch_cannot_credit_unobserved_application_truth(self):
        path=ROOT/'tests/coverage_compiler_cases/dispatch.py'
        observer=ExecutionCoverage(path.parent)
        with tempfile.TemporaryDirectory() as directory:
            campaign=ChildCampaign(observer,directory)
            code=('import importlib.util;'
                  's=importlib.util.spec_from_file_location("child_oracle",'+repr(str(path))+');'
                  'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                  'assert m.pack([])==();assert m.pack([1,2])==(1,2);assert m.choose([False]) is False')
            with campaign:
                result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            receipt=campaign.merge();self.assertTrue(receipt['children'])
        source=compile(path.read_bytes(),str(path),'exec')
        choose=next(value for value in source.co_consts if getattr(value,'co_name',None)=='choose')
        inlined=any(item.opname=='LOAD_COMMON_CONSTANT' for item in dis.get_instructions(choose))
        self.assertEqual(observer.report()['global']['boolean_conditions'],
                         {'covered':1,'total':2,'percent':50.0} if inlined else {'covered':0,'total':0,'percent':None})

    def test_protocol_signatures_are_declarations_and_default_bodies_are_implementations(self):
        def exercise(module):
            value=module.Concrete()
            self.assertEqual(value.required(),9)
            self.assertEqual(value.provided(),7)
        report=self.load_definition_fixture('coverage_definition_cases/definitions.py',exercise)
        self.assertEqual(report['global']['functions'],{'covered':2,'total':2,'percent':100.0})
        self.assertEqual(report['global']['statements']['percent'],100.0)
        self.assertEqual(len(report['modules'][0]['declarations']),1)
        self.assertTrue(report['modules'][0]['declarations'][0]['qualname'].endswith('Contract.required'))

    def test_empty_application_function_is_still_required_and_same_line_lambdas_are_distinct(self):
        report=self.load_definition_fixture('coverage_empty_function_cases/unfinished.py',lambda module:None)
        self.assertEqual(report['global']['functions']['total'],1)
        self.assertEqual(report['global']['functions']['covered'],0)
        self.assertTrue(gate(report))
        report=self.load_definition_fixture('coverage_lambda_cases/lambdas.py',lambda module:self.assertEqual(module.first(),1))
        self.assertEqual(report['global']['functions'],{'covered':1,'total':2,'percent':50.0})

    def test_constant_identity_matches_child_catalog_and_preserves_literal_types(self):
        child=runpy.run_path(str(ROOT/'scripts/coverage_child.py'))
        path=ROOT/'tests/coverage_lambda_cases/lambdas.py'
        code=compile(path.read_bytes(),str(path),'exec',dont_inherit=True)
        signatures=[TOOLS['constant_signature'](value) for value in code.co_consts if hasattr(value,'co_code')]
        self.assertEqual(len(set(signatures)),2)
        self.assertEqual(TOOLS['constant_signature'](code),child['constant_signature'](code))
        other=compile(path.read_bytes(),str(path),'exec',dont_inherit=True)
        self.assertEqual(TOOLS['_CodeIdentity'](code),TOOLS['_CodeIdentity'](other))

    def test_same_line_statements_remain_independent_after_an_exception(self):
        path=ROOT/'tests/coverage_statement_cases/statements.py'
        spec=importlib.util.spec_from_file_location('coverage_statement_oracle',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        def fail(): raise ValueError('synthetic stop')
        with observer:
            spec.loader.exec_module(module)
            with self.assertRaisesRegex(ValueError,'synthetic stop'):
                module.interrupted(fail)
        row=observer.report()['modules'][0]
        missing=row['missing_statements']
        self.assertTrue(any(item[0]==5 and item[1]>20 for item in missing),missing)
        self.assertFalse(any(item[0]==5 and item[1]==4 for item in missing),missing)
        self.assertNotEqual(row['metrics']['statements'],row['metrics']['lines'])
        with observer:
            self.assertEqual(module.interrupted(lambda:None),3)
        self.assertFalse(any(item[0]==5 for item in observer.report()['modules'][0]['missing_statements']))

    def test_executing_a_body_does_not_infer_an_unobserved_definition(self):
        path=ROOT/'tests/coverage_statement_cases/statements.py'
        spec=importlib.util.spec_from_file_location('coverage_statement_scope',path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        observer=ExecutionCoverage(path.parent)
        with observer:
            inner=module.nested()
            self.assertEqual(inner(),9)
        row=observer.report()['modules'][0]
        self.assertTrue(any(item[0]==9 and item[4]=='FunctionDef' for item in row['missing_statements']))
        self.assertFalse(any(item[0]==10 and item[4]=='FunctionDef' for item in row['missing_statements']))

    def test_statement_counts_use_instruction_events_with_opcode_fallback(self):
        path=ROOT/'tests/coverage_statement_cases/statements.py'
        reports=[]
        for fallback in (False,True):
            spec=importlib.util.spec_from_file_location('coverage_statement_fallback',path)
            module=importlib.util.module_from_spec(spec)
            observer=ExecutionCoverage(path.parent)
            with patch.object(sys,'monitoring',None if fallback else getattr(sys,'monitoring',None),create=True):
                with observer:
                    spec.loader.exec_module(module)
                    self.assertEqual(module.interrupted(lambda:None),3)
                    self.assertEqual(module.nested()(),9)
            reports.append(observer.report()['global'])
        self.assertEqual(reports[0],reports[1])
        self.assertEqual(reports[0]['statements']['covered'],reports[0]['statements']['total'])

    def test_short_circuit_does_not_infer_an_unobserved_true_outcome(self):
        observer = ExecutionCoverage(ROOT / 'tests/coverage_cases')
        previous = sys.gettrace()
        with observer:
            module = self.fixture()
            self.assertEqual(module.choice(True, False), 1)
            self.assertEqual(module.choice(False, False), 0)
        self.assertIs(sys.gettrace(), previous)
        row = observer.report()['modules'][0]
        self.assertEqual(row['metrics']['boolean_conditions'],
                         {'covered': 3, 'total': 4, 'percent': 75.0})
        self.assertEqual(row['metrics']['functions']['covered'], 1)
        self.assertEqual(row['metrics']['functions']['total'], 1)
        self.assertIn(100.0, [row['metrics']['lines']['percent']])

    def test_all_elementary_outcomes_are_observed_without_extra_truth_calls(self):
        class Truth:
            def __init__(self, value):
                self.value, self.calls = value, 0

            def __bool__(self):
                self.calls += 1
                return self.value

        observer = ExecutionCoverage(ROOT / 'tests/coverage_cases')
        with observer:
            module = self.fixture()
            first, second = Truth(True), Truth(False)
            self.assertEqual(module.choice(first, second), 1)
            self.assertEqual((first.calls, second.calls), (1, 0))
            self.assertEqual(module.choice(False, False), 0)
            self.assertEqual(module.choice(False, True), 1)
        metrics = observer.report()['global']
        self.assertEqual(metrics['boolean_conditions']['covered'], 4)
        self.assertEqual(metrics['boolean_conditions']['total'], 4)
        self.assertEqual(metrics['branches']['covered'], 4)
        self.assertEqual(metrics['branches']['total'], 4)

    def test_unloaded_source_is_not_omitted_from_denominators(self):
        observer = ExecutionCoverage(ROOT / 'tests/coverage_cases')
        report = observer.report()
        self.assertEqual(report['global']['functions']['covered'], 0)
        self.assertEqual(report['global']['functions']['total'], 1)
        self.assertEqual(report['global']['boolean_conditions']['covered'], 0)
        self.assertEqual(report['global']['boolean_conditions']['total'], 4)
        self.assertTrue(report['modules'][0]['sha256'])

    def test_iteration_branches_and_boolean_conditions_are_distinct_metrics(self):
        path = ROOT / 'tests/coverage_iteration_cases/iteration.py'
        spec = importlib.util.spec_from_file_location('coverage_iteration_oracle', path)
        module = importlib.util.module_from_spec(spec)
        observer = ExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.count_true([True, False]), 1)
            self.assertEqual(module.count_true([]), 0)
        metrics = observer.report()['global']
        self.assertEqual(metrics['boolean_conditions']['total'], 2)
        self.assertEqual(metrics['boolean_conditions']['covered'], 2)
        self.assertEqual(metrics['branches']['total'], 4)
        self.assertEqual(metrics['branches']['covered'], 4)

    def test_truth_conversion_failure_has_no_inferred_outcome(self):
        class BrokenTruth:
            def __bool__(self):
                raise ValueError('synthetic truth failure')

        observer = ExecutionCoverage(ROOT / 'tests/coverage_cases')
        with observer:
            module = self.fixture()
            with self.assertRaisesRegex(ValueError, 'synthetic truth failure'):
                module.choice(BrokenTruth(), False)
        self.assertEqual(observer.report()['global']['boolean_conditions']['covered'], 0)

    def test_chained_comparisons_do_not_merge_two_elementary_conditions(self):
        path=ROOT/'tests/coverage_chained_cases/choice.py'
        spec=importlib.util.spec_from_file_location('coverage_chained_oracle',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.between(0,1,0),0)
            self.assertEqual(module.between(1,0,1),0)
        self.assertEqual(observer.report()['global']['boolean_conditions'],
                         {'covered':3,'total':4,'percent':75.0})
        with observer:
            self.assertEqual(module.between(0,1,2),1)
        self.assertEqual(observer.report()['global']['boolean_conditions']['covered'],4)

    def test_duplicated_loop_comparisons_keep_one_identity_per_source_element(self):
        path=ROOT/'tests/coverage_chained_loop_cases/iteration.py'
        spec=importlib.util.spec_from_file_location('coverage_chained_loop_oracle',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.advance(1,2),1)
            self.assertEqual(module.advance(0,2),0)
        self.assertEqual(observer.report()['global']['boolean_conditions'],
                         {'covered':4,'total':4,'percent':100.0})

    def test_opcode_fallback_observes_short_circuit_and_restores_trace_hooks(self):
        path=ROOT/'tests/coverage_chained_cases/choice.py'
        spec=importlib.util.spec_from_file_location('coverage_fallback_oracle',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        previous=sys.gettrace()
        with patch.object(sys,'monitoring',None,create=True):
            with observer:
                spec.loader.exec_module(module)
                self.assertEqual(module.between(0,1,0),0)
                self.assertEqual(module.between(1,0,1),0)
        self.assertIs(sys.gettrace(),previous)
        self.assertEqual(observer.report()['global']['boolean_conditions'],
                         {'covered':3,'total':4,'percent':75.0})

    def test_opcode_fallback_observes_iteration_exhaustion(self):
        path=ROOT/'tests/coverage_iteration_cases/iteration.py'
        spec=importlib.util.spec_from_file_location('coverage_fallback_iteration',path)
        module=importlib.util.module_from_spec(spec)
        observer=ExecutionCoverage(path.parent)
        with patch.object(sys,'monitoring',None,create=True):
            with observer:
                spec.loader.exec_module(module)
                self.assertEqual(module.count_true([True,False]),1)
                self.assertEqual(module.count_true([]),0)
        self.assertEqual(observer.report()['global']['branches'],
                         {'covered':4,'total':4,'percent':100.0})

    def test_exception_restores_instrumentation_ownership(self):
        previous = sys.gettrace()
        before = ([sys.monitoring.get_tool(number) for number in range(6)]
                  if hasattr(sys, 'monitoring') else None)
        with self.assertRaisesRegex(ValueError, 'application failure'):
            with ExecutionCoverage(ROOT / 'tests/coverage_cases'):
                raise ValueError('application failure')
        self.assertIs(sys.gettrace(), previous)
        if before is not None:
            self.assertEqual([sys.monitoring.get_tool(number) for number in range(6)], before)

    def test_catalog_preserves_source_compile_flags_and_class_body_lines(self):
        path = ROOT / 'tests/coverage_annotation_cases/annotations.py'
        spec = importlib.util.spec_from_file_location('coverage_annotation_oracle', path)
        module = importlib.util.module_from_spec(spec)
        observer = ExecutionCoverage(path.parent)
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.SourceRecord().size(), 6)
            self.assertIs(module.SourceRecord.__annotations__['label'], str)
        # A class declaration/field is executed during import, even though the
        # observer itself uses postponed annotations in its own source module.
        self.assertNotIn(5, observer.report()['modules'][0]['missing_lines'])


class ChildCoverageIntegrationTests(unittest.TestCase):
    """Real child exit and hostile receipts cannot manufacture observations."""

    def test_death_before_header_publication_cannot_publish_a_corrupt_observation_journal(self):
        observer=ExecutionCoverage(ROOT/'tests/coverage_cases')
        for phase in ('write','publish'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as directory:
                campaign=ChildCampaign(observer,directory)
                # -S deliberately avoids automatic site startup: this test
                # enters the measurement bootstrap itself and exits before
                # any fixture/application code can begin.
                code=('import os,sys;sys.path.insert(0,sys.argv[1]);from coverage_child import ChildObserver;'
                      'phase=sys.argv[3];'
                      'os.write=(lambda *args:os._exit(43)) if phase=="write" else os.write;'
                      'os.replace=(lambda *args:os._exit(44)) if phase=="publish" else os.replace;'
                      'ChildObserver(sys.argv[2])')
                child=subprocess.run([sys.executable,'-S','-c',code,str(campaign.directory),str(campaign.descriptor),phase],capture_output=True,timeout=10)
                self.assertEqual(child.returncode,43 if phase=='write' else 44,child.stderr.decode())
                before=observer.report()['global']
                receipt=campaign.merge()
                self.assertEqual(receipt['children'],[])
                self.assertEqual(len(receipt['unpublished_bootstraps']),1)
                self.assertEqual(observer.report()['global'],before)

    def test_same_line_constant_lambdas_remain_distinct_in_a_child(self):
        path=(ROOT/'tests/coverage_lambda_cases/lambdas.py').resolve()
        observer=ExecutionCoverage(path.parent)
        with tempfile.TemporaryDirectory() as directory:
            campaign=ChildCampaign(observer,directory)
            code='import runpy,sys;scope=runpy.run_path(sys.argv[1]);assert scope["second"]()==2'
            with campaign:
                child=subprocess.run([sys.executable,'-c',code,str(path)],capture_output=True,timeout=10)
            self.assertEqual(child.returncode,0,child.stderr.decode())
            campaign.merge()
        self.assertEqual(observer.report()['global']['functions'],{'covered':1,'total':2,'percent':50.0})

    def test_abrupt_child_exit_retains_only_observed_short_circuit_outcomes(self):
        path=(ROOT/'tests/coverage_cases/choice.py').resolve()
        observer=ExecutionCoverage(path.parent)
        with tempfile.TemporaryDirectory() as directory:
            campaign=ChildCampaign(observer,directory)
            code='import os,sys;path=sys.argv[1];scope={};exec(compile(open(path,"rb").read(),path,"exec"),scope);assert scope["choice"](False,False)==0;os._exit(31)'
            with campaign:
                child=subprocess.run([sys.executable,'-c',code,str(path)],capture_output=True,timeout=10)
            self.assertEqual(child.returncode,31,child.stderr.decode())
            self.assertEqual(observer.report()['global']['boolean_conditions']['covered'],0)
            receipt=campaign.merge()
            self.assertEqual(len(receipt['children']),1)
            self.assertEqual(observer.report()['global']['boolean_conditions']['covered'],2)
            self.assertEqual(observer.report()['global']['boolean_conditions']['total'],4)
            before=observer.report()['global']
            campaign.merge()
            self.assertEqual(observer.report()['global'],before)

    def test_corrupt_foreign_and_truncated_child_journals_are_rejected_atomically(self):
        observer=ExecutionCoverage(ROOT/'tests/coverage_cases')
        with tempfile.TemporaryDirectory() as directory:
            campaign=ChildCampaign(observer,directory)
            path=campaign.directory/'synthetic.events'
            header={'schema_version':1,'catalog':campaign.token,'pid':os.getpid()}
            before=observer.report()['global']
            for raw in (b'',b'broken\n',json.dumps({**header,'catalog':'foreign'}).encode()+b'\n',
                        json.dumps(header).encode()+b'\n'+b'x',
                        json.dumps(header).encode()+b'\n'+struct.pack('!I',len(campaign.units))):
                with self.subTest(raw=raw[:32]):
                    path.write_bytes(raw)
                    with self.assertRaises((ValueError,KeyError,TypeError)):
                        campaign.merge()
                    self.assertEqual(observer.report()['global'],before)

    def test_source_change_makes_bootstrap_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'source';root.mkdir()
            path=root/'module.py';path.write_text('answer=41\n')
            observer=ExecutionCoverage(root)
            campaign=ChildCampaign(observer,directory)
            path.write_text('answer=42\n')
            code='import sys;path=sys.argv[1];exec(compile(open(path,"rb").read(),path,"exec"),{})'
            with campaign:
                child=subprocess.run([sys.executable,'-c',code,str(path)],capture_output=True,timeout=10)
            self.assertNotEqual(child.returncode,0)
            self.assertIn(b'child coverage source changed',child.stderr)
            self.assertEqual(observer.report()['global']['statements']['covered'],0)


class CoverageGateTests(unittest.TestCase):
    @staticmethod
    def report(covered=98, total=100):
        metrics = {name: {'covered': covered, 'total': total,
                         'percent': 100 * covered / total if total else None}
                   for name in METRICS}
        return {'global': copy.deepcopy(metrics),
                'components': {'domain': copy.deepcopy(metrics)},
                'modules': [{'module': 'domain/operation.py', 'metrics': copy.deepcopy(metrics)}]}

    def test_each_metric_is_independently_blocking_before_rounding(self):
        self.assertEqual(gate(self.report()), [])
        for name in METRICS:
            report = self.report()
            report['global'][name] = {'covered': 97999, 'total': 100000, 'percent': 98.0}
            with self.subTest(metric=name):
                self.assertIn('global: ' + name + ' below 98%', gate(report))

    def test_weak_component_or_file_cannot_hide_behind_global_coverage(self):
        for field in ('components', 'modules'):
            report = self.report(100)
            metrics = (report['components']['domain'] if field == 'components'
                       else report['modules'][0]['metrics'])
            metrics['branches']['covered'] = 97
            self.assertTrue(gate(report))

    def test_missing_boolean_metric_and_malformed_counters_are_rejected(self):
        report = self.report()
        del report['global']['boolean_conditions']
        self.assertIn('global: missing boolean_conditions', gate(report))
        for value in (True, '100', -1, 101):
            report = self.report()
            report['global']['lines']['covered'] = value
            self.assertIn('global: invalid lines', gate(report))
        self.assertTrue(gate({}))

    def test_zero_denominator_is_explicit_and_threshold_cannot_be_weakened(self):
        self.assertEqual(gate(self.report(0, 0)), [])
        for threshold in (97, True, 98.0, 101):
            with self.assertRaises(ValueError):
                gate(self.report(), threshold)
