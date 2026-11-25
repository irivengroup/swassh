"""Return-before-finally statements must be observed at actual instructions."""
import importlib.util
import ast
from pathlib import Path
import runpy
import sys
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
ExecutionCoverage=runpy.run_path(str(ROOT/'scripts/coverage_metrics.py'))['ExecutionCoverage']
SourceExecutionCoverage=runpy.run_path(str(ROOT/'scripts/coverage_source.py'))['SourceExecutionCoverage']
ChildCampaign=runpy.run_path(str(ROOT/'scripts/coverage_processes.py'))['ChildCampaign']


class NopInstructionTests(unittest.TestCase):
    def observe(self,function,*args):
        path=ROOT/'tests/statement_cases/decisions.py'
        observer=ExecutionCoverage(path.parent)
        spec=importlib.util.spec_from_file_location('nop_instruction_oracle',path)
        module=importlib.util.module_from_spec(spec);events=[]
        with observer:
            spec.loader.exec_module(module)
            result=getattr(module,function)(*args,events)
        return result,events,observer.report()['modules'][0]

    def test_executed_return_has_an_instruction_hit_without_crediting_alternatives(self):
        path=ROOT/'tests/statement_cases/decisions.py'
        observer=ExecutionCoverage(path.parent)
        spec=importlib.util.spec_from_file_location('nop_instruction_oracle',path)
        module=importlib.util.module_from_spec(spec);events=[]
        with observer:
            spec.loader.exec_module(module)
            self.assertEqual(module.finish('first',events),11)
        self.assertEqual(events,['cleaned'])
        row=observer.report()['modules'][0]
        missing={item[0] for item in row['missing_statements'] if item[-1]=='Return'}
        self.assertNotIn(7,missing)
        self.assertEqual(missing,{9,10,17,18,26})

    def test_second_return_does_not_credit_the_first_or_the_default(self):
        value,events,row=self.observe('finish','second')
        self.assertEqual((value,events),(22,['cleaned']))
        self.assertEqual({item[0] for item in row['missing_statements'] if item[-1]=='Return'},
                         {7,10,17,18,26})

    def test_default_return_requires_both_earlier_guards_to_be_false(self):
        value,events,row=self.observe('finish','other')
        self.assertEqual((value,events),(33,['cleaned']))
        self.assertEqual({item[0] for item in row['missing_statements'] if item[-1]=='Return'},
                         {7,9,17,18,26})

    def test_same_line_guard_does_not_infer_the_skipped_return(self):
        for choice,expected,missing_return in ((False,55,17),(True,44,18)):
            with self.subTest(choice=choice):
                value,events,row=self.observe('same_line',choice)
                self.assertEqual((value,events),(expected,['cleaned']))
                self.assertEqual({item[0] for item in row['missing_statements'] if item[-1]=='Return'},
                                 {7,9,10,26,missing_return})

    def test_exception_does_not_credit_the_unreachable_return_after_raise(self):
        path=ROOT/'tests/statement_cases/decisions.py';observer=ExecutionCoverage(path.parent)
        spec=importlib.util.spec_from_file_location('nop_exception_oracle',path)
        module=importlib.util.module_from_spec(spec);events=[]
        with observer:
            spec.loader.exec_module(module)
            with self.assertRaisesRegex(ValueError,'^stopped$'):module.stopped_before_return(events)
        self.assertEqual(events,['cleaned'])
        self.assertEqual({item[0] for item in observer.report()['modules'][0]['missing_statements'] if item[-1]=='Return'},
                         {7,9,10,17,18,26})

    def test_observer_reentry_captures_a_new_return_on_the_same_code_object(self):
        path=ROOT/'tests/statement_cases/decisions.py';observer=ExecutionCoverage(path.parent)
        spec=importlib.util.spec_from_file_location('nop_reentry_oracle',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for choice,expected in (('first',11),('second',22),('other',33)):
            with observer:self.assertEqual(module.finish(choice,[]),expected)
        self.assertEqual({item[0] for item in observer.report()['modules'][0]['missing_statements'] if item[-1]=='Return'},
                         {17,18,26})

    def test_denominators_and_raw_source_statement_parity_are_preserved(self):
        path=ROOT/'tests/statement_cases/decisions.py';source=SourceExecutionCoverage(path.parent)
        baseline=source.report();totals={name:value['total'] for name,value in baseline['raw_python']['global'].items()}
        tree=ast.parse(path.read_bytes())
        # This corpus has no Protocol declarations or function docstrings.
        self.assertEqual(totals['statements'],sum(isinstance(node,ast.stmt) for node in ast.walk(tree)))
        spec=importlib.util.spec_from_file_location('nop_source_parity',path)
        module=importlib.util.module_from_spec(spec)
        with source:
            spec.loader.exec_module(module);self.assertEqual(module.finish('first',[]),11)
        after=source.report()
        self.assertEqual({name:value['total'] for name,value in after['raw_python']['global'].items()},totals)
        self.assertEqual(after['global']['statements'],after['raw_python']['global']['statements'])
        self.assertFalse(any(item[0]==7 and item[-1]=='Return' for item in after['modules'][0]['missing_statements']))

    def test_child_eager_journal_records_only_the_executed_return_before_abrupt_exit(self):
        path=ROOT/'tests/statement_cases/decisions.py'
        code=('import importlib.util,os,sys;'
              's=importlib.util.spec_from_file_location("nop_child_oracle",sys.argv[1]);'
              'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
              'events=[];assert m.finish("first",events)==11 and events==["cleaned"];print(os.getpid(),flush=True);os._exit(17)')
        for factory in (ExecutionCoverage,SourceExecutionCoverage):
            with self.subTest(factory=factory.__name__),tempfile.TemporaryDirectory() as directory:
                observer=factory(path.parent);campaign=ChildCampaign(observer,directory)
                with campaign:
                    child=subprocess.run([sys.executable,'-c',code,str(path)],capture_output=True,timeout=20)
                self.assertEqual(child.returncode,17,child.stderr.decode('utf-8','replace'))
                processes=campaign.merge();self.assertEqual(len(processes['children']),1)
                self.assertEqual(processes['children'][0]['pid'],int(child.stdout))
                row=observer.report()['modules'][0]
                self.assertEqual({item[0] for item in row['missing_statements'] if item[-1]=='Return'},
                                 {9,10,17,18,26})


if __name__=='__main__':unittest.main()
