"""Five source coverage gates, with independently retained raw Python evidence."""

import json
import sys
import os
import unittest
import tempfile
from pathlib import Path

from coverage_source import SourceExecutionCoverage as ExecutionCoverage, gate
from coverage_diagnostics import RuntimeDiagnostics
from coverage_processes import ChildCampaign

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def execute_suite():
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    tests = [test for test in flatten(suite) if "test_50000_fleet" not in test.id()]
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(tests))
    if not result.wasSuccessful():
        raise ValueError("coverage test suite failed")


def main():
    output = ROOT / "validation"
    output.mkdir(exist_ok=True)
    observer = ExecutionCoverage(ROOT / 'src/swassh')
    campaign=ChildCampaign(observer,output)
    failure = None
    descriptor,temporary=tempfile.mkstemp(prefix='.asyncio-diagnostics-',dir=output)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as journal, RuntimeDiagnostics(journal) as diagnostics:
            with campaign, observer:
                execute_suite()
    except BaseException as error:
        failure = error
    finally:
        os.replace(temporary,output/'runtime-diagnostics.jsonl')
    try:
        children=campaign.merge()
    except BaseException as error:
        failure=error
        children={'error':str(error)}
    report = observer.report()
    report['child_processes']=children
    report['definitions']['processes']='parent/threads and strictly verified inherited-environment CPython child journals; no inferred child observations'
    report['runtime_diagnostics']={'file':'runtime-diagnostics.jsonl',
        'records':diagnostics.records,'bytes':diagnostics.bytes}
    report['tests_succeeded'] = failure is None
    report['threshold_percent'] = 98
    report['gate_failures'] = gate(report)
    (output / "coverage.json").write_text(json.dumps(report, indent=2) + "\n")
    for metric, values in report['global'].items():
        print(f"{metric}: {values['percent']}% ({values['covered']}/{values['total']})")
    if failure is not None:
        raise failure
    if report['gate_failures']:
        raise ValueError('coverage gate refused: ' + '; '.join(report['gate_failures']))


if __name__ == "__main__":
    main()
