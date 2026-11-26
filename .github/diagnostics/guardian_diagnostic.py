"""Observe unchanged synthetic guardian tests; never authorize a release."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--review', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--iterations', type=int, default=100)
args = parser.parse_args()
if not 1 <= args.iterations <= 100:
    raise ValueError('Diagnostic campaign must remain bounded')
root = args.root.resolve(strict=True)
output = args.output.resolve()
output.mkdir(exist_ok=False)
review_bytes = args.review.read_bytes()
if hashlib.sha256(review_bytes).hexdigest() != '3cdf2a28b5e7a4af0a873771df8eaa1808ed24f472eec4d15846270d3d3ec944':
    raise ValueError('Expected the actually approved C159 review')
gate = root / 'scripts/sast_gate.py'
if hashlib.sha256(gate.read_bytes()).hexdigest() != 'e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803':
    raise ValueError('Untrusted source snapshot verifier')
api = runpy.run_path(str(gate))
review = json.loads(review_bytes)
before = api['SourceSnapshot'].capture(root)
if before != review['source_files'] or not all(record['approved'] for record in review['records']):
    raise ValueError('The complete approved source identity differs')
sys.path[:0] = [str(root / 'scripts'), str(root / 'src'), str(root / 'tests')]
os.environ['PYTHONPATH'] = str(root / 'src')
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
from coverage_source import SourceExecutionCoverage
from coverage_processes import ChildCampaign

# Only the synthetic fixture's outer error translation is bypassed. The exact
# approved main/cleanup code, descriptor inheritance and test assertions run.
# No endpoint, command or credential from an operator is accepted by this driver.
diagnostic_entry = '''import sys,traceback,os,time,json
from swassh.infrastructure import process_guard
try:
    result=process_guard.main(sys.argv[1])
except BaseException as error:
    print("SWASSH_SYNTHETIC_GUARD_EXCEPTION",type(error).__name__,getattr(error,"errno",None),file=sys.stderr,flush=True)
    traceback.print_exc()
    if isinstance(error, PermissionError):
        frame=error.__traceback__
        while frame is not None and frame.tb_frame.f_code.co_name!="_stop_native":
            frame=frame.tb_next
        if frame is not None:
            pid=frame.tb_frame.f_locals["process"].pid
            signum=int(frame.tb_frame.f_locals["sig"])
            began=time.monotonic()
            observations=[]
            for _ in range(32):
                try:
                    os.killpg(pid,0)
                    state="present-and-signalable"
                except ProcessLookupError:
                    state="absent"
                except PermissionError:
                    state="permission-denied"
                elapsed=time.monotonic()-began
                observations.append({"seconds":elapsed,"state":state})
                if state=="absent" or elapsed>=0.35:
                    break
                time.sleep(min(0.025,0.35-elapsed))
            print("SWASSH_SYNTHETIC_GROUP_OBSERVATIONS",json.dumps({"signal":signum,"observations":observations}),file=sys.stderr,flush=True)
    raise SystemExit(125)
raise SystemExit(result)
'''
original = asyncio.create_subprocess_exec


async def observe_spawn(*argv, **kwargs):
    if len(argv) == 4 and argv[1:3] == ('-m', 'swassh.infrastructure.process_guard'):
        argv = (argv[0], '-c', diagnostic_entry, argv[3])
    return await original(*argv, **kwargs)


observer = SourceExecutionCoverage(root / 'src/swassh')
campaign = ChildCampaign(observer, output)
with campaign, observer, patch.object(asyncio, 'create_subprocess_exec', observe_spawn):
    from test_improvements import GuardTests
    suite = unittest.TestSuite(GuardTests('test_exited_leader_child_holding_pipe_is_removed')
                              for _ in range(args.iterations))
    with (output / 'tests.log').open('x', encoding='utf-8') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
children = campaign.merge()
after = api['SourceSnapshot'].capture(root)
if after != before:
    raise ValueError('Source bytes changed during diagnosis')
receipt = {'diagnostic_only': True, 'publication_authorized': False,
           'python': sys.version, 'iterations': args.iterations, 'tests_run': result.testsRun,
           'failures': [{'test': test.id(), 'traceback': trace} for test, trace in result.failures],
           'errors': [{'test': test.id(), 'traceback': trace} for test, trace in result.errors],
           'skipped': result.skipped, 'source_unchanged': True, 'source_files': before,
           'candidate_archive_sha256': '89eb05a3210b072d24b426e79dbe66fe3d9d830c9adb05c087ef7dd0059154ef',
           'approved_review_sha256': hashlib.sha256(review_bytes).hexdigest(),
           'child_campaign': children, 'all_original_assertions_succeeded': result.wasSuccessful()}
(output / 'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8')
print(json.dumps({key: value for key, value in receipt.items() if key not in ('failures', 'errors', 'child_campaign')}))
raise SystemExit(0 if result.wasSuccessful() and result.testsRun == args.iterations and not result.skipped else 1)
