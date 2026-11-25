"""Repeat real CLI scheduling with concurrent manual invocations, without SSH network."""
import argparse
from collections import Counter
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROBE = runpy.run_path(str(ROOT/'scripts/validate_installation.py'))
ProbeWorkspace, wait_until_due = PROBE['ProbeWorkspace'], PROBE['wait_until_due']


class ScheduleCampaign:
    """Check durable outcomes, reports and exact call counts across worker restarts."""
    def __init__(self, iterations):
        if type(iterations) is not int or not 1 <= iterations <= 200:
            raise ValueError('iterations must be between 1 and 200')
        self.iterations = iterations

    def run(self):
        if os.name != 'posix':
            raise RuntimeError('this native executable fixture requires POSIX')
        with ProbeWorkspace() as workspace:
            root = workspace.path
            fixture = root/'ssh-fixture'
            fixture.write_text('#!'+sys.executable+'\n'+(ROOT/'tests/fake_ssh.py').read_text())
            fixture.chmod(0o700)
            # The CLI runs from a disposable directory. Bind its imports to
            # this checkout even if the caller supplied a relative PYTHONPATH.
            env = dict(os.environ, HOME=str(root), SWASSH_TEST_CALLS=str(root/'calls'),
                       PYTHONPATH=str(ROOT/'src'))
            common = ['--ssh-executable', str(fixture), '--budget-dir', str(root/'budget'),
                      '--bastion-concurrency', '2', '--bastion-connect-rate', '1000']
            state = ['--state-dir', str(root/'state')]

            def cli(*arguments, expected=0, environment=env):
                result = subprocess.run([sys.executable, '-m', 'swassh', *arguments], cwd=root,
                    env=environment, text=True, capture_output=True, timeout=45)
                workspace.checks.append({'arguments': arguments, 'exit_code': result.returncode,
                                         'stdout': result.stdout, 'stderr': result.stderr})
                if result.returncode != expected:
                    raise RuntimeError('schedule campaign CLI failed; retained evidence contains the cause')
                return result.stdout

            jobs, expected_calls = [], Counter()
            for index in range(self.iterations):
                command = 'failed' if index % 10 == 0 else f'ok-{index}'
                # Nominal jobs span the existing 900-second campaign allowance.
                # Production defaults and explicit expiry tests remain unchanged.
                # Future input spans the existing 45-second CLI allowance.
                # This is not a timeout: command=45s, clock wait=60s and
                # the campaign allowance/iterations/assertions are unchanged.
                due = datetime.now(UTC)+timedelta(seconds=45)
                job = json.loads(cli('schedule', command, '-H', 'a', 'b', '--at', due.isoformat(),
                    '--format', 'json', '--misfire-grace', '900', *state, *common, '--adaptive'))[0]
                jobs.append((job, command))
                expected_calls[command] += 1 if command == 'failed' else 2
            wait_until_due(due)
            rows = []
            for job, command in jobs:
                # A manual invocation shares the same coordinator while the
                # scheduler owns its claim. Each worker process handles one job.
                manual_env = dict(env, SWASSH_TEST_CALLS=str(root/'manual-calls'))
                manual = subprocess.Popen([sys.executable, '-m', 'swassh', 'run', 'ok', '-H', 'manual',
                    *common], cwd=root, env=manual_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    cli('schedule', '--worker', '--once', *state)
                    if manual.wait(timeout=45) != 0:
                        raise RuntimeError('concurrent manual invocation failed')
                finally:
                    if manual.poll() is None:
                        manual.kill()
                        manual.wait(timeout=5)
                observed = json.loads(cli('schedule', '--show', job['id'], '--format', 'json', *state))[0]
                expected_state = 'failed' if command == 'failed' else 'succeeded'
                if not (observed['state'] == expected_state):
                    raise AssertionError(observed)
                report = json.loads(Path(job['report_path']).read_text())
                if not (report['total'] == 2 and report['ok'] == (command != 'failed')):
                    raise AssertionError()
                if command == 'failed':
                    if not (observed['reason'] == 'host_or_canary_failed'):
                        raise AssertionError()
                    if not (report['counts']['failed'] == report['counts']['skipped'] == 1):
                        raise AssertionError()
                rows.append({'state': observed['state'], 'reason': observed['reason'],
                             'counts': observed['counts'], 'report_verified': True})
            cli('schedule', '--worker', '--once', *state)
            cli('schedule', '--worker', '--once', *state)
            if not (Counter((root/'calls').read_text().splitlines()) == expected_calls):
                raise AssertionError()
            if not ((root/'manual-calls').read_text().splitlines() == ['ok']*self.iterations):
                raise AssertionError()
            return {'status': 'EXÉCUTÉ', 'jobs': self.iterations, 'manual_invocations': self.iterations,
                    'command_calls': sum(expected_calls.values()), 'no_replay_verified': True,
                    'network': 'deterministic process fixture; no remote SSH', 'results': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=50)
    args = parser.parse_args()
    result = ScheduleCampaign(args.iterations).run()
    destination = ROOT/'validation'
    destination.mkdir(exist_ok=True)
    (destination/'schedule-campaign.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'results'}))


if __name__ == '__main__':
    main()
