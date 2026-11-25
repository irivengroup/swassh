"""Offline installation probes in fresh environments; no dependency resolution."""
import json
import hashlib
import time
from datetime import UTC, datetime, timedelta
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProbeWorkspace:
    """Keep the private fixture and diagnostics on failure, clean only success."""
    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix='swassh-installed-'))
        self.checks = []

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        if kind is None:
            shutil.rmtree(self.path)
        else:
            # Fixture state, database and audit survive even an assertion failure.
            # Raw transcripts stay here, never in the distributable package.
            descriptor = os.open(self.path/'failure.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                json.dump({'status': 'failed', 'checks': self.checks}, stream, indent=2)
            print(f'Private installation failure evidence retained at: {self.path}', file=sys.stderr)


def wait_until_due(due, *, clock=None, sleep=time.sleep):
    """Recheck UTC after early wakeups; never assume one sleep reached the due date."""
    clock = clock or (lambda: datetime.now(UTC))
    deadline = time.monotonic() + 60
    while (remaining := (due - clock()).total_seconds()) > 0:
        if time.monotonic() >= deadline:
            raise TimeoutError('schedule fixture clock did not reach its due date')
        sleep(min(remaining, 1))


class InstallationScheduleProbe:
    """Build the future-date input and submit through the bounded CLI caller.

    The caller owns its existing timeout and nonzero-exit checks; this object
    adds no retry and leaves the production scheduler's date policy untouched.
    """
    def __init__(self, call):
        self.call = call

    def register(self, root, inventory, fixture):
        due = datetime.now(UTC) + timedelta(seconds=60)
        state = root / 'schedules'
        registration = self.call(['-m', 'swassh', 'schedule', 'ok', '-i', str(inventory), '--at', due.isoformat(), '--ssh-executable', str(fixture), '--format', 'json', '--state-dir', str(state), '--budget-dir', str(root / 'budgets'), '--adaptive'])
        return due, state, registration


def probe(artifact):
    with ProbeWorkspace() as workspace:
        root = workspace.path
        environment = root / 'venv'
        venv.EnvBuilder(with_pip=True).create(environment)
        executable = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        checks = workspace.checks
        def call(arguments, expected=0):
            with subprocess.Popen([str(executable), *arguments], cwd=root, env=env,
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                try:
                    stdout, stderr = process.communicate(timeout=60)
                except subprocess.TimeoutExpired:
                    # Context-manager exit must not wait on an unbounded leader.
                    process.kill()
                    process.wait(timeout=5)
                    raise
                completed = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
            checks.append({'arguments': arguments, 'exit_code': completed.returncode,
                           'stdout': completed.stdout, 'stderr': completed.stderr, 'pid': process.pid})
            if completed.returncode != expected:
                raise RuntimeError(f'installation probe failed: {completed.stderr}')
            return completed
        call(['-m', 'pip', 'install', '--disable-pip-version-check', '--no-index', '--no-deps',
              '--no-build-isolation', str(artifact)])
        version = call(['-m', 'swassh', '--version']).stdout.strip()
        expected_version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
        if not (version == 'swassh ' + expected_version):
            raise AssertionError()
        installed_sources=json.loads(call(['-c',
            'import swassh,pathlib,hashlib,json; root=pathlib.Path(swassh.__file__).parent; '
            'print(json.dumps({p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() '
            'for p in root.rglob("*.py")}))']).stdout)
        expected_sources={path.relative_to(ROOT/'src/swassh').as_posix():hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (ROOT/'src/swassh').rglob('*.py')}
        if not (installed_sources==expected_sources):
            raise AssertionError('installed production sources differ from the measured candidate')
        help_run = call(['-m', 'swassh', 'run', '--help']).stdout
        help_push = call(['-m', 'swassh', 'push', '--help']).stdout
        if not ('--report-timeout' in help_run and '--rsync-max-alloc-mib' in help_push):
            raise AssertionError()
        if not (all(flag in help_run for flag in ('--budget-dir', '--bastion-memory-mib', '--adaptive', '--progress'))):
            raise AssertionError()
        if not ('--dry-run' in help_push and '--verify-sha256' in help_push):
            raise AssertionError()
        help_schedule = call(['-m', 'swassh', 'schedule', '--help']).stdout
        if not ('--worker' in help_schedule and '--at' in help_schedule):
            raise AssertionError()
        plan_schedule = call(['-m', 'swassh', 'schedule', 'true', '-H', 'example', '--at', '2099-01-01 00:00', '--canary', '5', '--plan-only'])
        if not (json.loads(plan_schedule.stdout)['canary_count'] == 1):
            raise AssertionError()
        if not ('--canary' in help_run and '--canary' in help_push):
            raise AssertionError()
        if not ('--show-output' in help_run and '--hide-output' in help_run and '--output-lines' in help_run):
            raise AssertionError()
        if not ('--show-output' in help_schedule):
            raise AssertionError()
        if not ('--check' in help_run and '--check' in help_push and '--check' in help_schedule):
            raise AssertionError()
        if not (all(flag in help_run for flag in ('--stream-output', '--stdin-file', '--host-profiles', '--encoding', '--auth-method', '--askpass-executable'))):
            raise AssertionError()
        if not ('--pty' in help_run):
            raise AssertionError()
        if not ('--commands-file' in call(['-m', 'swassh', 'session', '--help']).stdout):
            raise AssertionError()
        call(['-m', 'swassh', 'shell', '-H', 'example', '--plan-only'])
        call(['-m', 'swassh', 'shell', '-H', 'one', 'two', '--plan-only'], 2)
        commands = root/'commands.json'
        commands.write_text(json.dumps(['true', 'uname -r']))
        call(['-m', 'swassh', 'session', '-H', 'example', '--commands-file', str(commands), '--plan-only'])
        call(['-c', 'from swassh import Session, Options; assert Options().pty is False'])
        if not ('--procedure' in call(['-m', 'swassh', 'network', '--help']).stdout):
            raise AssertionError()
        network_file = root/'network.json'
        network_file.write_text(json.dumps({'platform': 'cisco_ios', 'operation': 'administration',
            'steps': [{'stage': 'identify', 'command': 'show version', 'expect': ['fixture']}]}))
        network_plan = json.loads(call(['-m', 'swassh', 'network', '-H', 'example',
                                       '--procedure', str(network_file)]).stdout)
        if not (len(network_plan['approval_sha256']) == 64 and network_plan['targets'] == ['example:22']):
            raise AssertionError()
        call(['-m', 'swassh', 'network', '-H', 'example', '--procedure', str(network_file),
              '--apply', network_plan['approval_sha256'], '--plan-only'], 2)
        call(['-c', 'from swassh import NetworkSwarm, NetworkProcedure, NetworkStep, ReconnectPolicy; assert ReconnectPolicy().attempts == 3'])
        call(['-c', 'from swassh import Client, AsyncClient, CommandError, ExecutionError, OutputDecodeError, Transport, OutputEvent, CommandInput; assert Client("host").hosts[0].hostname == "host"; assert AsyncClient("host").options.canary == 1'])
        call(['-c', 'from swassh import DesiredState, ConvergentSwarm, Workflow, WorkflowStep, WorkflowRunner, '
            'WorkflowState, WorkflowInfo, SSHChannel, SSHTunnel, LocalForward, ChannelCapture, Status; '
            'assert ChannelCapture(Status.SUCCESS,0,b"",b"").ok; '
            'assert SSHChannel("example","true").channel is None; '
            'assert not SSHTunnel("example",LocalForward(18443,"internal",443)).is_open'])
        desired_file=root/'desired-state.json'
        desired_file.write_text(json.dumps({'schema_version':1,'name':'installed-check',
            'check':'ok','apply':'failed','verify':'ok'}),encoding='utf-8')
        desired_plan=json.loads(call(['-m','swassh','converge','--action-file',str(desired_file),
                                      '-H','example','--plan-only']).stdout)
        workflow_file=root/'workflow.json'
        workflow_file.write_text(json.dumps({'schema_version':1,'name':'installed-workflow','steps':[
            {'id':'first','hosts':['srv01'],'command':'ok'},
            {'id':'second','hosts':['srv01'],'command':'ok','needs':['first']}]}),encoding='utf-8')
        workflow_state=root/'workflow-plan-must-not-create-state'
        workflow_plan=json.loads(call(['-m','swassh','workflow','--workflow-file',str(workflow_file),
                                      '--state-dir',str(workflow_state),'--plan-only']).stdout)
        if not (workflow_plan['resource_plan_per_step']['workers']==desired_plan['workers']):
            raise AssertionError()
        if not (not workflow_plan['automatic_replay'] and not workflow_state.exists()):
            raise AssertionError()
        tunnel_plan=json.loads(call(['-m','swassh','tunnel','-H','example','--local-port','18443',
            '--remote-host','internal','--remote-port','443','--plan-only']).stdout)
        if not (tunnel_plan['bind_address']=='127.0.0.1' and tunnel_plan['requested_workers']==1):
            raise AssertionError()
        call(['-m', 'swassh', 'run', 'true', '-H', 'example', '--auth-method', 'gssapi', '--plan-only'])
        call(['-m', 'swassh', 'run', 'true', '-H', 'example', '--auth-method', 'password', '--askpass-executable', str(executable), '--plan-only'])
        call(['-m', 'swassh', 'run', 'true', '-H', 'example', '--auth-method', 'password', '--plan-only'], 2)
        known = root / 'check-known-hosts'
        known.write_text('readability fixture')
        check_report = root / 'must-not-create-report'
        check_budget = root / 'must-not-create-budget'
        checked = call(['-m', 'swassh', 'run', 'true', '-H', 'example', '--check',
            '--ssh-executable', str(executable), '--known-hosts', str(known),
            '--budget-dir', str(check_budget), '--output', str(check_report), '--format', 'json'])
        if not (json.loads(checked.stdout)['ok']):
            raise AssertionError()
        if not (not check_report.exists() and not check_budget.exists()):
            raise AssertionError()
        rejected = call(['-m', 'swassh', 'run', 'true', '-H', 'example', '-k', str(root/'missing-key')], 2)
        if not ('key_1_missing' in rejected.stderr):
            raise AssertionError()
        if not ('setup-path' in call(['-m', 'swassh', 'setup-path', '--help']).stdout):
            raise AssertionError()
        for action in ('run', 'push', 'pull'):
            arguments = [action, 'uname -r'] if action == 'run' else [action, '--source', '/source/', '--destination', '/destination/']
            result = call(['-m', 'swassh', *arguments, '-H', 'example', '--plan-only'])
            if not (1 <= json.loads(result.stdout)['workers'] <= 256):
                raise AssertionError()
            if not (json.loads(result.stdout)['canary_count'] == 1):
                raise AssertionError()
        for flag in (['--canary'], ['--canary', '5']):
            result = call(['-m', 'swassh', 'run', 'true', '-H', 'a', 'b', *flag, '--plan-only'])
            if not (json.loads(result.stdout)['canary_count'] == (2 if len(flag) == 2 else 1)):
                raise AssertionError()
        for flag in ('--dry-run', '--verify-sha256'):
            result = call(['-m', 'swassh', 'push', '--source', '/source', '--destination', '/destination',
                '-H', 'example', flag, '--plan-only'])
            if not (json.loads(result.stdout)['workers'] >= 1):
                raise AssertionError()
        call(['-m', 'swassh', 'push', '--source', '/source', '--destination', '/destination',
            '-H', 'example', '--dry-run', '--verify-sha256', '--plan-only'], 2)
        call(['-m', 'swassh', 'run', 'true', '-H', 'example', '--progress', '--progress-interval', '0.1', '--plan-only'], 2)
        inventory = root / 'hosts.txt'
        inventory.write_text('srv01\nsrv02\n')
        for alias in ('-c', '--command', '--commande'):
            call(['-m', 'swassh', 'run', 'true', alias, 'false', '-i', str(inventory)], 2)
        for timeout in ('0', 'nan'):
            call(['-m', 'swassh', 'run', 'true', '-i', str(inventory), '--report-timeout', timeout, '--plan-only'], 2)
        native_cli = 'not attempted on Windows'
        if os.name == 'posix':
            fixture = root / 'ssh-fixture'
            fixture.write_text('#!' + str(executable) + '\n' + (ROOT / 'tests/fake_ssh.py').read_text())
            fixture.chmod(0o700)
            stdin = root/'stdin-data'
            stdin.write_bytes(b'caf\xe9\n')
            profiles = root/'profiles.json'
            profiles.write_text(json.dumps([{'hostname': 'srv01', 'encoding': 'latin-1'}]))
            extended = call(['-m', 'swassh', 'run', 'stdin-echo', '-H', 'srv01',
                '--ssh-executable', str(fixture), '--stdin-file', str(stdin),
                '--host-profiles', str(profiles), '--stream-output', '--format', 'json'])
            if not (json.loads(extended.stdout)['results'][0]['stdout'] == 'caf\u00e9\n'):
                raise AssertionError()
            live = [json.loads(line) for line in extended.stderr.splitlines()]
            if not (live[0]['text'] == 'caf\u00e9\n' and live[-1]['event'] == 'stream_finished'):
                raise AssertionError()
            calls, output, audit = root / 'calls', root / 'report.json', root / 'audit.jsonl'
            env['SWASSH_TEST_CALLS'] = str(calls)
            marker = root / 'must-not-exist'
            command = 'cd /srv && ./deploy.sh --label "a b"; $(touch ' + str(marker) + ')\ntrue'
            call(['-m', 'swassh', 'run', command, '-i', str(inventory), '--ssh-executable', str(fixture),
                  '--format', 'json', '-o', str(output), '--log-file', str(audit), '--budget-dir', str(root/'budgets'), '--adaptive', '--progress'])
            data = json.loads(output.read_text())
            if not (data['command'] == command and data['total'] == 2 and data['ok']):
                raise AssertionError()
            if not (calls.read_text() == (command + '\n') * 2 and not marker.exists()):
                raise AssertionError()
            if not (data['report_worker_pid'] != checks[-1]['pid']):
                raise AssertionError()
            if not (data['canary'] == {'requested': 1, 'selected': 1, 'passed': True}):
                raise AssertionError()
            call(['-m', 'swassh', 'run', 'failed', '-i', str(inventory), '--canary', '1',
                  '--ssh-executable', str(fixture), '--format', 'json', '-o', str(output), '--log-file', str(audit)], 1)
            failed = json.loads(output.read_text())
            if not (failed['counts']['failed'] == 1 and failed['counts']['skipped'] == 1):
                raise AssertionError()
            if not (failed['canary']['passed'] is False):
                raise AssertionError()
            if not (failed['results'][1]['attempts'] == 0):
                raise AssertionError()
            if not (command not in audit.read_text()):
                raise AssertionError()
            for extra, visible in (([], True), (['--hide-output'], False)):
                text = call(['-m', 'swassh', 'run', 'ok', '-i', str(inventory),
                    '--ssh-executable', str(fixture), *extra]).stdout
                if not (('Linux' in text) == visible):
                    raise AssertionError()
            due, state, registration = InstallationScheduleProbe(call).register(root, inventory, fixture)
            job = json.loads(registration.stdout)[0]
            inventory.write_text('different-after-registration\n')
            wait_until_due(due)
            scheduled_calls = calls.read_text()
            for _ in range(2):
                call(['-m', 'swassh', 'schedule', '--worker', '--once', '--state-dir', str(state)])
            status = call(['-m', 'swassh', 'schedule', '--show', job['id'], '--format', 'json', '--state-dir', str(state)])
            observed = json.loads(status.stdout)[0]
            if not (observed['state'] == 'succeeded'):
                raise AssertionError({
                'state': observed['state'], 'reason': observed.get('reason'),
                'counts': observed.get('counts'), 'due_at': observed['due_at'],
                'started_at': observed.get('started_at'), 'finished_at': observed.get('finished_at')})
            if not (calls.read_text() == scheduled_calls + 'ok\nok\n'):
                raise AssertionError()
            scheduled_report = json.loads(Path(job['report_path']).read_text())
            if not (scheduled_report['total'] == 2 and scheduled_report['ok']):
                raise AssertionError()
            if not (scheduled_report['canary']['passed'] is True):
                raise AssertionError()
            workflow_state=root/'workflows'
            registration=call(['-m','swassh','workflow','--workflow-file',str(workflow_file),
                '--state-dir',str(workflow_state),'--ssh-executable',str(fixture),'--budget-dir',str(root/'budgets')])
            workflow=json.loads(registration.stdout)[0]
            before_workflow=calls.read_text()
            for _ in range(2):
                call(['-m','swassh','workflow','--state-dir',str(workflow_state),'--worker','--once'])
            observed=json.loads(call(['-m','swassh','workflow','--state-dir',str(workflow_state),
                                      '--show',workflow['id']]).stdout)[0]
            if not (observed['state']=='succeeded' and all(step['state']=='succeeded' for step in observed['steps'])):
                raise AssertionError()
            if not (calls.read_text()==before_workflow+'ok\nok\n'):
                raise AssertionError()
            for step in observed['steps']:
                if not (json.loads(Path(step['report_path']).read_text())['ok']):
                    raise AssertionError()
            before_check=calls.read_text()
            converged=json.loads(call(['-m','swassh','converge','--action-file',str(desired_file),'-H','srv01',
                '--ssh-executable',str(fixture),'--budget-dir',str(root/'budgets'),'--format','json']).stdout)
            if not (converged['ok'] and not converged['results'][0]['changed']):
                raise AssertionError()
            if not (calls.read_text()==before_check+'ok\n'):
                raise AssertionError()
            peer=root/'binary-peer'
            peer.write_text('#!'+str(executable)+'\n'+(ROOT/'tests/channel_peer.py').read_text(encoding='utf-8'),encoding='utf-8')
            peer.chmod(0o700)
            binary_script=root/'binary-smoke.py'
            binary_script.write_text(
                'import asyncio\nfrom swassh import SSHChannel,Options\n'
                'async def main():\n'
                '    async with SSHChannel("synthetic","echo",Options(ssh_executable='+repr(str(peer))+',budget_dir='+repr(str(root/'budgets'))+')) as channel:\n'
                '        await channel.send(bytes(range(256)))\n'
                '        channel.close_input()\n'
                '        capture=await channel.wait()\n'
                '        assert capture.ok and capture.stdout==bytes(range(256))\n'
                '        assert capture.stderr==b"synthetic-stderr"\n'
                'if __name__=="__main__": asyncio.run(main())\n',encoding='utf-8')
            call([str(binary_script)])
            native_cli = 'PASS with native process fixture, opaque positional command, report child, audit'
        return {'artifact': artifact.name,'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),
                'version': version, 'fresh_environment': True,'production_sources_identical':True,
                'production_source_files':len(installed_sources),'new_api_exports_and_cli_plans':True,
                'offline_no_dependencies': True, 'native_cli': native_cli, 'checks': checks}


def main():
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    artifacts = [ROOT / 'dist' / f'swassh-{version}-py3-none-any.whl', ROOT / 'dist' / f'swassh-{version}.tar.gz']
    output = {'python': sys.version, 'installations': [probe(path) for path in artifacts]}
    (ROOT / 'validation').mkdir(exist_ok=True)
    (ROOT / 'validation/installation.json').write_text(json.dumps(output, indent=2) + '\n')
    print('Wheel and sdist installed offline in fresh environments: PASS')


if __name__ == '__main__':
    main()
