"""Qualification failures retain evidence and early timers cannot race the worker."""
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock, patch


class InstallationProbeTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/validate_installation.py'))

    def test_early_wakeup_is_rechecked_before_worker(self):
        due = datetime(2030, 1, 1, tzinfo=UTC)
        clock = Mock(side_effect=[due-timedelta(seconds=1), due-timedelta(milliseconds=20), due])
        sleep = Mock()
        self.module['wait_until_due'](due, clock=clock, sleep=sleep)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, .02])

    def test_clock_regression_cannot_wait_forever(self):
        due = datetime(2030, 1, 1, tzinfo=UTC)
        with patch('time.monotonic', side_effect=[0, 61]):
            with self.assertRaises(TimeoutError):
                self.module['wait_until_due'](due, clock=lambda: due-timedelta(seconds=1))

    def test_failure_keeps_private_state_and_success_removes_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'fixture'
            root.mkdir(mode=0o700)
            with patch('tempfile.mkdtemp', return_value=str(root)):
                with self.assertRaisesRegex(RuntimeError, 'probe failure'):
                    with self.module['ProbeWorkspace']() as workspace:
                        (workspace.path/'state').write_text('durable evidence')
                        workspace.checks.append({'exit_code': 2})
                        raise RuntimeError('probe failure')
                self.assertEqual((root/'state').read_text(), 'durable evidence')
                self.assertEqual(json.loads((root/'failure.json').read_text())['checks'], [{'exit_code': 2}])
                with self.module['ProbeWorkspace']():
                    pass
                self.assertFalse(root.exists())


    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_schedule_fixture_future_input_survives_slow_cli_startup(self):
        """A valid future-date scenario must allow the existing CLI startup budget."""
        self._inspect_schedule_submission(delay=2.25, expired=False)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_schedule_fixture_still_rejects_an_expired_submission(self):
        """Changing synthetic lead time must never admit a genuinely past date."""
        self._inspect_schedule_submission(delay=0, expired=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_installation_future_input_survives_slow_cli_startup(self):
        """Keep the installed-package scenario valid across permitted startup time."""
        self._inspect_schedule_submission(delay=2.25, expired=False, installation=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_installation_still_rejects_an_expired_submission(self):
        """The longer synthetic lead never changes the real past-date refusal."""
        self._inspect_schedule_submission(delay=0, expired=True, installation=True)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_nominal_schedule_jobs_span_the_existing_campaign_allowance(self):
        """The durability scenario stays nominal throughout its unchanged budget."""
        self._inspect_schedule_submission(delay=0, expired=False, expected_grace=900)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CLI process fixture required')
    def test_schedule_window_still_marks_a_job_missed_after_its_real_deadline(self):
        """A real persisted job cannot be claimed once its own deadline is past."""
        self._inspect_schedule_submission(delay=0, expired=False, expire_after_deadline=True)

    def _inspect_schedule_submission(self, *, delay, expired, installation=False,
                                     expected_grace=None, expire_after_deadline=False):
        import subprocess
        import sys
        import time
        script = Path(__file__).resolve().parents[1]/'scripts'/('validate_installation.py' if installation else 'qualify_schedule.py')
        module = runpy.run_path(str(script))
        campaign = module.get('ScheduleCampaign')
        execute = subprocess.run
        observations = []
        class SubmissionObserved(Exception):
            """End this focused probe after inspecting the real CLI submission."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'fixture'
            root.mkdir(mode=0o700)
            class Workspace:
                def __init__(self):
                    self.path, self.checks = root, []
                def __enter__(self):
                    return self
                def __exit__(self, *error):
                    # The enclosing temporary directory owns all synthetic state.
                    return False
            def inspect(arguments, *args, **kwargs):
                if arguments[:4] == [sys.executable, '-m', 'swassh', 'schedule'] and '--at' in arguments:
                    self.assertEqual(kwargs['timeout'], 60 if installation else 45)
                    arguments = list(arguments)
                    at = arguments.index('--at') + 1
                    if expired:
                        arguments[at] = '2020-01-01T00:00:00+00:00'
                    time.sleep(delay)
                    result = execute(arguments, *args, **kwargs)
                    observations.append((arguments[at], result))
                    if expired or result.returncode == 0:
                        raise SubmissionObserved()
                    return result
                return execute(arguments, *args, **kwargs)
            if installation:
                case = self
                class InstalledSubmission:
                    def __init__(self, iterations):
                        case.assertEqual(iterations, 1)
                    def run(self):
                        inventory = root/'inventory'
                        inventory.write_text('a\nb\n',encoding='utf-8')
                        fixture = root/'ssh-fixture'
                        fixture.write_text('#!'+sys.executable+'\n'+(script.parents[1]/'tests/fake_ssh.py').read_text(),encoding='utf-8')
                        fixture.chmod(0o700)
                        def call(arguments):
                            return inspect([sys.executable,*arguments],cwd=root,env=dict(os.environ),
                                text=True,capture_output=True,timeout=60)
                        module['InstallationScheduleProbe'](call).register(root, inventory, fixture)
                campaign = InstalledSubmission
            with patch.dict(campaign.run.__globals__, ProbeWorkspace=Workspace), patch.object(subprocess, 'run', inspect):
                with self.assertRaises(SubmissionObserved):
                    campaign(1).run()
            self.assertEqual(len(observations), 1)
            due, result = observations[0]
            if expired:
                self.assertEqual(result.returncode, 2)
                self.assertIn('scheduled date and time must be in the future', result.stderr)
                self.assertEqual(result.stdout, '')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertGreater(datetime.fromisoformat(due), datetime.now(UTC))
                job = json.loads(result.stdout)[0]
                self.assertEqual(job['state'], 'pending')
                if expected_grace is not None or expire_after_deadline:
                    from swassh.infrastructure.schedule_store import SQLiteScheduleStore
                    from swassh.domain.scheduling import JobState
                    store = SQLiteScheduleStore(root/'state')
                    try:
                        registered = store.get(job['id'])
                        if expected_grace is not None:
                            self.assertEqual(registered.deadline-registered.due_at,
                                             timedelta(seconds=expected_grace))
                        if expire_after_deadline:
                            self.assertIsNone(store.claim_due(registered.deadline+timedelta(seconds=1)))
                            missed = store.get(job['id'])
                            self.assertEqual(missed.state, JobState.MISSED)
                            self.assertEqual(missed.reason, 'misfire_grace_exceeded')
                            self.assertFalse(Path(job['report_path']).exists())
                            self.assertFalse((root/'calls').exists())
                    finally:
                        store.close()
