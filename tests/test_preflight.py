"""Local diagnostics never execute a remote operation or reveal key contents."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from swassh import Options, Status
from swassh.application.preflight import PreflightError
from swassh.application.transfer_settings import TransferSettings
from swassh.domain.transfers import FileTransfer, TransferDirection
from swassh.infrastructure.preflight import LocalPreflight
from swassh.infrastructure.ssh import SSHTransport, _outcome
from swassh.interfaces import cli


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'private-key'
        self.key.write_text('PRIVATE-CONTENT-MUST-NOT-APPEAR')
        self.key.chmod(0o600)
        self.known = self.root / 'known_hosts'
        self.known.write_text('local readability fixture')
        self.options = Options(ssh_executable=sys.executable, client_keys=(str(self.key),),
            known_hosts=str(self.known), budget_dir=str(self.root / 'budget'))
        self.checker = LocalPreflight()

    def test_readable_files_without_reading_secret_or_writing(self):
        before = sorted(self.root.iterdir())
        report = self.checker.inspect(self.options, output=self.root / 'report', spool=self.root)
        self.assertTrue(report.ok, report)
        text = json.dumps(report.to_dict())
        self.assertNotIn('PRIVATE-CONTENT', text)
        self.assertNotIn(str(self.root), text)
        self.assertEqual(sorted(self.root.iterdir()), before)

    def test_missing_key_prevents_transport_construction(self):
        options = Options(ssh_executable=sys.executable, client_keys=(str(self.root / 'missing'),))
        with patch('swassh.infrastructure.ssh.launch_native') as launch:
            with self.assertRaises(PreflightError) as caught:
                SSHTransport(options)
            launch.assert_not_called()
        self.assertEqual(caught.exception.report.issues[0].code, 'key_1_missing')

    def test_empty_and_nonregular_keys(self):
        self.key.write_text('')
        self.assertEqual(self.checker.credentials(self.options).issues[0].code, 'key_1_empty')
        report = self.checker.credentials(Options(client_keys=(str(self.root),)))
        self.assertFalse(report.ok)

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions and FIFO')
    def test_unsafe_permissions_and_fifo_do_not_block(self):
        self.key.chmod(0o644)
        self.assertEqual(self.checker.credentials(self.options).issues[0].code, 'key_1_permissions')
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        self.assertEqual(self.checker.credentials(Options(client_keys=(str(fifo),))).issues[0].code, 'key_1_not_regular')

    def test_permission_failure_does_not_disclose_exception(self):
        with patch('swassh.infrastructure.preflight.PinnedDirectory', side_effect=PermissionError('SECRET PATH')):
            issue = self.checker.credentials(self.options).issues[0]
        self.assertEqual(issue.code, 'key_1_unreadable')
        self.assertNotIn('SECRET', issue.message)

    def test_invalid_parent_or_io_failure_is_controlled(self):
        for error in (OSError('SECRET'), ValueError('SECRET'), RuntimeError('SECRET')):
            with patch('swassh.infrastructure.preflight.PinnedDirectory', side_effect=error):
                self.assertEqual(self.checker.credentials(self.options).issues[0].code, 'key_1_unsafe')

    def test_missing_tools_and_report_directory(self):
        with patch('swassh.infrastructure.preflight.shutil.which', return_value=None):
            report = self.checker.inspect(self.options, output=self.root / 'missing/report')
            with self.assertRaises(PreflightError):
                self.checker.transport(self.options)
        self.assertFalse(report.ok)
        self.assertIn('ssh_missing', [issue.code for issue in report.issues])
        self.assertIn('report_parent_unavailable', [issue.code for issue in report.issues])

    def test_nonwritable_directory_and_nonfile_destination(self):
        with patch('swassh.infrastructure.preflight.os.access', return_value=False):
            self.assertFalse(self.checker.inspect(self.options, output=self.root / 'report').ok)
        self.assertIn('report_target_invalid', [issue.code for issue in self.checker.inspect(self.options, output=self.root).issues])

    def test_absent_default_identity_and_agent_are_warnings(self):
        options = Options(ssh_executable=sys.executable, known_hosts=str(self.known), budget_dir=str(self.root / 'budget'))
        with patch.dict(os.environ, {'SSH_AUTH_SOCK': str(self.root / 'missing-agent')}):
            report = self.checker.inspect(options)
        self.assertTrue(report.ok)
        self.assertIn('identity_implicit', [issue.code for issue in report.issues])
        self.assertTrue(any(issue.code.startswith('agent_') and issue.level == 'warning' for issue in report.issues))

    def test_transfer_tool_requirements_and_readonly_destinations(self):
        request = FileTransfer(TransferDirection.PUSH, str(self.key), '/remote/file')
        with patch('swassh.infrastructure.preflight.shutil.which', return_value=None):
            report = self.checker.inspect(self.options, request=request, settings=TransferSettings(dry_run=True))
        self.assertIn('transfer_tool_missing', [issue.code for issue in report.issues])
        with self.assertRaises(ValueError):
            self.checker.inspect(self.options, request=request)
        directory = FileTransfer(TransferDirection.PUSH, str(self.root), '/remote/')
        report = self.checker.inspect(self.options, request=directory, settings=TransferSettings(verify_sha256=True))
        self.assertIn('sha256_directory', [issue.code for issue in report.issues])
        pull = FileTransfer(TransferDirection.PULL, str(self.root / 'new'), '/remote/file')
        self.checker.inspect(self.options, request=pull, settings=TransferSettings())
        self.assertFalse((self.root / 'new').exists())

    def test_cli_check_never_reserves_executes_or_creates_job(self):
        for action, extra in (('run', []), ('schedule', ['--at', '2099-01-01 00:00', '--state-dir', str(self.root/'state')])):
            stdout = io.StringIO()
            with patch.object(cli, 'cli_invocation_budget') as budget, patch.object(cli, 'execute_to_file') as execute, patch.object(cli, 'Scheduler') as scheduler, contextlib.redirect_stdout(stdout):
                code = cli.main([action, 'uname -r', '-H', 'host', '--check', '--format', 'json',
                    '--ssh-executable', sys.executable, '--known-hosts', str(self.known), '-k', str(self.key),
                    '--budget-dir', str(self.root/'budget'), *extra])
            self.assertEqual(code, 0, stdout.getvalue())
            self.assertTrue(json.loads(stdout.getvalue())['ok'])
            budget.assert_not_called()
            execute.assert_not_called()
            scheduler.assert_not_called()
        self.assertFalse((self.root/'budget').exists())
        self.assertFalse((self.root/'state').exists())

    def test_transfer_shape_size_and_root_match_execution_contract(self):
        with self.key.open('wb') as stream:
            stream.truncate(2 * 1024**2)
        request = FileTransfer(TransferDirection.PUSH, str(self.key), '/remote/')
        report = self.checker.inspect(self.options, request=request, settings=TransferSettings(max_file_mib=1))
        codes = {issue.code for issue in report.issues}
        self.assertTrue({'source_budget', 'destination_shape'} <= codes)
        pull = FileTransfer(TransferDirection.PULL, self.root.anchor, '/remote/file')
        self.assertIn('pull_root', {issue.code for issue in self.checker.inspect(self.options, request=pull, settings=TransferSettings()).issues})
        nested = self.root / 'missing/nested'
        pull = FileTransfer(TransferDirection.PULL, str(nested), '/remote/file')
        self.assertNotIn('pull_destination_unavailable', {issue.code for issue in self.checker.inspect(self.options, request=pull, settings=TransferSettings()).issues})
        self.assertFalse(nested.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symbolic link')
    def test_transfer_symlink_is_rejected_without_reading_target(self):
        link = self.root / 'link'
        link.symlink_to(self.key)
        request = FileTransfer(TransferDirection.PUSH, str(link), '/remote/file')
        report = self.checker.inspect(self.options, request=request, settings=TransferSettings())
        self.assertIn('source_link', {issue.code for issue in report.issues})

    def test_cli_missing_key_is_actionable_before_budget_and_canary(self):
        stderr = io.StringIO()
        with patch.object(cli, 'cli_invocation_budget') as budget, patch.object(cli, 'execute_to_file') as execute, contextlib.redirect_stderr(stderr):
            code = cli.main(['run', 'uname -r', '-H', 'host', '-k', str(self.root/'SECRET')])
        self.assertEqual(code, 2)
        self.assertIn('key_1_missing', stderr.getvalue())
        self.assertNotIn('SECRET', stderr.getvalue())
        budget.assert_not_called()
        execute.assert_not_called()

    def test_check_formats_and_plan_exclusion(self):
        report = self.checker.credentials(self.options)
        self.assertIn('key_1_readable', cli._render_check(report, 'csv'))
        self.assertIn('[ok]', cli._render_check(report, 'text'))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli._parser().parse_args(['run', 'x', '-H', 'host', '--check', '--plan-only'])

    def test_auth_diagnostics_remain_private_and_do_not_retry(self):
        for detail, phrase, status in (
            ('REMOTE HOST IDENTIFICATION HAS CHANGED', 'changed', Status.HOST_KEY_FAILED),
            ('Host key verification failed', 'unknown', Status.HOST_KEY_FAILED),
            ('Load key SECRET: bad permissions', 'permissions', Status.AUTH_FAILED),
            ('Load key SECRET: invalid format', 'format', Status.AUTH_FAILED),
            ('agent refused operation', 'agent', Status.AUTH_FAILED),
            ('read_passphrase: cannot open tty', 'unlocking', Status.AUTH_FAILED),
            ('Permission denied', 'passwords are disabled', Status.AUTH_FAILED),
        ):
            with self.subTest(detail=detail):
                actual, message, retry = _outcome(255, detail, True)
                self.assertEqual(actual, status)
                self.assertIn(phrase, message)
                self.assertNotIn('SECRET', message)
                self.assertFalse(retry)
        status, _, retry = _outcome(255, 'Authenticated to target\nExit status 255\ninvalid format', True)
        self.assertEqual(status, Status.FAILED)
        self.assertFalse(retry)
