"""Human reports retain machine data and remain bounded across report processes."""

import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from swassh import Host, Options, Result, Status, Swarm
from swassh.infrastructure.installation import PathConfigurator
from swassh.infrastructure.report import Report, ReportFormatter, TerminalColor, safe_text, response_payload


class PresentationTests(unittest.TestCase):
    def test_c1_controls_are_neutralized_without_losing_printable_unicode(self):
        self.assertEqual(safe_text('A\x7f\x85\x9f\u0100'),'A???\u0100')

    def test_formatter_column_and_line_limits_reject_invalid_types_and_upper_bound(self):
        with self.assertRaises(ValueError):ReportFormatter(max_lines=10001)
        for columns in (True,'1',0):
            with self.subTest(columns=columns),self.assertRaises(ValueError):ReportFormatter(max_columns=columns)

    def test_explicit_colors_sample_remainder_and_truncated_stdout_are_rendered(self):
        colors=TerminalColor(enabled=True);formatter=ReportFormatter(colors=colors)
        self.assertIs(formatter.colors,colors)
        payload=response_payload(Result(Host('one'),Status.FAILED,stdout='partial',exit_code=7,stdout_truncated=True))
        text=formatter.render(3,{'failed':3},[(payload,3,('one',),0)],show_output=True)
        self.assertIn('(+2)',text);self.assertIn('capture output truncated',text);self.assertIn('partial',text)

    def test_output_enabled_by_default_and_explicitly_disabled(self):
        from swassh.interfaces import cli
        parser = cli._parser()
        base = ['run', 'uname -r', '-H', 'host']
        self.assertTrue(parser.parse_args(base).show_output)
        self.assertTrue(parser.parse_args(base + ['--show-output']).show_output)
        self.assertFalse(parser.parse_args(base + ['--hide-output']).show_output)
        self.assertTrue(Options().show_output)
        now = datetime.now(UTC)
        report = Report('uname -r', (Result(Host('ok'), Status.SUCCESS, 'kernel-version'),), now, now)
        self.assertIn('kernel-version', report.to_text())

    def test_scheduled_output_snapshot_preserves_old_and_new_defaults(self):
        from swassh.application.schedule_contracts import ScheduledInvocation
        from swassh.infrastructure.schedule_store import encode_invocation, decode_invocation
        invocation = ScheduledInvocation('uname -r', (Host('ok'),), Options(), str(Path.cwd() / 'report.json'))
        payload = json.loads(encode_invocation(invocation))
        self.assertTrue(decode_invocation(json.dumps(payload)).options.show_output)
        payload['options']['show_output'] = False
        self.assertFalse(decode_invocation(json.dumps(payload)).options.show_output)
        del payload['options']['show_output']
        self.assertFalse(decode_invocation(json.dumps(payload)).options.show_output)

    def test_setup_path_cli_dispatch_and_failure(self):
        import contextlib
        from swassh.interfaces import cli
        with patch('swassh.infrastructure.installation.setup_path') as setup:
            self.assertEqual(cli.main(['setup-path']), 0)
            setup.assert_called_once_with()
        with patch('swassh.infrastructure.installation.setup_path') as setup:
            self.assertEqual(cli.main(['setup-path', '--app-venv']), 0)
            setup.assert_called_once_with(allow_venv=True)
        with patch('swassh.infrastructure.installation.setup_path', side_effect=ValueError('unsupported shell')):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(cli.main(['setup-path']), 2)
            self.assertIn('unsupported shell', output.getvalue())
        args = cli._parser().parse_args(['run', 'ip a', '-H', 'host', '--show-output', '--output-lines', '0'])
        self.assertTrue(args.show_output)
        self.assertEqual(args.output_lines, 0)
        for settings in ({'show_output': 'yes'}, {'output_lines': -1}, {'output_lines': True}, {'output_lines': 10001}):
            with self.assertRaises(ValueError):
                Options(**settings)

    def test_installer_offline_wheel_and_skip_path(self):
        import runpy
        from types import SimpleNamespace
        script = Path(__file__).resolve().parents[1] / 'scripts/install.py'
        main = runpy.run_path(str(script))['main']
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / 'swassh-test-py3-none-any.whl'
            wheel.write_bytes(b'input verified by pip')
            with patch('sys.argv', ['install.py', str(wheel)]), patch('subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(main(), 0)
                self.assertIn('--no-index', run.call_args_list[0].args[0])
                self.assertIn('--no-deps', run.call_args_list[0].args[0])
                self.assertEqual(run.call_args_list[1].args[0][-1], 'setup-path')
            with patch('sys.argv', ['install.py', str(wheel), '--skip-path', '--user']), patch('subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(main(), 0)
                self.assertEqual(run.call_count, 1)
                self.assertIn('--user', run.call_args.args[0])
            with patch('sys.argv', ['install.py', str(wheel)]), patch('subprocess.run', return_value=SimpleNamespace(returncode=7)) as run:
                self.assertEqual(main(), 7)
                self.assertEqual(run.call_count, 1)

    def test_installed_entrypoint_discovery_and_environment_guard(self):
        import importlib.metadata
        from types import SimpleNamespace
        from swassh.infrastructure import installation
        with patch('importlib.metadata.distribution', side_effect=importlib.metadata.PackageNotFoundError), self.assertRaisesRegex(ValueError, 'install the SWASSH wheel'):
            installation.installed_scripts()
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory)
            entry = scripts / ('swassh.exe' if os.name == 'nt' else 'swassh')
            entry.write_text('entrypoint')
            distribution = SimpleNamespace(files=[Path(entry.name)], locate_file=lambda value: scripts / value)
            with patch('importlib.metadata.distribution', return_value=distribution):
                self.assertEqual(installation.installed_scripts(), scripts.resolve())
            distribution.files = []
            with patch('importlib.metadata.distribution', return_value=distribution), patch('sysconfig.get_path', return_value=str(scripts)):
                self.assertEqual(installation.installed_scripts(), scripts)
                entry.unlink()
                with self.assertRaises(ValueError):
                    installation.installed_scripts()
            with patch('sys.prefix', 'virtual'), patch('sys.base_prefix', 'base'), self.assertRaises(ValueError):
                installation.setup_path()

    def test_arbitrary_multiline_limits_and_terminal_controls(self):
        formatter = ReportFormatter(max_lines=2, max_columns=30)
        text = formatter._format_complex_output('  first\n\x1b[31msecond\nthird\n ')
        self.assertIn('  │ first', text)
        self.assertIn('  │ ?[31msecond', text)
        self.assertIn('1 lines hidden', text)
        self.assertNotIn('\x1b', text)
        self.assertIn('no output', formatter._format_complex_output(' \n'))
        self.assertIn('line truncated', formatter._format_complex_output('x' * 50))
        for value in (-1, True, '1'):
            with self.assertRaises(ValueError):
                ReportFormatter(max_lines=value)

    def test_success_hidden_changed_explicit_and_no_command_parsing(self):
        now = datetime.now(UTC)
        results = (Result(Host('ok'), Status.SUCCESS, 'SECRET-SUCCESS\nsecond'),
                   Result(Host('change'), Status.SUCCESS, 'updated\nsecond', changed=True),
                   Result(Host('bad'), Status.FAILED, stderr='failed\nreason', exit_code=9))
        report = Report('arbitrary command', results, now, now, show_output=False)
        text = report.to_text()
        self.assertNotIn('SECRET-SUCCESS', text)
        self.assertIn('[CHANGED / success]', text)
        self.assertIn('  │ updated\n  │ second', text)
        self.assertIn('exit code: 9', text)
        self.assertEqual(len(report.response_groups()), 3)
        self.assertIn('SECRET-SUCCESS', report.to_json())
        rows = list(csv.DictReader(io.StringIO(report.to_csv())))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]['stdout'], 'SECRET-SUCCESS\nsecond')
        self.assertIn('\r\n\r\n', report.to_csv())
        self.assertEqual(rows[1]['changed'], 'True')
        with self.assertRaises(ValueError):
            Result(Host('bad'), Status.FAILED, changed=True)

    def test_colors_only_for_tty_and_no_color(self):
        raw = io.BytesIO()
        legacy = io.TextIOWrapper(raw, encoding='ascii', newline='')
        TerminalColor(legacy).write(legacy, '  │ sortie é\n')
        legacy.flush()
        self.assertEqual(raw.getvalue(), b'  \\u2502 sortie \\xe9\n')
        stream = io.StringIO()
        self.assertEqual(TerminalColor(stream).danger('bad'), 'bad')
        with patch.object(stream, 'isatty', return_value=True), patch.dict(os.environ, {'TERM': 'xterm'}, clear=True):
            colors = TerminalColor(stream)
            self.assertIn('\x1b[', colors.heading('[FAILED / timeout]'))
            self.assertIn('\x1b[', colors.heading('[CHANGED / success]'))
            self.assertIn('\x1b[', colors.heading('SWASSH'))
            self.assertIn('\x1b[', colors.heading('success 2'))
            self.assertIn('\x1b[', colors.info('info'))
            self.assertEqual(colors.heading('  │ [FAILED payload]'), '  │ [FAILED payload]')
            with patch.dict(os.environ, {'NO_COLOR': ''}):
                self.assertEqual(TerminalColor(stream).danger('bad'), 'bad')


class MixedTransport:
    """A deterministic adapter supplies explicit change information, never guesses."""

    async def execute(self, host, command):
        if host.hostname == 'bad':
            return Result(host, Status.FAILED, stderr='failure\n' * 20, exit_code=3)
        return Result(host, Status.SUCCESS, stdout='multiline\noutput', changed=host.hostname == 'change')


class MultiprocessPresentationTests(unittest.IsolatedAsyncioTestCase):
    async def test_show_success_output_without_command_heuristics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = Swarm(Options(output_lines=0), transport=MixedTransport())
            for command in ('ls', 'ip a', 'opaque-custom-command'):
                report = await service.run(['ok', 'change'], command)
                text = report.to_text()
                self.assertEqual(text.count('  │ multiline\n  │ output'), 2)
                self.assertIn('[OK / success]', text)
                self.assertIn('ok:22', text)
            summary = await service.run_to_file(['ok', 'bad'], 'opaque', root / 'text', 'text')
            self.assertTrue(summary.show_output)
            text = (root / 'text').read_text(encoding='utf-8')
            self.assertIn('  │ multiline\n  │ output', text)
            self.assertEqual(text.count('  │ failure'), 20)
            self.assertNotIn('lines hidden', text)

    async def test_real_report_worker_json_csv_and_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for format in ('json', 'csv', 'text'):
                summary = await Swarm(Options(show_output=False), transport=MixedTransport()).run_to_file(
                    ['ok', 'change', 'bad'], 'opaque', root / format, format)
                self.assertNotEqual(summary.report_worker_pid, os.getpid())
            data = json.loads((root / 'json').read_text(encoding='utf-8'))
            self.assertEqual(data['total'], 3)
            self.assertEqual(sum(result['changed'] for result in data['results']), 1)
            self.assertIn('\n  "results": [\n    {\n', (root / 'json').read_text())
            with (root / 'csv').open(newline='', encoding='utf-8') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]['stdout'], 'multiline\noutput')
            text = (root / 'text').read_text(encoding='utf-8')
            self.assertEqual(text.count('  │ multiline'), 1)
            self.assertIn('10 lines hidden', text)
            self.assertNotIn('\x1b', text)


@unittest.skipUnless(os.name == 'posix', 'POSIX shell profile configuration')
class PathSetupTests(unittest.TestCase):
    def test_legacy_block_is_backed_up_and_upgraded(self):
        import shlex
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            setup = PathConfigurator(home / 'bin', home, 'sh')
            quoted = shlex.quote(str(setup.scripts))
            marker = '# SWASSH PATH ' + str(setup.scripts)
            original = ('\n' + marker + '\ncase ":$PATH:" in\n  *:' + quoted
                        + ':*) ;;\n  *) export PATH="$PATH":' + quoted + ' ;;\nesac\n')
            profile = home / '.profile'
            profile.write_text(original)
            profile.chmod(0o600)
            backups = setup.configure()
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)
            output = subprocess.check_output(['/bin/sh', '-cu',
                'unset PATH; . "$1"; printf "%s" "$PATH"', 'test', str(profile)], text=True)
            self.assertEqual(output, str(setup.scripts))
            self.assertEqual(setup.configure(), [])
            profile.write_text(marker + '\n')
            with self.assertRaisesRegex(ValueError, 'incomplete or modified'):
                setup.configure()

    def test_empty_and_unset_path_do_not_add_current_directory(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            setup = PathConfigurator(Path(directory) / 'bin', Path(directory), 'sh')
            for initial in ('unset PATH', 'PATH=', 'PATH=/usr/bin'):
                output = subprocess.check_output(
                    ['/bin/sh', '-cu', initial + '; ' + setup.command() + '; printf "%s" "$PATH"'],
                    text=True)
                expected = ('/usr/bin:' if initial == 'PATH=/usr/bin' else '') + str(setup.scripts)
                self.assertEqual(output, expected)
            with self.assertRaisesRegex(ValueError, 'colon'):
                PathConfigurator(Path(directory) / 'a:b', Path(directory), 'sh')

    def test_setup_path_entrypoint_updates_only_selected_home(self):
        import contextlib
        from swassh.infrastructure.installation import setup_path
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            with patch('swassh.infrastructure.installation.installed_scripts', return_value=home / 'bin'), patch('pathlib.Path.home', return_value=home), patch.dict(os.environ, {'SHELL': '/bin/sh'}), patch('sys.prefix', 'base'), patch('sys.base_prefix', 'base'):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    setup_path()
                self.assertIn('export PATH=', output.getvalue())
                self.assertIn('# SWASSH PATH', (home / '.profile').read_text())

    def test_profiles_backup_idempotence_quoting_and_current_shell(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = home / '.bash_profile'
            profile.write_text('# existing\n', encoding='utf-8')
            profile.chmod(0o600)
            scripts = home / "space ' dollar$ dir"
            configurator = PathConfigurator(scripts, home, 'bash')
            backups = configurator.configure()
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), '# existing\n')
            self.assertTrue(profile.read_text().startswith('# existing\n'))
            self.assertEqual(configurator.configure(), [])
            output = subprocess.check_output(['/bin/sh', '-c', '. "$1"; . "$1"; printf "%s" "$PATH"',
                                               'test', str(profile)], env={'PATH': '/usr/bin'}, text=True)
            self.assertEqual(output, '/usr/bin:' + str(scripts))
            self.assertIn('export PATH=', configurator.command())

    def test_alias_special_permissions_shell_and_profile_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            target = home / 'target'
            target.write_text('untouched')
            profile = home / '.profile'
            profile.symlink_to(target)
            setup = PathConfigurator(home / 'bin', home, 'sh')
            with self.assertRaises(OSError):
                setup.configure()
            self.assertEqual(target.read_text(), 'untouched')
            profile.unlink()
            os.mkfifo(profile)
            with self.assertRaises(ValueError):
                setup.configure()
            profile.unlink()
            profile.write_text('original')
            profile.chmod(0o666)
            with self.assertRaises(ValueError):
                setup.configure()
            with self.assertRaises(ValueError):
                PathConfigurator(home, home, 'csh').profiles()
            with self.assertRaises(ValueError):
                PathConfigurator(Path('/bad\npath'), home, 'sh')
            with patch.dict(os.environ, {'ZDOTDIR': '/custom'}), self.assertRaises(ValueError):
                PathConfigurator(home, home, 'zsh').profiles()
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(len(PathConfigurator(home, home, 'zsh').profiles()), 2)
