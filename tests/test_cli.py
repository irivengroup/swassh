import asyncio
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Report, Result, Status
from swassh.interfaces import cli


class CLITests(unittest.TestCase):
    def test_importing_module_entrypoint_does_not_dispatch_the_cli(self):
        """Import is distinct from the separately tested python -m invocation."""
        import importlib
        with patch('swassh.interfaces.cli.main') as dispatch:
            module = importlib.import_module('swassh.__main__')
            importlib.reload(module)
        dispatch.assert_not_called()

    def test_python_module_entrypoint_reports_the_canonical_version_and_exits(self):
        result=subprocess.run([sys.executable,'-m','swassh','--version'],
            cwd=Path(__file__).resolve().parents[1],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
        self.assertEqual(result.stdout.decode().strip(),'swassh '+cli.__version__)
        self.assertEqual(result.stderr,b'')

    def fake(self, hosts, command, path, options, format="json", **kwargs):
        now = datetime.now(UTC)
        report = Report(command, tuple(Result(host, Status.SUCCESS, stdout="Linux") for host in hosts), now, now, show_output=options.show_output)
        report.write(path, format)
        return report

    def test_default_output_compact_opt_out_and_inventory_export(self):
        output = io.StringIO()
        with patch.object(cli, "execute_to_file", self.fake), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["run", "uname", "-H", "a", "b"]), 0)
        self.assertEqual(output.getvalue().count('  │ Linux'), 2)
        compact = io.StringIO()
        with patch.object(cli, "execute_to_file", self.fake), contextlib.redirect_stdout(compact):
            self.assertEqual(cli.main(["run", "uname", "-H", "a", "b", "--hide-output"]), 0)
        self.assertNotIn('  │ Linux', compact.getvalue())
        self.assertLess(len(compact.getvalue().splitlines()), 15)
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory)/"hosts.txt"
            inventory.write_text("a\nb")
            report = Path(directory)/"report.csv"
            with patch.object(cli, "execute_to_file", self.fake):
                self.assertEqual(cli.main(["run", "uname", "-i", str(inventory), "--format", "csv", "-o", str(report)]), 0)
            self.assertIn("success", report.read_text())

    def test_invalid_options(self):
        for extra in (["-j", "0"], ["--connect-rate", "nan"], ["--jump", "bad port"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["run", "x", "-H", "a", *extra]), 2)

    def test_interrupt(self):
        with patch.object(cli, "execute_to_file", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["run", "x", "-H", "a"]), 130)

    def test_plan_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["run", "x", "-H", "a", "-j", "10000", "--plan-only"]), 0)
        plan = json.loads(output.getvalue())
        self.assertLessEqual(plan["workers"], 256)
        self.assertLess(plan["workers"], plan["requested_workers"])

    def test_help_version(self):
        for flag in ("--help", "--version"):
            with self.subTest(flag=flag), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main([flag])
            self.assertEqual(raised.exception.code, 0)


    def test_run_command_verbatim_and_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "hosts.txt"
            inventory.write_text("srv01\nsrv02\n")
            marker = root / "must-not-exist"
            command = ("  cd /srv/app && ./deploy.sh --env production --label 'a b' "
                       + '; printf "%s" "$HOME"; $(touch ' + str(marker) + ")\ntrue  ")
            output = root / "report.json"
            with patch.object(cli, "execute_to_file", self.fake) as execute:
                self.assertEqual(cli.main(["run", command, "-i", str(inventory),
                    "--format", "json", "-o", str(output), "--command-timeout", "120"]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["command"], command)
            self.assertEqual(len(report["results"]), 2)
            self.assertFalse(marker.exists())
            with patch.object(cli, "execute_to_file", wraps=self.fake) as operation, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["run", command, "-H", "srv01", "-u", "admin"]), 0)
                self.assertEqual(operation.call_args.args[1], command)
                self.assertEqual(operation.call_args.args[3].username, "admin")

    def test_run_requires_one_nonempty_command(self):
        invalid = (["run", "-i", "hosts.txt"], ["run", "uname", "-r", "-H", "srv01"],
                   ["run", "", "-H", "srv01"], ["run", "   ", "-H", "srv01"],
                   ["run", "x\x00y", "-H", "srv01"], ["run", "true", "-c", "false", "-H", "srv01"])
        for argv in invalid:
            with self.subTest(argv=argv), patch.object(cli, "execute_to_file") as execute, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.main(argv)
                self.assertEqual(raised.exception.code, 2)
                execute.assert_not_called()

    def test_removed_command_options_are_rejected(self):
        for option in ("-c", "--command", "--commande"):
            for argv in ([option, "true", "-H", "srv01"],
                         ["run", "true", "-H", "srv01", option, "10"],
                         ["push", "-H", "srv01", "--source", "/a", "--destination", "/b", option, "10"],
                         ["pull", "-H", "srv01", "--source", "/a", "--destination", "/b", option, "10"]):
                with self.subTest(argv=argv), patch.object(cli, "execute_to_file") as execute, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        cli.main(argv)
                    self.assertEqual(raised.exception.code, 2)
                    execute.assert_not_called()
        for argv in ([], ["-H", "srv01"], ["unknown", "true", "-H", "srv01"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main(argv)
            self.assertEqual(raised.exception.code, 2)
        help_text = cli._parser("run").format_help()
        self.assertNotIn("--command ", help_text)
        self.assertNotIn("--commande", help_text)

    def test_run_plan_help_and_version(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["run", "./remote.sh --mode production", "-H", "srv01", "--plan-only", "--ssh-executable", "absent-ssh"]), 0)
        self.assertGreater(json.loads(output.getvalue())["workers"], 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            cli.main(["run", "--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("swassh run", output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.main(["run", "--version"])
        self.assertEqual(raised.exception.code, 0)

    def test_run_functional_native_process_and_report(self):
        original = asyncio.create_subprocess_exec
        async def launch(executable, *args, **kwargs):
            kwargs.pop("options", None)
            return await original(sys.executable, str(Path(__file__).with_name("fake_ssh.py")), *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, output, calls, log = (root / name for name in ("hosts.txt", "report.json", "calls", "audit.jsonl"))
            inventory.write_text("srv01\n")
            command = './script.sh --option "a b" && printf "%s" "$USER"'
            with patch("swassh.infrastructure.ssh.launch_native", launch), patch.dict(os.environ, {"SWASSH_TEST_CALLS": str(calls)}):
                self.assertEqual(cli.main(["run", command, "-i", str(inventory), "--ssh-executable", sys.executable,
                    "--format", "json", "-o", str(output), "--log-file", str(log)]), 0)
            self.assertEqual(calls.read_text(), command + "\n")
            data = json.loads(output.read_text())
            self.assertEqual(data["command"], command)
            self.assertEqual(data["results"][0]["status"], "success")
            self.assertNotEqual(data["report_worker_pid"], os.getpid())
            self.assertNotIn(command, log.read_text())


@unittest.skipUnless(shutil.which("ssh"), "OpenSSH system client unavailable")
class NativeClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_client_unreachable_and_cli_trace(self):
        with socket.socket() as sock, tempfile.TemporaryDirectory() as directory:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            # Keep this non-listening port reserved. Allow guardian/report startup
            # under coverage or loaded CI; the native connection deadline stays 1s.
            output = Path(directory)/"report.json"
            log = Path(directory)/"audit.jsonl"
            process = await asyncio.create_subprocess_exec(sys.executable, "-m", "swassh", "run", "true", "-H", f"127.0.0.1:{port}", "--connect-timeout", "1", "--command-timeout", "15", "--retries", "1", "--retry-delay", "0",
                "--format", "json", "-o", str(output), "--log-file", str(log),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 45)
            self.assertEqual(process.returncode, 1, stderr.decode())
            self.assertFalse(stdout)
            data = json.loads(output.read_text())
            # Windows can drop SYNs to closed loopback ports instead of refusing
            # them. Both classifications must remain pre-authentication failures.
            self.assertIn(data["results"][0]["status"], ("unreachable", "timeout"), data["results"][0])
            self.assertIn(data["results"][0]["error"], (
                "SSH connection failed before authentication", "SSH connection deadline exceeded"), data["results"][0])
            self.assertEqual(data["results"][0]["attempts"], 2)
            records = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(all(item["run_id"] == data["run_id"] for item in records))
            self.assertNotEqual(data["report_worker_pid"], process.pid)

    async def test_real_client_handshake_deadline(self):
        from swassh import Options, Swarm
        writers = []
        def accept(reader, writer):
            writers.append(writer)
        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            result = (await Swarm(Options(command_timeout=0.2)).run([Host("127.0.0.1", port)], "true")).results[0]
            self.assertEqual(result.status, Status.TIMEOUT)
            self.assertEqual(result.attempts, 1)
        finally:
            server.close()
            for writer in writers:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionResetError:
                    # Killing the timed-out SSH client can reset its TCP socket.
                    # This is expected during teardown, after outcome assertions.
                    pass
            await server.wait_closed()


class InventoryPortPrivacyCLITests(unittest.TestCase):
    """Reject malformed inventory before any native operation, without echoing it."""

    def test_invalid_inventory_ports_are_redacted_before_any_cli_operation(self):
        marker = 'synthetic-confidential-port-value-27'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for extension, content in (
                    ('csv', 'hostname,port\nnode,' + marker + '\n'),
                    ('yaml', '- hostname: node\n  port: ' + marker + '\n'),
                    ('txt', 'node:' + marker + '\n')):
                path = root / ('inventory.' + extension)
                path.write_text(content, encoding='utf-8')
                stdout, stderr = io.StringIO(), io.StringIO()
                with self.subTest(format=extension), patch.object(cli, 'execute_to_file') as execute, \
                        patch.object(cli, 'LocalPreflight') as preflight, \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(cli.main(['run', 'true', '-i', str(path), '--check']), 2)
                execute.assert_not_called()
                preflight.assert_not_called()
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(stderr.getvalue(), 'swassh: invalid input or report I/O (InventoryError): check inventory, options, credentials and output path\n')
                self.assertNotIn(marker, stderr.getvalue())


class SelectedCommandParserTests(unittest.TestCase):
    def test_entrypoint_constructs_only_the_selected_command_options(self):
        parser = cli._parser
        for arguments, expected in ((['run', '--help'], ['run']), (['--help'], [])):
            with self.subTest(arguments=arguments), patch.object(cli, '_parser', wraps=parser) as observed, \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
                cli.main(arguments)
            self.assertEqual(exit.exception.code, 0)
            self.assertEqual([call.args[0] for call in observed.call_args_list if call.args], expected)

    def test_selected_parser_preserves_all_command_help_and_parsed_values(self):
        for action in ('run', 'network', 'converge', 'tunnel', 'session', 'shell',
                       'push', 'pull', 'schedule', 'workflow', 'setup-path'):
            with self.subTest(action=action):
                complete = cli._parser()
                selected = cli._parser(selected=action)
                self.assertEqual(selected.format_help(), complete.format_help())
                first = complete._subparsers._group_actions[0].choices[action]
                second = selected._subparsers._group_actions[0].choices[action]
                self.assertEqual(second.format_help(), first.format_help())
        for arguments in (['run', 'true', '-H', 'node', '--plan-only'],
                          ['schedule', '--list'], ['setup-path', '--app-venv']):
            self.assertEqual(vars(cli._parser(selected=arguments[0]).parse_args(arguments)),
                             vars(cli._parser().parse_args(arguments)))
