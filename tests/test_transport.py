import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swassh import Host, Options, Status, Swarm
from swassh.infrastructure.ssh import SSHTransport, _config, _outcome, _quote

FAKE = Path(__file__).with_name("fake_ssh.py")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def execute(self, command, *, ready=None, on_ready=None, **kwargs):
        original = asyncio.create_subprocess_exec

        async def fake(executable, *args, **options):
            options.pop("options", None)
            process = await original(sys.executable, str(FAKE), *args, **options)
            if ready is not None:
                try:
                    async with asyncio.timeout(5):
                        while not ready.exists():
                            await asyncio.sleep(0.005)
                    on_ready()
                except BaseException:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    raise
            return process

        with patch("swassh.infrastructure.ssh.launch_native", fake):
            return (
                await Swarm(Options(ssh_executable=sys.executable, **kwargs)).run(
                    ["host"], command
                )
            ).results[0]

    async def test_outcomes(self):
        cases = [
            ("ok", Status.SUCCESS, 0),
            ("failed", Status.FAILED, 7),
            ("remote255", Status.FAILED, 255),
            ("auth", Status.AUTH_FAILED, 255),
            ("key", Status.HOST_KEY_FAILED, 255),
            ("unreachable", Status.UNREACHABLE, 255),
            ("unknown", Status.ERROR, 255),
            ("interrupt", Status.INTERRUPTED, 255),
        ]
        for command, status, code in cases:
            with self.subTest(command=command):
                result = await self.execute(command)
                self.assertEqual(result.status, status)
                self.assertEqual(result.exit_code, code)

    async def test_no_retry_after_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls"
            with patch.dict(os.environ, {"SWASSH_TEST_CALLS": str(path)}):
                result = await self.execute("remote255", retries=3)
            self.assertEqual(result.attempts, 1)
            self.assertEqual(path.read_text().splitlines(), ["remote255"])

    async def test_retry_connection_only(self):
        result = await self.execute("unreachable", retries=2, retry_delay=0)
        self.assertEqual(result.attempts, 3)
        result = await self.execute("auth", retries=2)
        self.assertEqual(result.attempts, 1)

    async def test_capture(self):
        result = await self.execute("large", max_output_bytes=1024)
        self.assertEqual(result.stdout, "a" * 1024)
        self.assertEqual(result.stderr, "b" * 1024)
        self.assertTrue(result.stdout_truncated and result.stderr_truncated)
        self.assertEqual((await self.execute("binary")).stdout, "bad\ufffd")

    async def test_deadline_partial(self):
        # Exercise partial-output preservation after a real child has emitted.
        # Process startup latency is tested independently below, not guessed.
        real_timeout = asyncio.timeout
        deadlines = []

        def timeout(delay):
            if delay == 0.1:
                deadline = real_timeout(None)
                deadlines.append(deadline)
                return deadline
            return real_timeout(delay)

        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready'
            with patch.dict(os.environ, {'SWASSH_TEST_READY': str(ready)}), patch(
                'swassh.infrastructure.ssh.asyncio.timeout', timeout
            ):
                result = await self.execute('sleep', command_timeout=0.1, retries=3,
                    ready=ready, on_ready=lambda: deadlines[0].reschedule(asyncio.get_running_loop().time() + 0.1))
        self.assertEqual(result.status, Status.TIMEOUT)
        self.assertEqual(result.stdout, "partial\n")
        self.assertEqual(result.attempts, 1)

    async def test_deadline_includes_slow_process_start(self):
        async def delayed_start(*args, **kwargs):
            await asyncio.Event().wait()
        with patch('swassh.infrastructure.ssh.launch_native', delayed_start):
            async with asyncio.timeout(5):
                report = await Swarm(Options(ssh_executable=sys.executable, command_timeout=0.1)).run(['host'], 'sleep')
        self.assertEqual(report.results[0].status, Status.TIMEOUT)
        self.assertEqual(report.results[0].stdout, '')
        self.assertEqual(report.results[0].attempts, 1)

    async def test_diagnostic_budget(self):
        result = await self.execute("diagnostic")
        self.assertEqual(result.status, Status.ERROR)

    async def test_cancel_process(self):
        task = asyncio.create_task(self.execute("sleep"))
        await asyncio.sleep(0.1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    def test_security_configuration(self):
        text = _config(
            Host("node", 2222, "admin"),
            Options(client_keys=("/key with spaces",), jump_host=Host("jump")),
        )
        for expected in (
            "StrictHostKeyChecking yes",
            "BatchMode yes",
            "ForwardAgent no",
            "ProxyJump swassh-jump",
            "ControlMaster no",
        ):
            self.assertIn(expected, text)
        for value in ("x\nInjected yes", "x\x00"):
            with self.assertRaises(ValueError):
                _quote(value)
        with self.assertRaises(ValueError):
            SSHTransport(Options(ssh_executable="swassh_missing_executable_987"))

    def test_conservative_classification(self):
        self.assertFalse(
            _outcome(255, "Authenticated to host\nConnection refused", True)[2]
        )
        self.assertFalse(_outcome(255, "Connection refused", False)[2])
        self.assertEqual(_outcome(255, "Connection timed out", True)[0], Status.TIMEOUT)
