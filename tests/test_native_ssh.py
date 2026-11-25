import asyncio
import getpass
import json
import os
import sys
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from swassh import Host, HostProfile, Options, Status, Swarm


class NativeTools:
    """Locate QA prerequisites in system locations, independently of caller PATH.

    Production still accepts the caller's explicitly configured executables.
    These helpers protect the qualification programs themselves; they do not
    attest binary contents or defend against an administrator changing the OS.
    """
    POSIX_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
    NAMES = frozenset({'ssh', 'sshd', 'ssh-keygen', 'rsync'})

    @staticmethod
    def windows_directory():
        """Read the real system directory through the OS, never an environment hint."""
        import ctypes
        from ctypes import wintypes
        from pathlib import PureWindowsPath
        from swassh.infrastructure.windows import kernel32
        query = kernel32().GetSystemDirectoryW
        query.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        query.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        length = query(buffer, len(buffer))
        if not 0 < length < len(buffer) or not PureWindowsPath(buffer.value).is_absolute():
            raise OSError('native QA system directory unavailable or oversized')
        return buffer.value

    @classmethod
    def search_path(cls):
        if os.name == 'nt':
            return str(Path(cls.windows_directory()) / 'OpenSSH')
        return cls.POSIX_PATH

    @classmethod
    def find(cls, name):
        """Return an absolute existing prerequisite, or None; never search caller PATH."""
        if name not in cls.NAMES:
            raise ValueError('unknown native QA prerequisite')
        if os.name == 'nt':
            candidate = Path(cls.search_path()) / (name + '.exe')
            return str(candidate.resolve()) if candidate.is_file() and os.access(candidate, os.X_OK) else None
        value = shutil.which(name, path=cls.search_path())
        return str(Path(value).resolve()) if value is not None else None

    @classmethod
    def require(cls, name):
        value = cls.find(name)
        if value is None:
            raise RuntimeError('native QA prerequisite unavailable: ' + name)
        return value

    @classmethod
    def environment(cls, **extra):
        """Keep fixture credentials/configuration, with a bounded system search path."""
        return dict(os.environ, **extra, PATH=cls.search_path())


SSHD = NativeTools.find('sshd')


@unittest.skipUnless(
    sys.platform.startswith("linux") and SSHD and NativeTools.find('ssh-keygen'),
    "local OpenSSH server unavailable",
)
class NativeSSHTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="swassh-sshd-test-")
        cls.root = Path(cls.directory.name)
        for name in ("host", "client"):
            subprocess.run(
                [
                    NativeTools.require('ssh-keygen'),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(cls.root / name),
                ],
                check=True,
                env=NativeTools.environment(),
            )
        (cls.root / "authorized_keys").write_text((cls.root / "client.pub").read_text())
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.username = getpass.getuser()
        (cls.root / "known_hosts").write_text(
            f"[127.0.0.1]:{cls.port} " + (cls.root / "host.pub").read_text()
            + f"[localhost]:{cls.port} " + (cls.root / "host.pub").read_text()
        )
        (cls.root / "sshd_config").write_text(f"""Port {cls.port}
ListenAddress 127.0.0.1
HostKey {cls.root}/host
PidFile {cls.root}/pid
AuthorizedKeysFile {cls.root}/authorized_keys
StrictModes no
PasswordAuthentication {'yes' if os.environ.get('SWASSH_TEST_PASSWORD_USER') else 'no'}
KbdInteractiveAuthentication no
PermitRootLogin yes
UsePAM {'no' if os.environ.get('SWASSH_TEST_PASSWORD_USER') else 'yes'}
AllowTcpForwarding yes
LogLevel ERROR
Subsystem sftp internal-sftp
{'GSSAPIAuthentication yes' if os.environ.get('SWASSH_TEST_KERBEROS') else ''}
{'GSSAPIStrictAcceptorCheck no' if os.environ.get('SWASSH_TEST_KERBEROS') else ''}
""")
        if os.geteuid() == 0:
            Path("/run/sshd").mkdir(exist_ok=True, mode=0o755)
        cls.log = (cls.root / "server.log").open("w")
        cls.server = subprocess.Popen(
            [SSHD, "-D", "-e", "-f", str(cls.root / "sshd_config")],
            stdout=cls.log,
            stderr=cls.log,
            env=NativeTools.environment(),
        )
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    pass
                client_config = cls.root / "preflight"
                client_config.write_text(
                    f"Host *\n  BatchMode yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {cls.root}/known_hosts\n"
                )
                probe = subprocess.run(
                    [
                        NativeTools.require('ssh'),
                        "-F",
                        str(client_config),
                        "-i",
                        str(cls.root / "client"),
                        "-p",
                        str(cls.port),
                        f"{cls.username}@127.0.0.1",
                        "true",
                    ],
                    capture_output=True,
                    timeout=5,
                    env=NativeTools.environment(),
                )
                if probe.returncode:
                    cls.log.flush()
                    server_error = (cls.root / "server.log").read_text()
                    cls.server.terminate()
                    cls.server.wait(timeout=5)
                    cls.log.close()
                    cls.directory.cleanup()
                    if (
                        "chroot(" in server_error
                        and "Operation not permitted" in server_error
                    ):
                        raise unittest.SkipTest(
                            "local sshd requires chroot capability unavailable in sandbox"
                        )
                    raise RuntimeError(
                        "native SSH preflight failed: " + probe.stderr.decode()
                    )
                return
            except OSError:
                if cls.server.poll() is not None:
                    cls.log.close()
                    raise RuntimeError((cls.root / "server.log").read_text())
                time.sleep(0.02)
        raise RuntimeError("local sshd did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)
        cls.log.close()
        cls.directory.cleanup()

    def options(self, **kwargs):
        return Options(
            username=self.username,
            client_keys=(str(self.root / "client"),),
            known_hosts=str(self.root / "known_hosts"),
            **kwargs,
        )

    async def run_host(self, command, **kwargs):
        return (
            await Swarm(self.options(**kwargs)).run(
                [Host("127.0.0.1", self.port)], command
            )
        ).results[0]

    async def test_command_exit_text_cannot_confirm_a_killed_shell(self):
        # A signal terminates this shell without an exit-status SSH receipt.
        # The same text is logged in Sending command and printed remotely.
        result = await self.run_host(
            "printf '%s\\n' 'Exit status 255'; kill -KILL $$",
            retries=3, command_timeout=5,
        )
        self.assertEqual(result.status, Status.INTERRUPTED)
        self.assertEqual(result.exit_code, 255)
        self.assertEqual(result.stdout, 'Exit status 255\n')
        self.assertEqual(result.attempts, 1)
        self.assertIn('unknown', result.error)

    async def test_multiline_exit_text_never_replaces_the_remote_exit_receipt(self):
        from swassh import SSHChannel
        from shlex import quote
        for mode in ('run', 'channel'):
            for confirmed in (False, True):
                with self.subTest(mode=mode, confirmed=confirmed):
                    counter = self.root / ('multiline-calls-' + mode + str(confirmed))
                    # These apparent receipts belong to an ignored literal
                    # argument and OpenSSH's echoed command, not SSH messages.
                    command = ("printf 'ran\\n' >> " + quote(str(counter)) +
                        "; : '\nExit status 255\ndebug1: Exit status 255\n'; " +
                        "printf 'multiline-output\\n'; " + ('exit 255' if confirmed else 'kill -KILL $$'))
                    if mode == 'run':
                        result = await self.run_host(command, retries=3, command_timeout=5)
                        self.assertEqual(result.attempts, 1)
                        output = result.stdout
                    else:
                        async with SSHChannel(Host('127.0.0.1', self.port), command,
                                              self.options(command_timeout=5)) as channel:
                            channel.close_input()
                            result = await channel.wait()
                        output = result.stdout.decode('ascii')
                    self.assertEqual(result.status, Status.FAILED if confirmed else Status.INTERRUPTED)
                    self.assertEqual(result.exit_code, 255)
                    self.assertEqual(output, 'multiline-output\n')
                    self.assertEqual(counter.read_text().splitlines(), ['ran'])

    async def test_real_success(self):
        result = await self.run_host("printf 'Linux\n'")
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.stdout, "Linux\n")
        self.assertEqual(result.stderr, "")

    async def test_scoped_binary_channel_over_authenticated_ssh(self):
        from swassh import SSHChannel
        async with SSHChannel(Host('127.0.0.1',self.port),'cat',self.options()) as channel:
            await channel.send(b'\x00\xffsynthetic-binary')
            channel.close_input()
            capture=await channel.wait()
            self.assertTrue(capture.ok)
            self.assertEqual(capture.stdout,b'\x00\xffsynthetic-binary')
            self.assertEqual(capture.stderr,b'')
            process=channel.native.process
        self.assertIsNotNone(process.returncode)
        self.assertIsNone(process._swassh_guardian)

    async def test_loopback_tunnel_transfers_bytes_and_rejects_unknown_key(self):
        from swassh import LocalForward, SSHTunnel
        async def echo(reader,writer):
            try:
                data=await asyncio.wait_for(reader.readexactly(16),5)
                writer.write(data); await writer.drain()
            finally:
                writer.close(); await writer.wait_closed()
        server=await asyncio.start_server(echo,'127.0.0.1',0)
        remote_port=server.sockets[0].getsockname()[1]
        with socket.socket() as free:
            free.bind(('127.0.0.1',0)); local_port=free.getsockname()[1]
        forward=LocalForward(local_port,'127.0.0.1',remote_port)
        try:
            async with SSHTunnel(Host('127.0.0.1',self.port),forward,self.options(),lifetime=5) as tunnel:
                self.assertTrue(tunnel.is_open)
                reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',local_port),3)
                try:
                    writer.write(b'synthetic-bytes!'); await writer.drain()
                    self.assertEqual(await asyncio.wait_for(reader.readexactly(16),3),b'synthetic-bytes!')
                finally:
                    writer.close(); await writer.wait_closed()
            bad=self.root/'tunnel-untrusted'
            bad.write_text('')
            from dataclasses import replace
            with self.assertRaises(OSError):
                async with SSHTunnel(Host('127.0.0.1',self.port),forward,
                        replace(self.options(),known_hosts=str(bad)),lifetime=5):
                    self.fail('untrusted SSH server admitted a tunnel')
        finally:
            server.close(); await server.wait_closed()

    async def test_application_clients_real_parallel_output_errors_and_session(self):
        from swassh import AsyncClient, ExecutionError
        hosts = [Host('127.0.0.1', self.port), Host('localhost', self.port)]
        client = AsyncClient(hosts, options=self.options())
        report = await client.run('printf \'{"value":7}\'', check=True)
        self.assertEqual([r.json() for r in report.results], [{'value': 7}, {'value': 7}])
        async with client.stream('printf output') as results:
            seen = [result async for result in results]
        self.assertEqual({r.host for r in seen},
                         {Host(h.hostname, h.port, self.username) for h in hosts})
        self.assertTrue(all(r.stdout == 'output' for r in seen))
        with self.assertRaises(ExecutionError) as caught:
            await client.run('exit 9', check=True)
        self.assertEqual([r.status for r in caught.exception.report.results], [Status.FAILED, Status.SKIPPED])
        async with client.on(hosts[0]).session(lifetime=10) as session:
            first = await session.run('printf "%s" "$SSH_CONNECTION"')
            second = await session.run('printf "%s" "$SSH_CONNECTION"')
        self.assertTrue(first.ok and second.ok)
        self.assertEqual(first.results[0].stdout, second.results[0].stdout)

    async def test_live_bidirectional_parallel_prompts_without_newlines(self):
        from swassh import AsyncClient
        hosts = [Host('127.0.0.1', self.port), Host('localhost', self.port)]
        seen = {}
        def factory(host):
            pending = bytearray()
            seen[host.hostname] = []
            async def handler(event, channel):
                if event.stream == 'stdout':
                    pending.extend(event.data)
                    self.assertLessEqual(len(pending), 128)
                    if bytes(pending) == b'answer?':
                        seen[host.hostname].append('prompt')
                        await channel.send(host.hostname.encode() + b'\n')
                        channel.close()
            return handler
        client = AsyncClient(hosts, options=self.options(concurrency=2, canary=2))
        command = "printf 'answer?'; IFS= read -r answer; printf '\nreply:%s' \"$answer\""
        async with client.interact_stream(command, factory, check=True) as results:
            reports = [result async for result in results]
        self.assertEqual(len(reports), 2)
        for result in reports:
            self.assertIn('reply:' + result.host.hostname, result.stdout)
            self.assertEqual(seen[result.host.hostname], ['prompt'])

    async def test_live_callback_failure_output_limit_and_timeout_are_not_success(self):
        from swassh import AsyncClient
        client = AsyncClient(Host('127.0.0.1', self.port), options=self.options())
        async def broken(event, channel):
            raise RuntimeError('sensitive callback content')
        report = await client.interact('printf hello', lambda host: broken)
        self.assertEqual(report.results[0].status, Status.ERROR)
        self.assertNotIn('sensitive', report.results[0].error)
        async def consume(event, channel):
            return None
        report = await client.interact('printf 123456789', lambda host: consume, max_output_bytes=8)
        self.assertEqual(report.results[0].status, Status.ERROR)
        self.assertTrue(report.results[0].stdout_truncated)
        async def stall(event, channel):
            await asyncio.Event().wait()
        report = await client.interact('printf waiting', lambda host: stall, command_timeout=1)
        self.assertEqual(report.results[0].status, Status.TIMEOUT)

    async def test_live_cancellation_revokes_input_and_allows_next_invocation(self):
        from swassh import AsyncClient
        ready = asyncio.Event()
        channels = []
        async def waiting(event, channel):
            channels.append(channel)
            ready.set()
            await asyncio.Event().wait()
        client = AsyncClient(Host('127.0.0.1', self.port), options=self.options())
        task = asyncio.create_task(client.interact('printf waiting', lambda host: waiting))
        try:
            async with asyncio.timeout(10):
                await ready.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            with self.assertRaises(ValueError):
                await channels[0].send(b'late')
            report = await client.run('printf recovered', check=True)
            self.assertEqual(report.results[0].stdout, 'recovered')
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_blocking_client_real_ssh_and_managed_stream(self):
        from swassh import Client
        host, options = Host('127.0.0.1', self.port), self.options()
        def application():
            client = Client(host, options=options)
            report = client.run('printf sync', check=True)
            with client.stream('printf stream', check=True) as results:
                result = next(results)
            return report.results[0], result
        result, streamed = await asyncio.to_thread(application)
        self.assertEqual(result.stdout, 'sync')
        self.assertEqual(streamed.stdout, 'stream')

    async def test_network_drivers_over_real_ssh_and_failure_stops_fleet(self):
        from swassh import NetworkProcedure, NetworkStep, NetworkSwarm
        from test_network import PROMPTS
        fixture = self.root/'device.py'
        fixture.write_bytes((Path(__file__).parent/'network_fixture.py').read_bytes())
        authorized = self.root/'authorized_keys'
        original = authorized.read_text()
        host = Host('127.0.0.1', self.port)
        try:
            for platform, prompt in PROMPTS.items():
                with self.subTest(platform=platform):
                    # SSH still authenticates and allocates a real remote PTY.
                    # Only the vendor device at the far end is simulated.
                    authorized.write_text(f'command="/usr/bin/python3 {fixture} \'{prompt}\'",no-port-forwarding ' + original)
                    request = NetworkProcedure(platform, 'administration', (
                        NetworkStep('identify', 'show version', ('SWASSH fixture-version',)),))
                    service = NetworkSwarm(request, self.options(command_timeout=10))
                    report = await service.run([host], approval=service.plan([host])['approval_sha256'])
                    self.assertTrue(report.ok, report.results)
                    self.assertIn('SWASSH fixture-version', report.to_text())
            sent = self.root/'network-sent'
            authorized.write_text(f'command="/usr/bin/python3 {fixture} router# {sent}",no-port-forwarding ' + original)
            for command, expected in [('fail', Status.ERROR), ('disconnect', Status.ERROR),
                                      ('flood', Status.ERROR), ('wait', Status.TIMEOUT)]:
                with self.subTest(command=command):
                    sent.unlink(missing_ok=True)
                    request = NetworkProcedure('cisco_ios', 'administration', (
                        NetworkStep('identify', command, ('never-observed',)),
                        NetworkStep('identify', 'must-not-execute', ('fixture-version',))))
                    service = NetworkSwarm(request, self.options(command_timeout=5, max_output_bytes=4096))
                    hosts = [host, Host('localhost', self.port)]
                    report = await service.run(hosts, approval=service.plan(hosts)['approval_sha256'])
                    self.assertEqual(report.results[0].status, expected, report.results)
                    self.assertEqual(report.results[1].status, Status.SKIPPED)
                    self.assertEqual(report.results[0].attempts, 1)
                    self.assertEqual(sent.read_text().splitlines(), [command])
                    if command == 'fail':
                        self.assertIn('% Invalid input', report.results[0].stdout)
        finally:
            authorized.write_text(original)

    async def test_network_reboot_reconnect_never_replays_activation(self):
        """Use real SSH/PTY; the device restart itself remains simulated."""
        from dataclasses import replace
        from unittest.mock import patch
        from swassh.infrastructure import network
        from swassh import NetworkSwarm, ReconnectPolicy
        from test_network_reboot import reboot_procedure
        fixture = self.root/'reboot-device.py'
        fixture.write_bytes((Path(__file__).parent/'network_fixture.py').read_bytes())
        authorized = self.root/'authorized_keys'
        original = authorized.read_text()
        state_path, sent = self.root/'reboot-state.json', self.root/'reboot-sent'
        hosts = [Host('127.0.0.1', self.port), Host('localhost', self.port)]
        original_launch = network.launch_native
        original_receive = network.DeviceDialogue.receive
        requested_attempts = []
        async def recorded_launch(*argv, **kwargs):
            attempt = {'argv': argv, 'limit': kwargs['max_native_seconds'], 'process': None,
                       'ready': False, 'commands_before': sent.read_text().splitlines() if sent.exists() else []}
            requested_attempts.append(attempt)
            if len(requested_attempts) > 1 and local_startup_delay:
                # Request ownership starts here; the global boot deadline still
                # includes this bounded local delay, before any remote session.
                await asyncio.sleep(local_startup_delay)
            attempt['process'] = await original_launch(*argv, **kwargs)
            return attempt['process']

        async def recorded_receive(channel, **kwargs):
            value = await original_receive(channel, **kwargs)
            if kwargs.get('command') is None:
                attempt = next(row for row in requested_attempts if row['process'] is channel.process)
                attempt['ready'] = True
            return value
        try:
            authorized.write_text(f'command="/usr/bin/python3 {fixture} router# {sent} {state_path}",no-port-forwarding ' + original)
            cases = [('ready', 0, Status.SUCCESS, 2, 1),
                     ('ready', 1, Status.SUCCESS, 3, 1),
                     ('wrong-version', 0, Status.ERROR, 2, 1),
                     ('verification-disconnect', 0, Status.ERROR, 2, 1),
                     ('reject', 0, Status.ERROR, 1, 0),
                     ('ready', 10, Status.TIMEOUT, 4, 0)]
            for local_startup_delay in (0., .8):
                with self.subTest(local_startup_delay=local_startup_delay):
                    for mode, unready, expected, connections, verifications in cases:
                        with self.subTest(mode=mode, unready=unready):
                            state_path.write_text(json.dumps({'mode': mode, 'unready': unready}), encoding='utf-8')
                            sent.unlink(missing_ok=True)
                            service = NetworkSwarm(reboot_procedure(), self.options(command_timeout=20, connect_timeout=1))
                            targets = hosts[:1] if expected == Status.SUCCESS else hosts
                            requested_attempts.clear()
                            with patch.object(network, 'launch_native', recorded_launch), \
                                    patch.object(network.DeviceDialogue, 'receive', recorded_receive):
                                report = await service.run(targets, approval=service.plan(targets)['approval_sha256'])
                            self.assertEqual(report.results[0].status, expected, report.results)
                            self.assertEqual(report.results[0].attempts, 1)
                            if len(targets) == 2:
                                self.assertEqual(report.results[1].status, Status.SKIPPED)
                            commands = sent.read_text().splitlines()
                            self.assertEqual(commands.count('activate'), 1)
                            self.assertEqual(commands.count('verify'), verifications)
                            initial_commands = ['identify', 'backup', 'transfer', 'checksum', 'activate']
                            # Physical pre-command retries are permitted. Exact
                            # command history and ready sessions must not replay.
                            self.assertEqual(commands, initial_commands + ['verify'] * verifications)
                            self.assertEqual(sum(row['ready'] for row in requested_attempts), 1 + verifications)
                            self.assertTrue(all(row['commands_before'] == initial_commands
                                                for row in requested_attempts[1:]))
                            self.assertLessEqual(len(requested_attempts), 1 + reboot_procedure().reconnect.attempts)
                            if expected == Status.TIMEOUT:
                                self.assertEqual(len(requested_attempts), connections)
                            else:
                                self.assertGreaterEqual(len(requested_attempts), connections)
                            if expected == Status.TIMEOUT:
                                # The policy caps requested connections. A pre-auth
                                # timeout need not reach the remote simulator at all.
                                self.assertGreaterEqual(json.loads(state_path.read_text())['connections'], 1)
                                self.assertLessEqual(json.loads(state_path.read_text())['connections'], connections)
                            else:
                                self.assertGreaterEqual(json.loads(state_path.read_text())['connections'], 1 + verifications)
                                self.assertLessEqual(json.loads(state_path.read_text())['connections'], len(requested_attempts))
                            self.assertTrue(all(0 < attempt['limit'] <= 10 for attempt in requested_attempts[1:]))
                            if unready == 1:
                                self.assertIn('no commands sent', report.results[0].stdout)
                    # A long handshake must still be cut off by the shorter boot
                    # window, with no second activation or verification dispatched.
                    state_path.write_text(json.dumps({'unready': 10}), encoding='utf-8')
                    sent.unlink()
                    request = replace(reboot_procedure(), reconnect=ReconnectPolicy(60, 1, 0.1))
                    service = NetworkSwarm(request, self.options(command_timeout=20, connect_timeout=10))
                    requested_attempts.clear()
                    started = time.monotonic()
                    with patch.object(network, 'launch_native', recorded_launch), \
                            patch.object(network.DeviceDialogue, 'receive', recorded_receive):
                        report = await service.run(hosts, approval=service.plan(hosts)['approval_sha256'])
                    self.assertEqual(report.results[0].status, Status.TIMEOUT, report.results)
                    self.assertEqual(report.results[1].status, Status.SKIPPED)
                    self.assertLess(time.monotonic()-started, 8)
                    self.assertEqual(sent.read_text().splitlines(), ['identify', 'backup', 'transfer', 'checksum', 'activate'])
                    self.assertEqual(len(requested_attempts), 2)
                    self.assertGreaterEqual(json.loads(state_path.read_text())['connections'], 1)
                    self.assertLessEqual(json.loads(state_path.read_text())['connections'], 2)
                    self.assertTrue(all(0 < attempt['limit'] <= 1 for attempt in requested_attempts[1:]))
        finally:
            authorized.write_text(original)

    async def test_network_reboot_trust_and_auth_failures_are_terminal(self):
        """Changing trust or credentials between connections must stop retries."""
        from dataclasses import replace
        from unittest.mock import patch
        from swassh import NetworkSwarm
        from swassh.infrastructure import network
        from test_network_reboot import reboot_procedure
        fixture = self.root/'trust-device.py'
        fixture.write_bytes((Path(__file__).parent/'network_fixture.py').read_bytes())
        authorized = self.root/'authorized_keys'
        original = authorized.read_text()
        state_path, sent = self.root/'trust-state.json', self.root/'trust-sent'
        trust = self.root/'reboot-known-hosts'
        hosts = [Host('127.0.0.1', self.port), Host('localhost', self.port)]
        native = network.launch_native
        try:
            for expected in (Status.HOST_KEY_FAILED, Status.AUTH_FAILED):
                with self.subTest(status=expected):
                    trust.write_bytes((self.root/'known_hosts').read_bytes())
                    state_path.write_text('{}', encoding='utf-8')
                    sent.unlink(missing_ok=True)
                    authorized.write_text(f'command="/usr/bin/python3 {fixture} router# {sent} {state_path}",no-port-forwarding ' + original)
                    launches = 0

                    async def launch(*args, **kwargs):
                        nonlocal launches
                        launches += 1
                        if launches == 2:
                            if expected == Status.HOST_KEY_FAILED:
                                trust.write_text('', encoding='utf-8')
                            else:
                                authorized.write_text('', encoding='utf-8')
                        return await native(*args, **kwargs)

                    options = replace(self.options(command_timeout=15), known_hosts=str(trust))
                    service = NetworkSwarm(reboot_procedure(), options)
                    with patch.object(network, 'launch_native', launch):
                        report = await service.run(hosts, approval=service.plan(hosts)['approval_sha256'])
                    self.assertEqual(report.results[0].status, expected, report.results)
                    self.assertEqual(report.results[1].status, Status.SKIPPED)
                    self.assertEqual(launches, 2)
                    self.assertEqual(sent.read_text().splitlines(), ['identify', 'backup', 'transfer', 'checksum', 'activate'])
        finally:
            authorized.write_text(original)

    async def test_reusable_session_and_no_fallback_after_master_loss(self):
        from swassh import Session
        host = Host('127.0.0.1', self.port)
        async with Session(host, self.options(), lifetime=10) as session:
            first = await session.run("printf '%s' \"$SSH_CONNECTION\"")
            second = await session.run("printf '%s' \"$SSH_CONNECTION\"")
            self.assertTrue(first.ok, first.results)
            self.assertTrue(second.ok, second.results)
            self.assertTrue(first.results[0].stdout)
            self.assertEqual(first.results[0].stdout, second.results[0].stdout)
            failed = await session.run('exit 7')
            self.assertEqual(failed.results[0].status, Status.FAILED)
            self.assertEqual(failed.results[0].exit_code, 7)
            master = session.transport.master
            master.terminate()
            await master.wait()
            marker = self.root/'must-not-run-after-master-loss'
            refused = await session.run('touch '+str(marker))
            self.assertFalse(refused.ok)
            self.assertEqual(refused.results[0].status, Status.ERROR)
            self.assertFalse(marker.exists())
        self.assertIsNotNone(master.returncode)

    async def test_remote_pty_is_opt_in_and_merges_streams(self):
        plain = await self.run_host('test -t 0')
        self.assertEqual(plain.status, Status.FAILED)
        terminal = await self.run_host("test -t 0 && printf 'tty-ok'; printf 'err' >&2", pty=True)
        self.assertEqual(terminal.status, Status.SUCCESS)
        self.assertIn('tty-ok', terminal.stdout)
        self.assertIn('err', terminal.stdout)
        # OpenSSH itself may print a connection-closed notice on local stderr;
        # the remote stderr payload must have been merged by the remote PTY.
        self.assertNotIn('err', terminal.stderr)

    async def test_session_lifetime_includes_deliberately_slow_authentication_setup(self):
        from swassh import Session
        from swassh.infrastructure import session as native_session
        from unittest.mock import patch
        original=native_session.launch_native;started=self.root/'delayed-session-client-started'
        wrapper=('import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).touch();'
                 'time.sleep(1.25);os.execv(sys.argv[2],sys.argv[2:])')
        async def delayed(executable,*arguments,**kwargs):
            return await original(sys.executable,'-c',wrapper,str(started),executable,*arguments,**kwargs)
        host=Host('127.0.0.1',self.port)
        try:
            with patch.object(native_session,'launch_native',side_effect=delayed):
                with self.assertRaisesRegex(OSError,'authentication or multiplexing failed'):
                    async with Session(host,self.options(),lifetime=1):
                        self.fail('master exceeded its authentication-inclusive lifetime')
        finally:
            # A protocol rejection or admission failure cannot stand in for
            # the deliberately slow native startup exercised by this test.
            self.assertTrue(started.is_file())

    async def test_session_socket_loss_lifetime_and_cancellation(self):
        from swassh import Session
        host = Host('127.0.0.1', self.port)
        marker = self.root/'must-not-run-after-socket-loss'
        async with Session(host, self.options()) as session:
            session.transport.socket.unlink()
            result = await session.run('touch '+str(marker))
            self.assertFalse(result.ok)
            self.assertEqual(result.results[0].attempts, 1)
            self.assertFalse(marker.exists())
            self.assertTrue(session.transport.closed)
        # Opening a master within one second is not an authentication contract.
        # The separate delayed-setup case above proves the original one-second
        # native bound. This case checks expiry after successful authentication.
        async with Session(host, self.options(connect_timeout=2,report_timeout=2), lifetime=5) as session:
            master = session.transport.master
            async with asyncio.timeout(9):
                await master.wait()
            result = await session.run('true')
            self.assertFalse(result.ok)
        async with Session(host, self.options()) as session:
            pending = asyncio.create_task(session.run('sleep 30'))
            await asyncio.sleep(0.2)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
            self.assertTrue(session.transport.closed)

    async def test_interactive_shell_restores_terminal(self):
        import pty
        import select
        import termios
        import fcntl
        import struct
        import signal
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = None
        try:
            process = subprocess.Popen([sys.executable, '-m', 'swassh', 'shell',
                '-H', f'{self.username}@127.0.0.1:{self.port}',
                '-k', str(self.root/'client'), '--known-hosts', str(self.root/'known_hosts'),
                '--command-timeout', '15'], stdin=slave, stdout=slave, stderr=slave)
            os.write(master, b"printf 'shell-%s\\n' ready\n")
            def collect():
                data = bytearray()
                deadline = time.monotonic() + 20
                resized = False
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        data.extend(os.read(master, 65536))
                    if b'shell-ready' in data and not resized:
                        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 33, 90, 0, 0))
                        os.kill(process.pid, signal.SIGWINCH)
                        # Window-change delivery is asynchronous; the remote
                        # command waits for the observed dimensions, bounded.
                        # Start a new output record even after a shell prompt.
                        # The split marker cannot match the echoed input.
                        os.write(master, b"i=0; while [ \"$(stty size)\" != '33 90' ] && [ $i -lt 20 ]; do i=$((i+1)); sleep .1; done; printf '\\nswassh-pty-%s' 'size='; stty size; exit\n")
                        resized = True
                    if process.poll() is not None:
                        return bytes(data)
                raise TimeoutError('interactive shell fixture deadline')
            output = await asyncio.to_thread(collect)
            self.assertEqual(process.returncode, 0, output)
            self.assertIn(b'shell-ready', output)
            self.assertRegex(output, rb'\nswassh-pty-size=33 90\r?\n')
            self.assertEqual(termios.tcgetattr(slave), before)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            os.close(master)
            os.close(slave)

    async def test_real_input_and_profile_encoding(self):
        path = self.root/'input-bytes'
        path.write_bytes(b'caf\xe9\x00\n' * 2000)
        options = Options(stdin_file=str(path), host_profiles=(HostProfile('127.0.0.1', self.port,
            username=self.username, client_keys=(str(self.root/'client'),),
            known_hosts=str(self.root/'known_hosts'), encoding='latin-1'),))
        result = (await Swarm(options).run([Host('127.0.0.1', self.port)], 'cat')).results[0]
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.stdout.encode('latin-1'), path.read_bytes())

    async def test_real_live_cli_before_completion(self):
        release = self.root/'live-release'
        command = f"printf 'early\\n'; while [ ! -f '{release}' ]; do sleep 0.1; done; printf 'late\\n'"
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'swassh', 'run', command,
            '-H', f'127.0.0.1:{self.port}', '-u', self.username, '-k', str(self.root/'client'),
            '--known-hosts', str(self.root/'known_hosts'), '--stream-output', '--format', 'json',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            async with asyncio.timeout(20):
                first = json.loads(await process.stderr.readline())
                self.assertEqual(first['text'], 'early\n')
                self.assertIsNone(process.returncode)
                release.write_text('continue')
                stdout, stderr = await process.communicate()
            self.assertEqual(process.returncode, 0)
            self.assertTrue(json.loads(stdout)['ok'])
            self.assertEqual(json.loads(stderr.splitlines()[-1])['event'], 'stream_finished')
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def test_real_nonzero_and_remote255(self):
        for code in (7, 255):
            result = await self.run_host(
                f"printf 'Connection refused\n' >&2; exit {code}", retries=2
            )
            self.assertEqual(result.status, Status.FAILED)
            self.assertEqual(result.exit_code, code)
            self.assertEqual(result.attempts, 1)

    async def test_real_jump(self):
        result = await self.run_host(
            "printf 'jump-ok'", jump_host=Host("127.0.0.1", self.port, self.username)
        )
        self.assertEqual(result.status, Status.SUCCESS)
        self.assertEqual(result.stdout, "jump-ok")
        self.assertEqual(result.stderr, "")

    async def test_real_unknown_key(self):
        path = self.root / "empty_known"
        path.write_text("")
        options = self.options()
        from dataclasses import replace

        result = (
            await Swarm(replace(options, known_hosts=str(path))).run(
                [Host("127.0.0.1", self.port)], "true"
            )
        ).results[0]
        self.assertEqual(result.status, Status.HOST_KEY_FAILED)

    async def test_real_timeout(self):
        await self._assert_real_invocation_deadline()

    async def test_real_timeout_without_optional_native_connector(self):
        # The optional connector cannot bypass the whole-invocation deadline.
        # Received-output preservation is tested separately after real output.
        from unittest.mock import patch
        with patch('swassh.infrastructure.relay_connect.NativeConnector.find',return_value=None):
            await self._assert_real_invocation_deadline()

    async def _assert_real_invocation_deadline(self):
        # A short whole-invocation deadline does not promise authentication or
        # first output by that instant. Keep the peer unable to authenticate.
        import shlex
        writers = []
        server = await asyncio.start_server(lambda reader, writer: writers.append(writer), '127.0.0.1', 0)
        marker = self.root/'blocked-command-must-not-run'
        try:
            port = server.sockets[0].getsockname()[1]
            command = 'printf executed > '+shlex.quote(str(marker))
            result = (await Swarm(self.options(command_timeout=.3)).run(
                [Host('127.0.0.1', port)], command)).results[0]
            self.assertEqual(result.status, Status.TIMEOUT)
            self.assertEqual(result.stdout, '')
            self.assertEqual(result.attempts, 1)
            self.assertFalse(marker.exists())
        finally:
            server.close()
            for writer in writers:
                writer.close()
            closed = await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            for failure in closed:
                if isinstance(failure, BaseException) and not isinstance(failure, ConnectionResetError):
                    raise failure
            await server.wait_closed()

    async def test_real_timeout_preserves_output_received_before_injected_deadline(self):
        # Preserve the complete native handshake and byte path. The independent
        # test above verifies the real .3 s whole-invocation deadline. Here a
        # bounded setup budget lets the fault occur after actual output, rather
        # than making its existence depend on scheduler/authentication speed.
        from unittest.mock import patch
        from swassh.infrastructure import ssh
        from swassh.infrastructure.admission_deadline import AdmissionDeadline
        real_timeout = asyncio.timeout
        real_consume = ssh._Buffer.consume
        real_observe = AdmissionDeadline.observe
        for python_connector in (False, True):
            with self.subTest(python_connector=python_connector):
                contexts = []
                admission_ready = asyncio.Event()
                armed = False
                def timeout(delay):
                    context = real_timeout(delay)
                    if delay == 10:
                        contexts.append(context)
                    return context
                async def observe(owner, process):
                    await real_observe(owner, process)
                    admission_ready.set()
                class Reader:
                    def __init__(self, reader): self.reader = reader
                    async def read(self, count):
                        nonlocal armed
                        raw = await self.reader.read(count)
                        if raw:
                            await admission_ready.wait()
                            if not armed:
                                self_test.assertEqual(len(contexts), 1)
                                contexts[0].reschedule(asyncio.get_running_loop().time()+.3)
                                armed = True
                        return raw
                self_test = self
                async def consume(buffer, stream):
                    return await real_consume(buffer, Reader(stream))
                # No timer is disabled. Only the real parent deadline is moved
                # earlier after a real byte arrives; the native watchdog stays
                # at the finite configured setup limit.
                with patch.object(ssh.asyncio, 'timeout', side_effect=timeout), \
                        patch.object(AdmissionDeadline, 'observe', observe), \
                        patch.object(ssh._Buffer, 'consume', consume):
                    async with real_timeout(15):
                        if python_connector:
                            with patch('swassh.infrastructure.relay_connect.NativeConnector.find', return_value=None):
                                result = await self.run_host("printf 'partial\\n'; sleep 3", command_timeout=10)
                        else:
                            result = await self.run_host("printf 'partial\\n'; sleep 3", command_timeout=10)
                self.assertTrue(armed)
                self.assertEqual(result.status, Status.TIMEOUT)
                self.assertEqual(result.stdout, 'partial\n')
                self.assertEqual(result.stderr, '')
                self.assertEqual(result.attempts, 1)

    async def test_real_cli_report(self):
        output = self.root / "cli.json"
        import sys

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "swassh",
            "run",
            "printf 'CLI-ok'",
            "-H",
            f"127.0.0.1:{self.port}",
            "-u",
            self.username,
            "-k",
            str(self.root / "client"),
            "--known-hosts",
            str(self.root / "known_hosts"),
            "--format",
            "json",
            "-o",
            str(output),
            "--log-file",
            str(self.root / "audit.jsonl"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        self.assertEqual(process.returncode, 0, stderr.decode())
        self.assertFalse(stdout)
        data = json.loads(output.read_text())
        self.assertEqual(data["results"][0]["stdout"], "CLI-ok")
        self.assertNotEqual(data["report_worker_pid"], process.pid)


    async def _transfer_with_jump(self, backend, *, verify=False):
        from swassh import FileSwarm, FileTransfer, TransferDirection, TransferSettings
        source = self.root / "transfer source"
        remote = self.root / "transfer remote"
        source.write_bytes(b"native SSH transfer\x00" * 100)
        host = Host("127.0.0.1", self.port)
        settings = TransferSettings(rsync_executable="rsync" if backend == "rsync" else "absent-rsync",
                                    verify_sha256=verify)
        options = self.options(jump_host=Host("127.0.0.1", self.port, self.username))
        service = FileSwarm(options, settings)
        pushed = await service.run([host], FileTransfer(TransferDirection.PUSH, str(source), str(remote)))
        self.assertTrue(pushed.ok, pushed.results)
        self.assertEqual(pushed.results[0].transfer.backend, backend)
        self.assertEqual(remote.read_bytes(), source.read_bytes())
        pulled = await service.run([host], FileTransfer(TransferDirection.PULL, str(self.root / "downloads"), str(remote)))
        self.assertTrue(pulled.ok, pulled.results)
        self.assertEqual(Path(pulled.results[0].transfer.local_path).read_bytes(), source.read_bytes())
        if verify:
            for result in (pushed.results[0], pulled.results[0]):
                self.assertIn('SHA-256 verified', result.stdout)
                self.assertIsNone(result.transfer.temporary_path)
            self.assertEqual(remote.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(self.root.glob('.swassh-*.part')), [])

    async def test_real_transfer_sftp_with_jump(self):
        await self._transfer_with_jump("sftp")

    async def test_real_transfer_rsync_with_jump(self):
        self.require_rsync()
        await self._transfer_with_jump("rsync")

    def require_rsync(self):
        """Never substitute a version banner in authenticated network tests."""
        from swassh.infrastructure.transfers import _modern_rsync
        executable = NativeTools.find('rsync')
        if not executable:
            self.skipTest("rsync unavailable")
        banner = subprocess.run([executable, "--version"], capture_output=True, text=True, check=True,
            env=NativeTools.environment()).stdout
        if not _modern_rsync(banner):
            self.skipTest("native rsync below security minimum 3.5.0")
    async def test_real_verified_sftp_push_pull_with_jump(self):
        await self._transfer_with_jump('sftp', verify=True)

    async def test_real_verified_rsync_push_pull_with_jump(self):
        self.require_rsync()
        await self._transfer_with_jump('rsync', verify=True)

    async def test_real_preview_then_delete_push_pull_with_jump(self):
        """Preview leaves both trees unchanged; the following real run deletes."""
        from swassh import FileSwarm, FileTransfer, TransferDirection, TransferSettings
        from swassh.domain.transfers import host_directory
        self.require_rsync()
        host = Host('127.0.0.1', self.port, self.username)
        options = self.options(jump_host=host)
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            root = Path(directory)
            source = root/'source'
            source.mkdir(mode=0o700)
            (source/'added').write_bytes(b'new')
            (source/'changed').write_bytes(b'new contents with different size')
            for path in source.iterdir():
                path.chmod(0o600)
            os.utime(source, ns=(1000000000000000000, 1000000000000000000))

            def snapshot(folder):
                return {str(path.relative_to(folder)): (
                    path.read_bytes() if path.is_file() else None,
                    path.stat().st_mtime_ns, path.stat().st_mode)
                    for path in [folder, *folder.rglob('*')]}

            for direction in (TransferDirection.PUSH, TransferDirection.PULL):
                with self.subTest(direction=direction):
                    local = root/direction.value
                    local.mkdir(mode=0o700)
                    destination = local if direction == TransferDirection.PUSH else local/host_directory(host)
                    if destination != local:
                        destination.mkdir(mode=0o700)
                    (destination/'changed').write_bytes(b'old')
                    (destination/'deleted').write_bytes(b'delete only on the real run')
                    for path in destination.iterdir():
                        path.chmod(0o600)
                    os.utime(destination, ns=(1000000000000000000, 1000000000000000000))
                    request = (FileTransfer(direction, str(source)+'/', str(destination)+'/')
                               if direction == TransferDirection.PUSH else
                               FileTransfer(direction, str(local), str(source)+'/'))
                    before_source, before_destination = snapshot(source), snapshot(destination)
                    report = await FileSwarm(options, TransferSettings(dry_run=True)).run([host], request)
                    self.assertTrue(report.ok, report.results)
                    result = report.results[0]
                    self.assertEqual(result.stdout, 'preview only: added=1 changed=1 deleted=1')
                    self.assertIsNone(result.transfer.bytes_transferred)
                    self.assertEqual(snapshot(source), before_source)
                    self.assertEqual(snapshot(destination), before_destination)
                    copied = await FileSwarm(options, TransferSettings()).run([host], request)
                    self.assertTrue(copied.ok, copied.results)
                    self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()},
                                     {p.name: p.read_bytes() for p in source.iterdir()})
