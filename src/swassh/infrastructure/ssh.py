"""OpenSSH system adapter; Python standard library only."""

from __future__ import annotations

from ..application.task_ownership import wait_owned

import asyncio
import codecs
import math
import os
import re
import secrets
import signal
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..domain.models import Host, Result, Status
from ..application.options import Options
from ..application.pacing import ConnectionPacer
from .lifecycle import finish_task, ensure_subprocess_loop, NativeStagingDirectory
from ..application.profiles import ProfileResolver
from .execution_input import InputSnapshot
from .live_output import LiveOutput
from .authentication import Authentication
from .tcp_proxy import proxy_command

DIAGNOSTIC_LIMIT = 131072


def _diagnostic_bytes(path):
    """Read the same bounded bytes; retain precise Win32 sharing refusals.

    The CRT file opener can collapse sharing violations into plain EACCES.
    The existing native opener distinguishes those from an ACL denial and
    refuses reparse points. POSIX keeps its existing file-opening behavior.
    """
    if os.name == 'nt':
        from .windows import open_file_without_reparse
        descriptor = open_file_without_reparse(path, os.O_RDONLY)
        with os.fdopen(descriptor, 'rb') as stream:
            return stream.read(DIAGNOSTIC_LIMIT + 1)
    with path.open('rb') as stream:
        return stream.read(DIAGNOSTIC_LIMIT + 1)


class _DiagnosticRead:
    """Finish a bounded final read across transient native-handle teardown.

    Only Win32 sharing/lock violations 32/33 receive the same two-second grace
    used by staging cleanup. ACL denials and other I/O errors remain failures.
    Each reader closes its handle before a retry yields; cancellation owns no
    background worker. This bounds retries, not an uninterruptible OS I/O call.
    """
    def __init__(self, reader):
        self.reader = reader

    async def read(self):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 2
        while True:
            try:
                return self.reader()
            except PermissionError as error:
                remaining = deadline - loop.time()
                if os.name != 'nt' or getattr(error, 'winerror', None) not in (32, 33) or remaining <= 0:
                    raise
                await asyncio.sleep(min(0.01, remaining))


@dataclass(slots=True)
class _Buffer:
    limit: int
    data: bytes = b""
    truncated: bool = False
    encoding: str = 'utf-8'
    live: object = None
    observer: object = None

    async def consume(self, stream: asyncio.StreamReader) -> None:
        chunks: list[bytes] = []
        retained = 0
        decoder = codecs.getincrementaldecoder(self.encoding)(errors='replace')
        pending = ''
        async def publish(text, final=False):
            nonlocal pending
            pending += text
            while pending:
                newline = pending.find('\n', 0, 1024)
                length = newline + 1 if newline >= 0 else min(1024, len(pending))
                if newline < 0 and len(pending) < 1024 and not final:
                    break
                piece, pending = pending[:length], pending[length:]
                await self.live(piece, continued=newline < 0 and not final)
        try:
            while chunk := await stream.read(4096 if self.observer else 65536):
                available = self.limit - retained
                if available:
                    chunks.append(chunk[:available])
                    if self.live:
                        # Decode and split bounded slices: even one enormous line
                        # cannot create an unbounded event or terminal write.
                        for offset in range(0, min(len(chunk), available), 1024):
                            await publish(decoder.decode(chunk[offset:min(offset+1024, available)]))
                retained += min(len(chunk), available)
                self.truncated |= len(chunk) > available
                if self.observer:
                    if self.truncated:
                        raise ValueError('interactive output budget exceeded')
                    await self.observer(chunk, eof=False)
            if self.observer:
                await self.observer(b'', eof=True)
            if self.live:
                await publish(decoder.decode(b'', final=True), final=True)
        finally:
            self.data = b"".join(chunks)

    @property
    def text(self) -> str:
        return self.data.decode(self.encoding, errors="replace")


def _quote(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("SSH configuration values cannot contain line breaks or NUL")
    value = value.replace("%", "%%")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _config(host: Host, options: Options, target_options=None, *, wire_lifetime=None) -> str:
    target_options = target_options or ProfileResolver(options).for_host(host)
    def settings_lines(settings):
        lines = [f"  ConnectTimeout {math.ceil(settings.connect_timeout)}",
                 "  UserKnownHostsFile " + _quote(str(Path(settings.known_hosts or "~/.ssh/known_hosts").expanduser()))]
        lines.extend("  IdentityFile " + _quote(str(Path(key).expanduser())) for key in settings.client_keys)
        if settings.client_keys:
            lines.append("  IdentitiesOnly yes")
        return lines + Authentication.directives(settings)
    lines = ["Host swassh-target", f"  HostName {_quote(host.hostname)}",
             f"  Port {host.port}", "  LogLevel DEBUG1"]
    if username := host.username or target_options.username:
        lines.append(f"  User {_quote(username)}")
    lines += settings_lines(target_options)
    if options.jump_host is None:
        lines.append('  ProxyCommand ' + proxy_command(host,options,
            lifetime=wire_lifetime if wire_lifetime is not None else target_options.command_timeout))
    if options.jump_host:
        jump = options.jump_host
        lines += ["  ProxyJump swassh-jump", "Host swassh-jump",
                  f"  HostName {_quote(jump.hostname)}", f"  Port {jump.port}", "  LogLevel ERROR"]
        if username := jump.username or options.username:
            lines.append(f"  User {_quote(username)}")
        lines += settings_lines(options)
        lines.append('  ProxyCommand ' + proxy_command(jump,options,
            lifetime=wire_lifetime if wire_lifetime is not None else target_options.command_timeout))
    lines += [
        "Host *",
        "  PermitLocalCommand no",
        "  StrictHostKeyChecking yes",
        "  UpdateHostKeys no",
        "  VerifyHostKeyDNS no",
        "  AddKeysToAgent no",
        "  Tunnel no",
        "  EscapeChar none",
        "  ForwardAgent no",
        "  ForwardX11 no",
        "  ClearAllForwardings yes",
        "  RequestTTY no",
        "  ControlMaster no",
        "  ControlPath none",
        "  GlobalKnownHostsFile none",
        "  ConnectionAttempts 1",
        "  ServerAliveInterval 5",
        "  ServerAliveCountMax 2",
    ]
    return "\n".join(lines) + "\n"


def _command_diagnostic(diagnostic: str, command: str | None) -> str:
    """Omit the echoed command record from the classification copy only.

    OpenSSH 7.3+ logs at most 900 UTF-8 command bytes in client_session2_setup.
    Its stderr logger preserves LF inside that text and appends one record LF.
    Counting those known payload LFs keeps an apparent exit receipt inside a
    multiline command from becoming evidence. Byte truncation matters for
    Unicode and a final payload LF. Raw diagnostics and remote output remain
    unchanged, and the command-start marker survives an incomplete log record.
    """
    if command is None:
        return diagnostic
    record = re.search(r"(?m)^debug[123]: Sending command: ", diagnostic)
    if record is None:
        return diagnostic
    end = record.start()
    for _ in range(command.encode('utf-8')[:900].count(b'\n') + 1):
        newline = diagnostic.find('\n', end)
        if newline < 0:
            end = len(diagnostic)
            break
        end = newline + 1
    return diagnostic[:record.start()] + 'debug1: Sending command: [omitted]\n' + diagnostic[end:]


def _outcome(
    code: int, diagnostic: str, complete_diagnostic: bool, auth_method: str = 'publickey'
) -> tuple[Status, str | None, bool]:
    """Only verified pre-authentication failures may be retried.

    Private OpenSSH diagnostics are separate from remote stderr. A remote command
    exiting 255 or printing a network-looking error cannot trigger another execution.
    """
    started = any(
        marker in diagnostic.lower()
        for marker in (
            "authenticated to ",
            "authentication succeeded",
            "sending command:",
            "entering interactive session",
        )
    )
    if not complete_diagnostic:
        return (
            Status.ERROR,
            "SSH diagnostic limit exceeded; remote state may be unknown",
            False,
        )
    if code == 0:
        return Status.SUCCESS, None, False
    if started:
        # OpenSSH logs the command as text too. Only a whole exit-status
        # non-negative record consistent with the native result confirms remote
        # failure. Negative native codes identify local process signals.
        if re.search(rf"(?m)^(?:debug[123]: )?Exit status (?=[0-9]){code}\r?$", diagnostic):
            return Status.FAILED, None, False
        return (
            Status.INTERRUPTED,
            "SSH transport interrupted; remote state may be unknown",
            False,
        )
    lowered = diagnostic.lower()
    if auth_method == 'gssapi' and 'gssapi' in lowered and any(word in lowered for word in ('unsupported option', 'bad configuration option')):
        return Status.AUTH_FAILED, 'OpenSSH client does not support the requested GSSAPI options', False
    # A normal password prompt also mentions askpass in DEBUG1. Only an explicit
    # helper execution error identifies a provider failure rather than a denial.
    if auth_method == 'password' and 'ssh_askpass: exec(' in lowered:
        return Status.AUTH_FAILED, 'SSH password provider failed; verify its availability and non-interactive secret retrieval', False
    if "remote host identification has changed" in lowered:
        return Status.HOST_KEY_FAILED, "SSH server key changed; verify its fingerprint before updating known_hosts", False
    if "host key verification failed" in lowered:
        return Status.HOST_KEY_FAILED, "SSH server key is untrusted or unknown; verify its fingerprint and known_hosts", False
    for markers, message in (
        (("bad permissions", "unprotected private key file"), "SSH private key permissions rejected; restrict access to its owner"),
        (("invalid format", "error in libcrypto"), "SSH private key could not be loaded; verify its format locally"),
        (("agent refused operation", "sign_and_send_pubkey: signing failed"), "SSH signing failed; check the agent and unlock the selected identity"),
        (("incorrect passphrase", "read_passphrase:", "can't open /dev/tty"), "SSH key needs unlocking; load it into an agent before non-interactive execution"),
    ):
        if auth_method == 'publickey' and any(marker in lowered for marker in markers):
            return Status.AUTH_FAILED, message, False
    if "permission denied" in lowered or "no supported authentication methods" in lowered:
        if auth_method == 'password':
            return Status.AUTH_FAILED, 'SSH password authentication denied; verify account, provider and server policy', False
        if auth_method == 'gssapi':
            return Status.AUTH_FAILED, 'SSH GSSAPI authentication denied; verify tickets, service principal, clock and server policy', False
        return Status.AUTH_FAILED, "SSH authentication denied; verify remote user (-u), identity (-k), agent and authorized_keys; passwords are disabled", False
    if "connection timed out" in lowered or "operation timed out" in lowered:
        return Status.TIMEOUT, "SSH connection deadline exceeded", True
    if any(
        marker in lowered
        for marker in (
            "connection refused",
            "no route to host",
            "network is unreachable",
            "could not resolve hostname",
            "connection closed",
            "connection reset",
            "name or service not known",
        )
    ):
        return Status.UNREACHABLE, "SSH connection failed before authentication", True
    return (
        Status.ERROR,
        "SSH client failed; check executable, keys and configuration",
        False,
    )


async def _stop(process: asyncio.subprocess.Process) -> None:
    if os.name == "posix":
        # A reaped leader can still have children holding pipes or ProxyJump open.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            async with asyncio.timeout(2):
                await process.wait()
        except TimeoutError:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()
    elif process.returncode is None:
        process.terminate()
        try:
            async with asyncio.timeout(2):
                await process.wait()
        except TimeoutError:
            process.kill()
            await process.wait()


async def _cleanup_process(process, tasks) -> dict:
    async def clean():
        metrics = {}
        try:
            if process is not None:
                await _stop(process)
                metrics = native_metrics(process)
                release_guardian(process)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return metrics
    cleanup = asyncio.create_task(clean())
    try:
        return await wait_owned(cleanup)
    except asyncio.CancelledError:
        await finish_task(cleanup)
        raise


from .process_guard import launch_native, release_guardian, native_metrics, native_relay
from .preflight import LocalPreflight


class SSHTransport:
    def channel_arguments(self):
        """Native channel overrides; persistent adapters may bind a private master."""
        return []

    def channel_connected(self):
        """Whether this process owns a new network connection reservation."""
        return True

    def classify(self, code, diagnostic, complete, auth_method):
        """Classify direct SSH execution without replaying an ambiguous command."""
        return _outcome(code, diagnostic, complete, auth_method)

    def __init__(self, options: Options, *, interaction_factory=None):
        if interaction_factory is not None and (options.stdin_file or options.retries):
            raise ValueError('interaction requires no stdin_file and retries=0')
        self.interaction_factory = interaction_factory
        self.options = options
        self._admission_wait_seconds = self._native_seconds = 0.0
        self.executable = LocalPreflight().transport(options)
        self.profiles = ProfileResolver(options)
        if os.name=='posix' and options.jump_host is None and options.auth_method!='gssapi':
            from .relay_connect import NativeConnector
            self.relay_connector=NativeConnector.find()
        else:
            self.relay_connector=None
        self.input = InputSnapshot.stdin(options)
        self.live = LiveOutput(options) if options.stream_output else None
        self._pacer = ConnectionPacer(
            options.connect_rate / (2 if options.jump_host else 1)
        )

    def metrics(self):
        return {"shared_admission_wait_seconds": self._admission_wait_seconds,
                "native_client_seconds": self._native_seconds,
                "stream_dropped_events": self.live.dropped if self.live else 0}

    async def aclose(self):
        """Stop the optional live writer after all workers have been cancelled."""
        if self.live:
            await self.live.close()

    async def _feed(self, writer):
        """Send the same immutable bytes to each target with pipe backpressure."""
        try:
            for offset in range(0, len(self.input), 16384):
                writer.write(self.input[offset:offset+16384])
                await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # A remote command may intentionally close stdin early.
        finally:
            writer.close()

    async def execute(self, host: Host, command: str) -> Result:
        if self.live:
            await self.live.start()
        started = time.monotonic()
        attempt = 0
        while True:
            attempt += 1
            await self._pacer.acquire()
            result, retryable = await self._attempt(host, command, attempt, started)
            if retryable and attempt <= self.options.retries:
                base = min(self.options.retry_delay * 2 ** (attempt - 1), 30)
                await asyncio.sleep(base * (0.5 + secrets.randbelow(501) / 1000))
            else:
                return result

    async def _attempt(
        self, host: Host, command: str, attempt: int, started: float
    ) -> tuple[Result, bool]:
        settings = self.profiles.for_host(host)
        stdout, stderr = (
            _Buffer(self.options.max_output_bytes, encoding=settings.encoding),
            _Buffer(self.options.max_output_bytes, encoding=settings.encoding),
        )
        if self.live:
            async def stdout_event(text, **kwargs):
                await self.live.emit(host, 'stdout', text, **kwargs)
            async def stderr_event(text, **kwargs):
                await self.live.emit(host, 'stderr', text, **kwargs)
            stdout.live, stderr.live = stdout_event, stderr_event
        process = None
        interaction = None
        drains: list[asyncio.Task[None]] = []
        code = None
        retryable = False
        status, error = Status.ERROR, None
        async with NativeStagingDirectory(prefix="swassh-ssh-") as directory:
            config = Path(directory) / "config"
            diagnostic = Path(directory) / "diagnostic"
            config.write_text(_config(host, self.options, settings), encoding="utf-8")
            config.chmod(0o600)
            diagnostic.touch(mode=0o600)

            async def watchdog() -> None:
                while True:
                    await asyncio.sleep(0.1)
                    if diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                        raise ValueError("SSH diagnostic budget exceeded")

            watcher = None
            waiter = None
            try:
                ensure_subprocess_loop()
                env = Authentication.environment(self.options, settings)
                async with asyncio.timeout(settings.command_timeout) as deadline:
                    if self.interaction_factory is not None:
                        from .interaction import Interaction
                        try:
                            handler = self.interaction_factory(host)
                        except Exception:
                            raise ValueError('interaction factory failed') from None
                        Interaction.validate_handler(handler)
                    relay=({'host':host.hostname,'port':host.port,'connect_timeout':settings.connect_timeout,
                            'connector':self.relay_connector}
                           if os.name=='posix' and self.channel_connected() and self.options.jump_host is None
                              and settings.auth_method!='gssapi' else None)
                    with native_relay(relay,settings.command_timeout):
                        process = await launch_native(
                        self.executable,
                        "-F",
                        str(config),
                        "-E",
                        str(diagnostic),
                        *self.channel_arguments(),
                        "-tt" if self.options.pty else "-T",
                        "swassh-target",
                        command,
                        options=self.options,
                        **({} if self.channel_connected() else {'connected': False}),
                        stdin=asyncio.subprocess.PIPE if self.input is not None or self.interaction_factory is not None else asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                        start_new_session=os.name == "posix",
                        limit=65536,
                    )
                    # Refuse a broken pipe contract under every optimization mode.
                    # The existing error boundary and finally own cleanup.
                    if process.stdout is None or process.stderr is None:
                        raise OSError('native SSH streams unavailable')
                    if self.interaction_factory is not None:
                        interaction = Interaction(host, process.stdin, self.options.max_stdin_bytes,
                                                  handler)
                        interaction_ready = asyncio.Event()
                        async def observe_stdout(data, **kwargs):
                            await interaction_ready.wait()
                            await interaction.emit('stdout', data, **kwargs)
                        async def observe_stderr(data, **kwargs):
                            await interaction_ready.wait()
                            await interaction.emit('stderr', data, **kwargs)
                        stdout.observer, stderr.observer = observe_stdout, observe_stderr
                    drains = [
                        asyncio.create_task(stdout.consume(process.stdout)),
                        asyncio.create_task(stderr.consume(process.stderr)),
                    ]
                    if getattr(process, '_swassh_admission_observation', None) is True:
                        from .admission_deadline import AdmissionDeadline
                        admission = AdmissionDeadline(process._swassh_guardian[1].name,
                                                      deadline, settings.command_timeout,
                                                      process._swassh_guardian_started)
                        drains.append(asyncio.create_task(admission.observe(process)))
                    if interaction is not None:
                        async def start_interaction():
                            await interaction.emit('start')
                            interaction_ready.set()
                        drains.append(asyncio.create_task(start_interaction()))
                    if self.input is not None:
                        drains.append(asyncio.create_task(self._feed(process.stdin)))
                    watcher = asyncio.create_task(watchdog())
                    async def completion():
                        await asyncio.gather(process.wait(), *drains)
                        return process.returncode
                    waiter = asyncio.create_task(completion())
                    done, _ = await asyncio.wait(
                        [waiter, watcher], return_when=asyncio.FIRST_COMPLETED
                    )
                    if watcher in done:
                        await watcher
                    code = await waiter
                    await asyncio.gather(*drains)
                raw = await _DiagnosticRead(lambda: _diagnostic_bytes(diagnostic)).read()
                status, error, retryable = self.classify(
                    code, _command_diagnostic(raw.decode("utf-8", "replace"), command),
                    len(raw) <= DIAGNOSTIC_LIMIT, settings.auth_method
                )
            except TimeoutError:
                status, error = (
                    Status.TIMEOUT,
                    "SSH invocation deadline exceeded; remote state may be unknown",
                )
            except (OSError, ValueError):
                status, error = (
                    Status.ERROR,
                    "SSH client I/O or diagnostic error; remote state may be unknown",
                )
            finally:
                if interaction is not None:
                    interaction.input.invalidate()
                metrics = await _cleanup_process(process, drains + [t for t in (watcher, waiter) if t is not None])
                self._admission_wait_seconds += metrics.get("admission_wait_seconds", 0)
                self._native_seconds += metrics.get("native_seconds", 0)

        return Result(
            host,
            status,
            stdout.text,
            stderr.text,
            code,
            error=error,
            attempts=attempt,
            duration=time.monotonic() - started,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
        ), retryable
