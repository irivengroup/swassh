"""Bounded network CLI dialogue over guarded native OpenSSH.

No vendor shell text is passed to a local shell. Unknown prompts, paging,
missing evidence and unexpected disconnects fail closed without command replay.
"""
import asyncio
import codecs
import os
import re
import secrets
import tempfile
import time
from pathlib import Path

from ..domain.models import Result, Status
from ..domain.network import PLATFORMS
from ..application.profiles import ProfileResolver
from .authentication import Authentication
from .lifecycle import ensure_subprocess_loop
from .preflight import LocalPreflight
from .process_guard import launch_native, native_relay
from .ssh import _config, _cleanup_process, _outcome, DIAGNOSTIC_LIMIT


class NetworkDialogueError(ValueError):
    """Controlled diagnostic without echoing commands, credentials or output."""
    def __init__(self, message, output=''):
        super().__init__(message)
        self.output = output


class DeviceDisconnected(NetworkDialogueError):
    """EOF before a normal prompt; never permission to replay a command."""


class NetworkConnectionError(NetworkDialogueError):
    """A classified failure before sending any command on a new connection."""
    def __init__(self, message, status=Status.ERROR, retryable=False):
        super().__init__(message)
        self.status, self.retryable = status, retryable


class DialogueBudget:
    """Aggregate wire bytes across the initial connection and all reconnects."""
    def __init__(self, limit):
        self.remaining = limit


class DeviceDriver:
    """Prompt and error families; model/version support is checked by the plan.

    Firmware syntax, enable passwords and global paging changes are deliberately
    never synthesized from a vendor name. All transmitted commands are reviewed.
    """
    _COMMON = r'(?P<identity>[A-Za-z0-9_.:/@-]{1,128})(?: ?\([^\r\n()]{1,80}\))? ?[#>]'
    _ARUBA = r'(?P<identity>\([A-Za-z0-9_.-]{1,128}\))(?: \[[A-Za-z0-9_.:/-]{1,80}\])?(?: \([^\r\n()]{1,80}\))? ?[#>]'
    _ERROR = re.compile(r'(?im)^\s*(?:%\s*(?:Invalid|Error|Incomplete|Ambiguous|Unknown)|'
                        r'error:|Error:|Error\s+\d|syntax error|Unknown command|'
                        r'Invalid input|Invalid command|Incomplete command|'
                        r'Ambiguous command|Command fail|command parse error|'
                        r'Permission denied|Access denied|Authorization failed|'
                        r'Unknown action|Unrecognized command|Return code -\d)')

    def __init__(self, platform):
        if platform not in PLATFORMS:
            raise ValueError('unsupported network platform')
        self.platform = platform
        pattern = self._ARUBA if platform == 'aruba_os' else self._COMMON
        if platform == 'huawei_vrp':
            pattern = r'(?:<(?P<identity>[A-Za-z0-9_.-]{1,128})>|\[[~*]?(?P<configuration>[A-Za-z0-9_.:/-]{1,200})\])'
        self.pattern = re.compile(pattern)
        self.identity = None

    def prompt(self, line):
        """Recognize only an anchored prompt belonging to this same CLI identity."""
        match = self.pattern.fullmatch(line)
        if match is None:
            return False
        identity = match.groupdict().get('identity')
        configuration = match.groupdict().get('configuration')
        if self.identity is None:
            if identity is None:
                return False  # Huawei must start in user view, not unknown subview.
            self.identity = identity
        return identity == self.identity or (configuration is not None and
                (configuration == self.identity or configuration.startswith(self.identity + '-')))

    @classmethod
    def check(cls, output):
        if cls._ERROR.search(output):
            raise NetworkDialogueError('device rejected the command; remote state may be partially changed', output)


class DeviceDialogue:
    """One reader, strict decoder and an aggregate wire-output ceiling per host."""
    def __init__(self, process, driver, limit, encoding, budget=None):
        self.process, self.driver = process, driver
        self.budget = budget or DialogueBudget(limit)
        self.decoder = codecs.getincrementaldecoder(encoding)(errors='strict')
        self.encoding = encoding

    async def receive(self, *, command=None, until=None, disconnect=False):
        fragments = []
        tail_window = ''
        while True:
            chunk = await self.process.stdout.read(min(4096, self.budget.remaining + 1))
            ended = not chunk
            if ended and not disconnect:
                raise DeviceDisconnected('device connection ended; remote state is unknown; no command replayed')
            self.budget.remaining -= len(chunk)
            if self.budget.remaining < 0:
                raise NetworkDialogueError('device output budget exceeded; remote state may be partially changed')
            decoded = self.decoder.decode(chunk, final=ended)
            fragments.append(decoded)
            tail_window = (tail_window + decoded)[-8192:]
            # Paging is not answered implicitly: a space may otherwise confirm
            # an unrelated destructive prompt. Prepare paging in the runbook.
            if re.search(r'(?i)--\s*more\s*--|press any key|press <space>', tail_window):
                raise NetworkDialogueError('device pagination requires an explicit supported procedure')
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', tail_window).replace('\r', '')
            tail = text.split('\n')[-1].rstrip(' ')
            if ended:
                complete = True
            elif until is not None:
                complete = tail == until
            else:
                complete = self.driver.prompt(tail)
            if not complete:
                continue
            # Join once, not once per packet: large bounded responses must not
            # cause quadratic copying/scanning under mass deployment load.
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', ''.join(fragments)).replace('\r', '')
            if any((ord(char) < 32 and char not in '\n\t') or 127 <= ord(char) <= 159 for char in text):
                raise NetworkDialogueError('unsupported device terminal control sequence')
            body = text if ended else text[:len(text)-len(text.split('\n')[-1])]
            if command is not None:
                lines = body.splitlines()
                # Mandatory echo prevents a stale prompt from completing the
                # next command. Echo is excluded from all success assertions.
                while lines and not lines[0].strip():
                    lines.pop(0)
                if command and (not lines or lines[0].strip() != command):
                    raise NetworkDialogueError('device command echo mismatch; no further commands sent')
                if command:
                    # The preceding echo check proved this first line exists.
                    lines.pop(0)
                body = '\n'.join(lines)
            self.driver.check(body)
            if disconnect and not ended:
                # Some CLIs return their prompt before the reboot actually
                # closes SSH. Wait, without sending another command. Rejected
                # activations are still detected at that intermediate prompt.
                continue
            return body

    async def execute(self, step):
        self.process.stdin.write((step.command + '\n').encode(self.encoding))
        await self.process.stdin.drain()
        output = await self.receive(command=step.command, until=step.until, disconnect=step.reboot)
        for expected in step.expect:
            found = expected in output.splitlines() if step.exact_lines else expected in output
            if not step.exact_lines and step.stage == 'checksum' and re.fullmatch('[0-9a-f]{64}', expected):
                found = re.search(r'(?i)(?<![0-9a-f])' + expected + r'(?![0-9a-f])', output) is not None
            if not found:
                raise NetworkDialogueError('required device response missing; remaining steps blocked', output)
        return output


class NetworkTransport:
    """Execute one reviewed procedure per host under existing shared budgets."""
    _native_guarded = True

    def __init__(self, options, procedure):
        if options.stdin_file or options.stream_output or options.retries:
            raise ValueError('network procedures reject stdin injection, live streaming and retries')
        self.options, self.procedure = options, procedure
        self.profiles = ProfileResolver(options)
        self.executable = LocalPreflight().transport(options)
        if os.name=='posix' and options.jump_host is None and options.auth_method!='gssapi':
            from .relay_connect import NativeConnector
            self.relay_connector=NativeConnector.find()
        else:
            self.relay_connector=None

    async def execute(self, host, command):
        """Apply once; reconnect only for opt-in verification after a reboot."""
        started = time.monotonic()
        settings = self.profiles.for_host(host)
        deadline = asyncio.get_running_loop().time() + settings.command_timeout
        budget = DialogueBudget(self.options.max_output_bytes)
        chunks = []
        phase = 'connect'
        status, error = Status.ERROR, None
        identity = None
        connection_number = 0
        with tempfile.TemporaryDirectory(prefix='swassh-network-') as directory:
            config = Path(directory)/'config'
            config.write_text(_config(host, self.options, settings), encoding='utf-8')
            config.chmod(0o600)

            async def connection(steps, *, reconnecting=False, window_deadline=None):
                nonlocal phase, identity, connection_number
                connection_number += 1
                diagnostic = Path(directory)/f'diagnostic-{connection_number}'
                diagnostic.touch(mode=0o600)
                process = None
                tasks = []
                commands_started = False
                phase = f'reconnect:{connection_number-1}' if reconnecting else 'connect'
                driver = DeviceDriver(self.procedure.platform)
                driver.identity = identity

                async def dialogue():
                    nonlocal phase, identity, commands_started
                    channel = DeviceDialogue(process, driver, self.options.max_output_bytes,
                                             settings.encoding, budget)
                    if reconnecting:
                        # Bound each boot-time handshake, including waiting for
                        # a CLI prompt. No verification command has been sent.
                        try:
                            async with asyncio.timeout(settings.connect_timeout) as handshake:
                                if getattr(process, '_swassh_admission_observation', None) is True:
                                    from .admission_deadline import AdmissionDeadline
                                    admission = AdmissionDeadline(process._swassh_guardian[1].name,
                                        handshake, settings.connect_timeout, process._swassh_guardian_started)
                                    try:
                                        await admission.observe(process)
                                    except ValueError as exc:
                                        raise NetworkDialogueError('invalid local guardian admission') from exc
                                await channel.receive()
                        except TimeoutError as exc:
                            raise NetworkConnectionError('device is not ready for verification',
                                                         Status.TIMEOUT, True) from exc
                    else:
                        await channel.receive()
                    identity = driver.identity
                    for number, step in steps:
                        phase = f'{step.stage}:{number}'
                        commands_started = True
                        output = await channel.execute(step)
                        chunks.append(f'[{phase}]\n{output}\n')

                async def diagnostic_watch():
                    while True:
                        if diagnostic.stat().st_size > DIAGNOSTIC_LIMIT:
                            raise NetworkDialogueError('SSH diagnostic budget exceeded')
                        await asyncio.sleep(0.1)

                try:
                    ensure_subprocess_loop()
                    remaining = min(deadline, window_deadline or deadline) - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise TimeoutError
                    relay=({'host':host.hostname,'port':host.port,'connect_timeout':settings.connect_timeout,
                            'connector':self.relay_connector}
                           if os.name=='posix' and self.options.jump_host is None and settings.auth_method!='gssapi' else None)
                    # Share command execution's guardian-owned relay. Device
                    # prompt/reboot deadlines must not pay for another Python
                    # ProxyCommand startup on each direct POSIX connection.
                    # Addressing, trust, accounting and no-replay rules stay in
                    # the same guardian/OpenSSH boundaries, including reconnects.
                    with native_relay(relay,remaining):
                        process = await launch_native(self.executable, '-F', str(config), '-E', str(diagnostic),
                            '-tt', 'swassh-target', options=self.options,
                            max_native_seconds=remaining,
                            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.DEVNULL,
                            env=Authentication.environment(self.options, settings))
                    work = asyncio.create_task(dialogue())
                    watcher = asyncio.create_task(diagnostic_watch())
                    tasks = [work, watcher]
                    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    if watcher in done:
                        await watcher
                    await work
                except DeviceDisconnected as exc:
                    if commands_started:
                        raise
                    with diagnostic.open('rb') as stream:
                        raw = stream.read(DIAGNOSTIC_LIMIT+1)
                    outcome, detail, preauth_retryable = _outcome(process.returncode if process.returncode is not None else 255,
                        raw.decode('utf-8', errors='replace'), len(raw) <= DIAGNOSTIC_LIMIT, settings.auth_method)
                    # SSH authentication/trust failures never become boot retries.
                    retryable = preauth_retryable or outcome == Status.INTERRUPTED
                    failure = outcome if outcome != Status.SUCCESS else Status.ERROR
                    raise NetworkConnectionError(detail or str(exc), failure, retryable) from exc
                finally:
                    # No next command may race with asynchronous process cleanup.
                    for task in tasks:
                        task.cancel()
                    await _cleanup_process(process, tasks)

            try:
                async with asyncio.timeout_at(deadline):
                    indexed = tuple(enumerate(self.procedure.steps, 1))
                    policy = self.procedure.reconnect
                    if policy is None:
                        await connection(indexed)
                    else:
                        split = next(index for index, step in indexed if step.reboot)
                        await connection(indexed[:split])
                        # The initial guardian and all descendants are gone
                        # before acquiring another shared connection lease.
                        boot_deadline = min(deadline, asyncio.get_running_loop().time() + policy.timeout)
                        async with asyncio.timeout_at(boot_deadline):
                            for attempt in range(1, policy.attempts + 1):
                                phase = f'reconnect:{attempt}'
                                delay = min(60, policy.interval * 2**min(attempt-1, 3) * (1 + secrets.randbelow(251)/1000))
                                await asyncio.sleep(delay)
                                try:
                                    await connection(indexed[split:], reconnecting=True, window_deadline=boot_deadline)
                                    break
                                except NetworkConnectionError as exc:
                                    if not exc.retryable or attempt == policy.attempts:
                                        raise
                                    chunks.append(f'[reconnect:{attempt}] device not ready; no commands sent\n')
                status = Status.SUCCESS
            except TimeoutError:
                status, error = Status.TIMEOUT, 'network procedure deadline exceeded; remote state is unknown'
            except (NetworkDialogueError, UnicodeError, OSError) as exc:
                error = str(exc) if isinstance(exc, NetworkDialogueError) else 'network dialogue I/O failed; remote state is unknown'
                if isinstance(exc, NetworkConnectionError):
                    status = exc.status
                if isinstance(exc, NetworkDialogueError) and exc.output:
                    chunks.append(f'[{phase}]\n{exc.output}\n')
        return Result(host, status, stdout=''.join(chunks), error=(f'{phase}: {error}' if error else None),
                      duration=time.monotonic()-started)
