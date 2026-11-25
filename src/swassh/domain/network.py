"""Strict, reviewed device procedures; no guessed firmware or recovery commands.

Device commands remain opaque vendor CLI text. A procedure binds the declared
platform, ordered stages and literal evidence required before advancing.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import re


PLATFORMS = ('cisco_ios', 'cisco_iosxe', 'cisco_nxos', 'juniper_junos',
             'aruba_aoscx', 'aruba_procurve', 'aruba_os', 'huawei_vrp', 'fortinet_fortios')
STAGES = ('identify', 'backup', 'prepare', 'transfer', 'checksum', 'configure',
          'activate', 'verify', 'persist')


def _text(value, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum or any(
            ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError('network text must be nonempty, bounded and without control characters')
    return value


@dataclass(frozen=True, slots=True)
class NetworkStep:
    """One line and its required output; until is an explicit dialogue question.

Empty commands are allowed only as explicit confirmation replies. Expectations
are literal strings checked after removing command echo, never regular expressions.
"""
    stage: str
    command: str
    expect: tuple[str, ...]
    until: str | None = None
    reboot: bool = False
    exact_lines: bool = False

    def __post_init__(self):
        if type(self.exact_lines) is not bool:
            raise ValueError('exact_lines must be boolean')
        if type(self.reboot) is not bool or (self.reboot and (self.stage != 'activate' or self.until is not None)):
            raise ValueError('reboot is an explicit final activation awaiting disconnect, not a question')
        if self.stage not in STAGES:
            raise ValueError('unknown network stage')
        if self.command != '':
            _text(self.command)
        if not isinstance(self.command, str) or not isinstance(self.expect, tuple) or len(self.expect) > 16:
            raise ValueError('invalid network command or expectations')
        for value in self.expect:
            _text(value, 512)
        if self.reboot and not self.expect:
            raise ValueError('reboot requires explicit acceptance evidence before disconnection')
        if self.until is not None:
            _text(self.until, 256)


@dataclass(frozen=True, slots=True)
class ReconnectPolicy:
    """Bounded connection-only retries after a reviewed firmware reboot.

    No command is retried: once verification starts, any failure is terminal.
    The invocation command timeout remains the outer deadline.
    """
    attempts: int = 3
    timeout: float = 120
    interval: float = 2

    def __post_init__(self):
        if type(self.attempts) is not int or not 1 <= self.attempts <= 60:
            raise ValueError('reconnect attempts must be 1..60')
        for value, minimum, maximum in ((self.timeout, 1, 3600), (self.interval, 0.1, 60)):
            if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
                raise ValueError('invalid bounded reconnect deadline or interval')

    def to_dict(self):
        return {'attempts': self.attempts, 'timeout': self.timeout, 'interval': self.interval}


@dataclass(frozen=True, slots=True)
class NetworkProcedure:
    """Immutable procedure; administration is also explicitly reviewed.

The operation label is not a read-only authorization boundary: vendor commands
are not interpreted. Every live invocation requires a matching review digest.
"""
    platform: str
    operation: str
    steps: tuple[NetworkStep, ...]
    image_sha256: str | None = None
    model: str | None = None
    current_version: str | None = None
    target_version: str | None = None
    recovery: str | None = None
    reconnect: ReconnectPolicy | None = None

    def __post_init__(self):
        if self.platform not in PLATFORMS or self.operation not in ('administration', 'configuration', 'file', 'firmware'):
            raise ValueError('unknown network platform or operation')
        if not isinstance(self.steps, tuple) or not 1 <= len(self.steps) <= 1000 or any(
                not isinstance(step, NetworkStep) for step in self.steps):
            raise ValueError('network procedure requires 1..1000 steps')
        text_bytes = sum(len(value.encode('utf-8')) for step in self.steps
                         for value in (step.command, *step.expect, step.until or ''))
        if text_bytes > 1048576:
            raise ValueError('network procedure text exceeds 1 MiB')
        stages = [step.stage for step in self.steps]
        if stages[0] != 'identify' or sorted(stages, key=STAGES.index) != stages:
            raise ValueError('network stages must start with identify and follow their defined order')
        required = {'administration': {'identify'},
                    'configuration': {'identify', 'backup', 'configure', 'verify'},
                    'file': {'identify', 'transfer', 'checksum', 'verify'},
                    'firmware': {'identify', 'backup', 'transfer', 'checksum', 'activate', 'verify'}}[self.operation]
        if not required <= set(stages):
            raise ValueError('network procedure lacks a mandatory stage')
        for stage in required:
            if not any(step.expect for step in self.steps if step.stage == stage):
                raise ValueError('each mandatory stage needs explicit output evidence')
        if self.operation in ('file', 'firmware'):
            if not isinstance(self.image_sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.image_sha256):
                raise ValueError('file and firmware procedures require a lowercase SHA-256')
            if not any(self.image_sha256 in step.expect for step in self.steps if step.stage == 'checksum'):
                raise ValueError('checksum stage must expect the exact SHA-256')
        elif self.image_sha256 is not None:
            raise ValueError('image SHA-256 applies only to file and firmware operations')
        if self.operation == 'firmware':
            for value in (self.model, self.current_version, self.target_version, self.recovery):
                _text(value, 512)
            if self.current_version == self.target_version:
                raise ValueError('firmware target version must differ from the current version')
            for value in (self.model, self.current_version):
                if not any(value in step.expect for step in self.steps if step.stage == 'identify'):
                    raise ValueError('firmware identity stage must verify model and current version')
            if not any(self.target_version in step.expect for step in self.steps if step.stage == 'verify'):
                raise ValueError('firmware verification must assert the target version')
        elif any(value is not None for value in (self.model, self.current_version, self.target_version, self.recovery)):
            raise ValueError('firmware identity and recovery fields apply only to firmware operations')
        if self.steps[-1].until is not None:
            raise ValueError('a procedure must finish at a device prompt, not an unanswered question')
        for index, step in enumerate(self.steps):
            if step.command == '' and (index == 0 or self.steps[index-1].until is None):
                raise ValueError('an empty command is only an explicit confirmation response')
        reboot_indices = [index for index, step in enumerate(self.steps) if step.reboot]
        if self.reconnect is None:
            if reboot_indices:
                raise ValueError('reboot requires an explicit reconnect policy')
        else:
            if not isinstance(self.reconnect, ReconnectPolicy) or self.operation != 'firmware' or len(reboot_indices) != 1:
                raise ValueError('reconnect requires exactly one firmware reboot')
            after = self.steps[reboot_indices[0]+1:]
            if not after or any(step.stage != 'verify' for step in after):
                raise ValueError('only verification steps may follow a reboot')
            if any(step.until is not None for step in after):
                raise ValueError('post-reboot verification cannot answer interactive questions')
            if not any(self.model in step.expect for step in after):
                raise ValueError('post-reboot verification must also verify the device model')
            for stage, values in (('identify', (self.model, self.current_version)),
                                  ('verify', (self.model, self.target_version))):
                for value in values:
                    if not any(step.exact_lines and value in step.expect for step in self.steps if step.stage == stage):
                        raise ValueError('reboot identity/version evidence must match complete output lines')

    @classmethod
    def decode(cls, data):
        """Decode bounded UTF-8 JSON with duplicate and unknown key rejection."""
        if not isinstance(data, bytes) or len(data) > 1048576:
            raise ValueError('network procedure exceeds 1 MiB')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate network property')
                result[key] = value
            return result
        try:
            raw = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
        except RecursionError as exc:
            raise ValueError('network JSON nesting is excessive') from exc
        if not isinstance(raw, dict) or set(raw) - {'platform', 'operation', 'steps', 'image_sha256', 'model', 'current_version', 'target_version', 'recovery', 'reconnect'} or not {'platform', 'operation', 'steps'} <= set(raw):
            raise ValueError('invalid network procedure schema')
        if not isinstance(raw['steps'], list) or not 1 <= len(raw['steps']) <= 1000:
            raise ValueError('invalid network steps')
        steps = []
        for row in raw['steps']:
            if not isinstance(row, dict) or set(row) - {'stage', 'command', 'expect', 'until', 'reboot', 'exact_lines'} or not {'stage', 'command', 'expect'} <= set(row):
                raise ValueError('invalid network step schema')
            if not isinstance(row['expect'], list):
                raise ValueError('network expectations must be an array')
            steps.append(NetworkStep(**(row | {'expect': tuple(row['expect'])})))
        reconnect = raw.get('reconnect')
        if reconnect is not None:
            if not isinstance(reconnect, dict) or set(reconnect) != {'attempts', 'timeout', 'interval'}:
                raise ValueError('reconnect must explicitly define attempts, timeout and interval')
            reconnect = ReconnectPolicy(**reconnect)
        return cls(raw['platform'], raw['operation'], tuple(steps), reconnect=reconnect, **{key: raw.get(key) for key in
            ('image_sha256', 'model', 'current_version', 'target_version', 'recovery')})

    def to_dict(self):
        """Return a deterministic, inspectable plan; it must not contain secrets."""
        result = {'platform': self.platform, 'operation': self.operation,
                'image_sha256': self.image_sha256,
                'model': self.model, 'current_version': self.current_version,
                'target_version': self.target_version, 'recovery': self.recovery,
                'steps': [{'stage': step.stage, 'command': step.command,
                           'expect': list(step.expect), 'until': step.until,
                           **({'reboot': True} if step.reboot else {}),
                           **({'exact_lines': True} if step.exact_lines else {})} for step in self.steps]}
        # Preserve the exact rc1 digest for procedures that do not opt in.
        if self.reconnect is not None:
            result['reconnect'] = self.reconnect.to_dict()
        return result

    def digest(self, targets):
        """Bind approval to both immutable procedure content and exact target order."""
        value = {'procedure': self.to_dict(), 'targets': [host.target for host in targets]}
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                        separators=(',', ':')).encode('ascii')).hexdigest()
