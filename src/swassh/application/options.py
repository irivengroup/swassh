"""Validated execution configuration, shared by use cases and adapters."""

from __future__ import annotations

import math
import codecs
import re
from dataclasses import dataclass

from ..domain.models import Host
from .profiles import HostProfile


# Match the literal C0/C1 controls in the native regex engine. Keep the
# historical iterator check for string subclasses as an additional constraint;
# a custom iterator must never conceal controls in the actual string payload.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True, slots=True)
class Options:
    concurrency: int = 32
    connect_timeout: float = 10.0
    command_timeout: float = 60.0
    retries: int = 0
    retry_delay: float = 0.5
    max_output_bytes: int = 65_536
    connect_rate: float = 20.0
    memory_budget_mib: int = 128
    max_report_mib: int = 1024
    username: str | None = None
    client_keys: tuple[str, ...] = ()
    known_hosts: str | None = None
    jump_host: Host | None = None
    log_file: str | None = None
    ssh_executable: str = "ssh"
    report_timeout: float = 60.0
    canary: int = 1
    budget_dir: str | None = None
    bastion_concurrency: int = 32
    bastion_connect_rate: float = 20.0
    bastion_memory_mib: int = 512
    bastion_bandwidth_kib: int = 10240
    adaptive: bool = False
    circuit_threshold: int = 5
    progress_interval: float = 0.0
    show_output: bool = True
    output_lines: int = 10
    encoding: str = 'utf-8'
    stdin_file: str | None = None
    stdin_sha256: str | None = None
    max_stdin_bytes: int = 1048576
    stream_output: bool = False
    stream_rate: int = 100
    host_profiles: tuple[HostProfile, ...] = ()
    auth_method: str = 'publickey'
    askpass_executable: str | None = None
    pty: bool = False

    def __post_init__(self) -> None:
        if type(self.pty) is not bool:
            raise ValueError('pty must be boolean')
        if self.auth_method not in ('publickey', 'password', 'gssapi'):
            raise ValueError('auth_method must be publickey, password or gssapi')
        if self.askpass_executable is not None and (not isinstance(self.askpass_executable, str) or not self.askpass_executable):
            raise ValueError('askpass executable must be a nonempty path')
        if self.auth_method == 'password' and self.askpass_executable is None:
            raise ValueError('password authentication requires an external askpass provider')
        if not isinstance(self.encoding, str):
            raise ValueError('encoding must name a text codec')
        try:
            codec = codecs.lookup(self.encoding)
            if not getattr(codec, '_is_text_encoding', False):
                raise ValueError('encoding must be a text codec')
            decoder = codec.incrementaldecoder(errors='replace')
            if not isinstance(decoder.decode(b'', final=True), str):
                raise ValueError('encoding must be a text codec')
            'swassh'.encode(self.encoding)
        except (LookupError, TypeError, UnicodeError) as exc:
            raise ValueError('unsupported text encoding') from exc
        if type(self.stream_output) is not bool or type(self.stream_rate) is not int or not 1 <= self.stream_rate <= 10000:
            raise ValueError('stream output requires a boolean and rate 1..10000')
        if type(self.max_stdin_bytes) is not int or not 1 <= self.max_stdin_bytes <= 16 * 1024**2:
            raise ValueError('stdin budget must be 1..16777216 bytes')
        if self.stdin_file is not None and (not isinstance(self.stdin_file, str) or not self.stdin_file):
            raise ValueError('stdin_file must be a nonempty path')
        if self.stdin_sha256 is not None and (self.stdin_file is None or not isinstance(self.stdin_sha256, str)
                or not re.fullmatch('[0-9a-f]{64}', self.stdin_sha256)):
            raise ValueError('stdin digest requires a file and lowercase SHA-256')
        if not isinstance(self.host_profiles, tuple) or len(self.host_profiles) > 10000 or any(
                not isinstance(profile, HostProfile) for profile in self.host_profiles):
            raise ValueError('host_profiles must contain at most 10000 HostProfile values')
        if len({profile.endpoint for profile in self.host_profiles}) != len(self.host_profiles):
            raise ValueError('duplicate profile endpoint')
        # Validate every override using the same contracts as invocation settings.
        if self.host_profiles:
            from dataclasses import replace
            profile_bytes = 0
            for profile in self.host_profiles:
                replace(self, host_profiles=(), **profile.overrides())
                profile_bytes += 256 + len(profile.hostname.encode('utf-8'))
                profile_bytes += sum(len(value.encode('utf-8')) for value in (
                    profile.username or '', profile.known_hosts or '', profile.encoding or '', *(profile.client_keys or ())))
                if profile_bytes > 4 * 1024**2:
                    raise ValueError('profile metadata exceeds its 4 MiB budget')
        if type(self.show_output) is not bool:
            raise ValueError('show_output must be boolean')
        if type(self.output_lines) is not int or not 0 <= self.output_lines <= 10000:
            raise ValueError('output_lines must be an integer between 0 and 10000')
        for name, minimum in (
            ("concurrency", 1),
            ("canary", 1),
            ("retries", 0),
            ("max_output_bytes", 1),
            ("memory_budget_mib", 8),
            ("max_report_mib", 1),
            ("bastion_concurrency", 1),
            ("bastion_memory_mib", 72),
            ("bastion_bandwidth_kib", 1),
            ("circuit_threshold", 1),
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        if self.canary > 100_000:
            raise ValueError("canary must be <= 100000")
        if self.concurrency > 10000 or self.retries > 10:
            raise ValueError("concurrency <= 10000 and retries <= 10 are required")
        if self.bastion_memory_mib > 1048576 or self.bastion_bandwidth_kib > 2147483647:
            raise ValueError("shared memory or bandwidth ceiling exceeds supported range")
        if self.bastion_concurrency > 10000 or self.circuit_threshold > 10000:
            raise ValueError("bastion_concurrency and circuit_threshold must be <= 10000")
        if type(self.adaptive) is not bool:
            raise ValueError("adaptive must be boolean")
        if (isinstance(self.progress_interval, bool) or not isinstance(self.progress_interval, (int, float))
                or not 0 <= self.progress_interval <= 86400 or not math.isfinite(self.progress_interval)
                or 0 < self.progress_interval < 1):
            raise ValueError("progress_interval must be zero or finite and >= 1 second")
        if (isinstance(self.bastion_connect_rate, bool)
                or not isinstance(self.bastion_connect_rate, (int, float))
                or not 0.1 <= self.bastion_connect_rate <= 1000):
            raise ValueError("bastion_connect_rate must be between 0.1 and 1000")
        if self.jump_host and self.bastion_concurrency < 2:
            raise ValueError("ProxyJump needs two shared connection slots")
        for name in (
            "connect_timeout",
            "command_timeout",
            "report_timeout",
            "retry_delay",
            "connect_rate",
        ):
            value = getattr(self, name)
            if not isinstance(value, (float, int)) or isinstance(value, bool):
                raise ValueError(f"{name} must be numeric")
            try:
                finite = math.isfinite(value)
            except OverflowError as exc:
                raise ValueError(f"{name} is outside the supported numeric range") from exc
            if (
                not finite
                or value < 0
                or (name != "retry_delay" and value == 0)
            ):
                raise ValueError(
                    f"{name} must be finite and positive (retry_delay may be zero)"
                )
        effective_rate = self.connect_rate / (2 if self.jump_host else 1)
        if effective_rate == 0 or not math.isfinite(1 / effective_rate):
            raise ValueError('connect_rate is too small to define a finite admission interval')
        if not isinstance(self.client_keys, tuple) or any(
            not isinstance(key, str) or not key for key in self.client_keys
        ):
            raise ValueError("client_keys must be a tuple of nonempty paths")
        if self.known_hosts is not None and (
            not isinstance(self.known_hosts, str) or not self.known_hosts
        ):
            raise ValueError(
                "known_hosts must be a nonempty path or None for the default file"
            )
        if self.log_file is not None and (
            not isinstance(self.log_file, str) or not self.log_file
        ):
            raise ValueError("log_file must be a nonempty path or None")
        if self.username is not None:
            Host("validation", username=self.username)
        if not isinstance(self.ssh_executable, str) or not self.ssh_executable:
            raise ValueError(
                "ssh_executable must be a nonempty executable name or path"
            )
        if self.budget_dir is not None and (not isinstance(self.budget_dir, str) or not self.budget_dir):
            raise ValueError("budget_dir must be a nonempty path or None")
        for path in (*self.client_keys, self.known_hosts, self.log_file, self.budget_dir, self.stdin_file, self.askpass_executable):
            if path is not None and (len(path.encode("utf-8")) > 4096
                    or _CONTROL_CHARACTERS.search(path) is not None
                    or (type(path) is not str
                        and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in path))
                    or "${" in path):
                raise ValueError("configuration paths must be literal and contain no controls")
        if self.jump_host is not None and not isinstance(self.jump_host, Host):
            raise ValueError("jump_host must be a Host")
