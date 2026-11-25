"""Bounded binary channel receipts and explicit loopback forwarding contracts."""
from dataclasses import dataclass, field

from .models import Host, Status


@dataclass(frozen=True, slots=True)
class ChannelCapture:
    """All bytes observed on a channel, including bytes already read by its owner."""
    status: Status
    exit_code: int | None
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    error: str | None = None

    def __post_init__(self):
        if (not isinstance(self.status,Status)
                or self.exit_code is not None and type(self.exit_code) is not int
                or not isinstance(self.stdout,bytes) or not isinstance(self.stderr,bytes)
                or self.error is not None and not isinstance(self.error,str)):
            raise ValueError('invalid binary channel capture types')
        if self.status==Status.SUCCESS and self.exit_code!=0:
            raise ValueError('binary channel success requires a confirmed zero exit code')

    @property
    def ok(self):
        return self.status == Status.SUCCESS


@dataclass(frozen=True, slots=True)
class LocalForward:
    """Expose a declared destination only on an explicit local loopback port.

    The destination is resolved from the SSH server. Local users who can reach
    the listening port can use the tunnel; destination authentication still
    belongs to that service. Port zero and wildcard bindings are refused.
    """
    local_port: int
    remote_host: str
    remote_port: int
    bind_address: str = '127.0.0.1'

    def __post_init__(self):
        if self.bind_address not in ('127.0.0.1', '::1'):
            raise ValueError('SSH forwards require an explicit IPv4 or IPv6 loopback bind')
        for port in (self.local_port, self.remote_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('forwarding ports must be integers in 1..65535')
        destination = Host(self.remote_host, self.remote_port)
        if '%' in destination.hostname:
            raise ValueError('scoped IPv6 destinations are unavailable for SSH forwarding')
        object.__setattr__(self, 'remote_host', destination.hostname)

    @property
    def argument(self):
        bind = '[' + self.bind_address + ']' if ':' in self.bind_address else self.bind_address
        target = '[' + self.remote_host + ']' if ':' in self.remote_host else self.remote_host
        return f'{bind}:{self.local_port}:{target}:{self.remote_port}'
