"""Reviewed network procedures through the existing bounded fleet engine."""
import hmac
import re
from pathlib import Path

from ..application.options import Options
from ..application.profiles import ProfileResolver
from ..domain.network import NetworkProcedure
from ..infrastructure.execution_input import InputSnapshot
from ..infrastructure.network import NetworkTransport
from ..infrastructure.resources import resource_plan
from .api import Swarm


class NetworkSwarm:
    """Plan locally, then apply the exact procedure digest to exact targets.

    Different device families or versions need separate reviewed procedures.
    Existing SSH, file and scheduling APIs retain their original contracts.
    """
    def __init__(self, procedure, options=None):
        if not isinstance(procedure, NetworkProcedure):
            raise ValueError('a validated NetworkProcedure is required')
        self.procedure, self.options = procedure, options or Options()
        if self.options.stdin_file or self.options.stream_output or self.options.retries:
            raise ValueError('network procedures reject stdin, streaming and retries')

    @classmethod
    def from_file(cls, path, options=None):
        """Snapshot a bounded regular file before any network activity."""
        return cls(NetworkProcedure.decode(InputSnapshot.read(Path(path), 1048576)), options)

    def plan(self, hosts):
        """Return reviewable commands, targets, digest and resource ceilings."""
        targets = self._targets(hosts)
        return {'procedure': self.procedure.to_dict(), 'targets': [host.target for host in targets],
                'approval_sha256': self.procedure.digest(targets),
                'resources': resource_plan(self.options, guarded=True).to_dict(),
                'canary_count': min(self.options.canary, len(targets)),
                'qualification': 'protocol tests do not certify hardware or firmware versions',
                'disconnect_policy': ('explicit firmware reboot; bounded connection-only retries; no command replay'
                                      if self.procedure.reconnect else 'unknown remote state; no reconnect or replay')}

    def _approved(self, hosts, approval):
        targets = self._targets(hosts)
        expected = self.procedure.digest(targets)
        if not isinstance(approval, str) or not re.fullmatch('[0-9a-f]{64}', approval) or not hmac.compare_digest(expected, approval):
            raise ValueError('network approval does not match procedure and targets')
        return targets

    def _targets(self, hosts):
        profiles = ProfileResolver(self.options)
        targets = profiles.targets(hosts)
        for encoding in {profiles.for_host(host).encoding for host in targets}:
            if 'CLI\n'.encode(encoding) != b'CLI\n':
                raise ValueError('network CLI requires an ASCII-compatible encoding')
            # Validate all commands before the first connection/mutation, not
            # halfway through a configuration when a late character is invalid.
            for step in self.procedure.steps:
                step.command.encode(encoding)
        return targets

    def _swarm(self):
        return Swarm(self.options, transport=NetworkTransport(self.options, self.procedure))

    async def run(self, hosts, *, approval):
        """Apply once and return existing grouped reports; never retry commands."""
        targets = self._approved(hosts, approval)
        return await self._swarm().run(targets, 'network:' + self.procedure.digest(targets))

    async def run_to_file(self, hosts, path, format='json', *, approval, spool_dir=None):
        """Stream reports with existing canary and bounded spool processing."""
        targets = self._approved(hosts, approval)
        return await self._swarm().run_to_file(targets, 'network:' + self.procedure.digest(targets),
                                              path, format, spool_dir=spool_dir)
