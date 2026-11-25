"""Immutable endpoint-specific connection overrides, never resource policies."""
from dataclasses import dataclass, replace
from ..domain.models import Host
from ..domain.inventory import normalize_hosts


@dataclass(frozen=True, slots=True)
class HostProfile:
    """Match one canonical hostname/port; None inherits the invocation setting."""
    hostname: str
    port: int = 22
    username: str | None = None
    client_keys: tuple[str, ...] | None = None
    known_hosts: str | None = None
    connect_timeout: float | None = None
    command_timeout: float | None = None
    encoding: str | None = None
    auth_method: str | None = None

    def __post_init__(self):
        host = Host(self.hostname, self.port, self.username)
        object.__setattr__(self, 'hostname', host.hostname)

    @property
    def endpoint(self):
        """Identity used for exact matching, without wildcard evaluation."""
        return self.hostname, self.port

    def overrides(self):
        """Return only supplied connection overrides."""
        return {name: getattr(self, name) for name in (
            'username', 'client_keys', 'known_hosts', 'connect_timeout', 'command_timeout', 'encoding', 'auth_method')
            if getattr(self, name) is not None}


class ProfileResolver:
    """Resolve in O(1) per host and retain explicit inventory usernames."""
    def __init__(self, options):
        self.options = options
        self.profiles = {profile.endpoint: profile for profile in options.host_profiles}
        self.settings = {key: replace(options, host_profiles=(), **profile.overrides())
                         for key, profile in self.profiles.items()}

    def for_host(self, host):
        """Get settings for a host; global concurrency and jump policy survive."""
        return self.settings.get((host.hostname, host.port), self.options)

    def targets(self, hosts):
        """Apply user precedence before deduplication, canary selection and audit."""
        targets = normalize_hosts(hosts)
        if not self.profiles and self.options.username is None:
            return targets
        return normalize_hosts(replace(host, username=host.username or self.for_host(host).username)
                               for host in targets)
