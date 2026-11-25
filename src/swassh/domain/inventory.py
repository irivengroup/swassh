"""Inventory invariants and target parsing; no file or format dependency."""

from __future__ import annotations

from collections.abc import Iterable

from .hosts import Host
from .errors import InventoryError

MAX_HOSTS = 100_000


def _parse_port(value: str) -> int:
    """Convert a port without retaining untrusted input in public exceptions.

    Preserve int's established numeric syntax; Host still enforces the range.
    Raise after leaving the conversion handler so neither the public message
    nor its exception chain retains a potentially confidential inventory value.
    """
    try:
        return int(value)
    except ValueError:
        pass
    raise InventoryError("invalid SSH port") from None


def parse_host(value: str) -> Host:
    """Parse [user@]host[:port], requiring brackets around IPv6 with a port."""
    value = value.strip()
    if value.count("@") > 1:
        raise InventoryError("host string contains multiple username separators")
    username, separator, address = value.rpartition("@")
    if separator and not username:
        raise InventoryError("username separator requires a username")
    if not separator:
        address, username = value, ""
    port = 22
    if address.startswith("["):
        end = address.find("]")
        if end == -1:
            raise InventoryError("unclosed IPv6 brackets")
        hostname, tail = address[1:end], address[end + 1 :]
        if ":" not in hostname:
            raise InventoryError("brackets are reserved for IPv6 addresses")
        if tail:
            if not tail.startswith(":"):
                raise InventoryError("invalid bracketed address")
            port = _parse_port(tail[1:])
    elif address.count(":") == 1:
        hostname, port_text = address.rsplit(":", 1)
        port = _parse_port(port_text)
    else:
        hostname = address
    try:
        return Host(hostname, port, username or None)
    except ValueError as exc:
        raise InventoryError(str(exc)) from exc


def normalize_hosts(values: Iterable[Host | str]) -> tuple[Host, ...]:
    hosts: dict[str, Host] = {}
    for number, value in enumerate(values, 1):
        if number > MAX_HOSTS:
            raise InventoryError("inventory contains too many input records")
        host = parse_host(value) if isinstance(value, str) else value
        if not isinstance(host, Host):
            raise InventoryError("hosts must contain Host objects or strings")
        if host.target in hosts and hosts[host.target] != host:
            raise InventoryError(f"conflicting duplicate target: {host.target}")
        hosts.setdefault(host.target, host)
        # At most one dictionary entry is added per bounded input record.
    if not hosts:
        raise InventoryError("inventory contains no hosts")
    return tuple(hosts.values())


