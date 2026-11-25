"""Literal SSH network endpoint validation without result or typing imports."""
import ipaddress
import re


class Endpoint:
    """Normalize DNS/IP names and reject invalid ports before socket creation."""
    __slots__=('hostname','port')

    def __init__(self,hostname,port):
        object.__setattr__(self,'hostname',hostname)
        object.__setattr__(self,'port',port)
        if not isinstance(self.hostname, str) or not self.hostname:
            raise ValueError("hostname must be nonempty")
        if ":" in self.hostname:
            address, _, scope = self.hostname.partition("%")
            try:
                normalized = str(ipaddress.IPv6Address(address))
            except ValueError as exc:
                raise ValueError("invalid IPv6 address") from exc
            if "%" in self.hostname and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", scope):
                raise ValueError("invalid IPv6 scope")
            object.__setattr__(self, "hostname", normalized + ("%" + scope if "%" in self.hostname else ""))
        else:
            try:
                ascii_name = self.hostname.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("invalid international hostname") from exc
            if any(not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
                   for label in ascii_name.rstrip(".").split(".")):
                raise ValueError("invalid DNS hostname")
            object.__setattr__(self, "hostname", ascii_name)
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("port must be an integer between 1 and 65535")
        if len(self.hostname) > 253:
            raise ValueError("hostname exceeds 253 characters")

    def __setattr__(self,name,value):
        raise AttributeError('SSH endpoint is immutable')
