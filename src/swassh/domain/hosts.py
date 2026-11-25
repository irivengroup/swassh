"""Validated immutable SSH endpoint, independent from execution results."""
from __future__ import annotations

import re
from .endpoints import Endpoint
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class Host:
    hostname: str
    port: int = 22
    username: str | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        endpoint=Endpoint(self.hostname,self.port)
        object.__setattr__(self,'hostname',endpoint.hostname)
        if self.username is not None and (
            not isinstance(self.username, str)
            or not re.fullmatch(r"[A-Za-z0-9_.\\-]{1,256}", self.username)
        ):
            raise ValueError("username contains unsupported characters")
        for name, value in (("username", self.username), ("label", self.label)):
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
            ):
                raise ValueError(
                    f"{name} must be a nonempty string without control characters"
                )

    @property
    def target(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        prefix = f"{self.username}@" if self.username else ""
        return f"{prefix}{host}:{self.port}"


# Preserve the established pickle and introspection identity. models re-exports
# this exact class; importing a relay endpoint need not build result objects.
Host.__module__='swassh.domain.models'


