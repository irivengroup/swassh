"""Persistence boundaries for a desired-state mutation's durable intent."""
from typing import AsyncContextManager, Protocol

from ..convergence import DesiredState
from ..models import Host


class ConvergenceLease(Protocol):
    pending: bool

    async def applying(self) -> None: ...
    async def verified(self) -> None: ...
    async def blocked(self) -> None: ...


class ConvergenceJournal(Protocol):
    def scope(self, host: Host, action: DesiredState) -> AsyncContextManager[ConvergenceLease]: ...
    async def aclose(self) -> None: ...
