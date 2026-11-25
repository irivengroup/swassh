"""Public desired-state fleet API with unchanged canary and report contracts."""
from contextlib import aclosing

from ..application.options import Options
from ..bootstrap import ConvergenceFactory
from ..domain.convergence import DesiredState
from ..infrastructure.convergence import load_desired_state
from .api import Swarm


class ConvergentSwarm:
    """Converge a fleet with explicit check/apply/verify and durable no-replay.

    Construction performs no storage or network I/O. Native execution stores
    private intents under the shared budget directory. Custom transport/journal
    factories are trusted extensions and must preserve their declared contracts.
    """

    def __init__(self, action: DesiredState, options: Options | None = None, *,
                 transport_factory=None, journal_factory=None):
        if not isinstance(action, DesiredState):
            raise TypeError('action must be a DesiredState')
        if options is not None and not isinstance(options, Options):
            raise TypeError('options must be Options')
        self.action, self.options = action, options or Options()
        if self.options.retries or self.options.stdin_file or self.options.pty:
            raise ValueError('desired-state execution requires retries=0, no stdin file and no PTY')
        for factory in (transport_factory, journal_factory):
            if factory is not None and not callable(factory):
                raise TypeError('desired-state factories must be callable')
        self._service = Swarm(self.options, transport_factory=ConvergenceFactory(
            action, transport_factory, journal_factory))
        self._verification_service = Swarm(self.options, transport_factory=ConvergenceFactory(
            action, transport_factory, journal_factory, verify_only=True))

    @classmethod
    def from_file(cls, path, options=None, **factories):
        """Read a strict bounded JSON specification; never execute while loading."""
        return cls(load_desired_state(path), options, **factories)

    def plan(self):
        return self._service.plan()

    async def run(self, hosts):
        """Return an in-memory Report for a bounded small fleet."""
        return await self._service.run(hosts, self.action.descriptor)

    async def run_to_file(self, hosts, path, format='json', *, spool_dir=None):
        """Stream a mass-fleet report through the existing bounded disk writer."""
        return await self._service.run_to_file(hosts, self.action.descriptor,
                                             path, format, spool_dir=spool_dir)

    async def verify(self, hosts):
        """Reconcile only by the postcondition; never execute the action."""
        return await self._verification_service.run(hosts, self.action.descriptor)

    async def verify_to_file(self, hosts, path, format='json', *, spool_dir=None):
        """Bounded verification report, preserving ambiguous mutation evidence."""
        return await self._verification_service.run_to_file(hosts, self.action.descriptor,
                                                          path, format, spool_dir=spool_dir)

    async def iter_results(self, hosts):
        """Yield completed host results; close the iterator on early exit."""
        async with aclosing(self._service.iter_results(hosts, self.action.descriptor)) as results:
            async for result in results:
                yield result
