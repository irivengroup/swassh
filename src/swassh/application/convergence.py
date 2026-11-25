"""Check/apply/verify orchestration over the existing bounded fleet transport."""
from dataclasses import replace
import time

from ..domain.convergence import DesiredState
from ..domain.models import Result, Status
from ..domain.repository.convergence import ConvergenceJournal


class ConvergentTransport:
    """Wrap a transport with a durable per-host operation journal.

    Journal scopes serialize a host/action identity across processes. An intent
    is durable before mutation. An interrupted or failed mutation is reconciled
    only by its read-only postcondition; it is never automatically repeated.
    The outer Swarm retains its canary, resource budgets, audit and reports.
    """

    def __init__(self, transport, action: DesiredState, journal: ConvergenceJournal, *, verify_only=False):
        if not isinstance(action, DesiredState):
            raise TypeError('action must be a DesiredState')
        self.transport, self.action, self.journal = transport, action, journal
        if type(verify_only) is not bool:
            raise TypeError('verify_only must be boolean')
        self.verify_only = verify_only

    def metrics(self):
        measure = getattr(self.transport, 'metrics', None)
        return measure() if measure is not None else {}

    async def aclose(self):
        """Close the underlying transport before releasing durable storage."""
        try:
            close = getattr(self.transport, 'aclose', None)
            if close is not None:
                await close()
        finally:
            await self.journal.aclose()

    async def execute(self, host, command):
        if command != self.action.descriptor:
            raise ValueError('desired-state descriptor does not match its action')
        started, attempts = time.monotonic(), 0
        async with self.journal.scope(host, self.action) as lease:
            pending = lease.pending
            # A pending intent can only be reconciled by verification. A failed
            # verifier is not permission to replay a possibly completed action.
            phases = ('reconcile',) if pending or self.verify_only else ('check', 'apply', 'verify')
            for phase in phases:
                actual = (self.action.check if phase == 'check' else self.action.apply
                          if phase == 'apply' else self.action.verification)
                if phase == 'apply':
                    await lease.applying()
                result = await self.transport.execute(host, actual)
                if not isinstance(result, Result) or result.host != host:
                    raise ValueError('desired-state transport returned a mismatched result')
                attempts += result.attempts
                if phase != 'apply' and result.changed:
                    raise ValueError('read-only desired-state probe declared a mutation')
                success = result.status == Status.SUCCESS and result.exit_code == 0
                if phase == 'check' and result.status == Status.FAILED and result.exit_code == 1:
                    del result  # Do not retain a second capture across phases.
                    continue
                if success:
                    if phase == 'apply':
                        del result
                        continue
                    await lease.verified()
                    return replace(result, changed=phase == 'verify', attempts=attempts,
                                   duration=time.monotonic() - started)
                if phase in ('apply', 'verify') or phase == 'reconcile' and pending:
                    await lease.blocked()
                # A claimed SUCCESS with an incompatible probe exit code must
                # not release the canary. Preserve stronger native failures.
                status = Status.ERROR if result.status in (Status.SUCCESS, Status.SKIPPED) else result.status
                return replace(result, status=status, changed=False,
                               attempts=max(1, attempts), duration=time.monotonic() - started,
                               error='desired-state ' + phase + ' failed; '
                                     + ('no action started' if phase == 'check' else
                                        'remote state requires verification; no automatic replay'))
        raise RuntimeError('desired-state operation produced no result')
