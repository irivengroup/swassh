"""Native invocation preparation and byte-accounting ownership."""
from contextlib import asynccontextmanager

from .bastion import invocation_budget, specification, _io
from .bandwidth import SQLiteByteBudget


@asynccontextmanager
async def native_invocation_budget(options):
    """Prepare local accounting before accepting native target operations.

    Like the invocation memory database, the byte schema is local preflight:
    initialize/migrate it once per invocation, before any SSH process or remote
    connection can start. Each command still bounds its complete guardian and
    OpenSSH startup with the unchanged command_timeout.
    """
    async with invocation_budget(options):
        opened=[]
        def prepare():
            opened.append(SQLiteByteBudget(specification(options)))
            # Finish schema-creation maintenance during local preflight. The
            # bounded WAL starts empty, with its owner still open for targets.
            with opened[0]._serialized():
                opened[0]._checkpoint(force=True)
        try:
            await _io(prepare)
            # Keep the validated WAL open for the invocation. Helpers do not
            # recreate/checkpoint its files on every target's critical path.
            # No transaction or token reservation is retained by this handle.
            yield
        finally:
            # _io joins a cancelled opener before this cleanup observes it.
            if opened:
                await _io(opened[0].close)
