"""Await application-owned futures without forwarding caller cancellation."""
import asyncio


async def wait_owned(future):
    """Return/raise the owned future's outcome while leaving it alive on cancel.

    The owner must retain the Future/Task and drain it during cleanup. Unlike
    shield() on affected CPython 3.14 versions, waiting does not install a late
    exception logger that fires even when the owner retrieves that exception.
    This function never changes the loop's exception handler or task flags.
    """
    if not future.done():
        await asyncio.wait((future,))
    return future.result()
