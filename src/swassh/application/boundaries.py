"""Optional invocation boundary for default and injected use cases."""
from contextlib import asynccontextmanager


@asynccontextmanager
async def invocation(service):
    if service._invocation_factory is None:
        yield
    else:
        async with service._invocation_factory(service.options):
            yield
