"""Bounded callback-driven stdin over the existing guarded OpenSSH transport."""
import asyncio
import inspect

from ..domain.interaction import OutputEvent


class CommandInput:
    """Write only from the current host callback; never retain for background use.

    send accepts bytes, at most 16384 per call, with a cumulative per-host
    max_stdin_bytes ceiling. close sends EOF; neither method logs input bytes.
    """
    def __init__(self, writer, limit):
        self._writer, self._remaining = writer, limit
        self._active = None
        self._closed = False

    def _check(self):
        if self._closed or self._active is not asyncio.current_task():
            raise ValueError('input is closed or outside its host callback')

    async def send(self, data: bytes) -> None:
        self._check()
        if not isinstance(data, bytes) or len(data) > 16384:
            raise ValueError('input must be bytes with at most 16384 bytes per send')
        if len(data) > self._remaining:
            raise ValueError('interactive input budget exceeded')
        self._remaining -= len(data)
        self._writer.write(data)
        await self._writer.drain()

    def close(self) -> None:
        """Send EOF once; subsequent writes are refused."""
        self._check()
        self._closed = True
        self._writer.close()

    def invalidate(self):
        """Revoke the application capability before process cleanup."""
        self._closed = True
        self._active = None


class Interaction:
    """Serialize callbacks per host, with no unbounded event queue or replay."""
    @staticmethod
    def validate_handler(handler):
        """Reject an invalid callback before any remote command can start."""
        if not (inspect.iscoroutinefunction(handler) or
                inspect.iscoroutinefunction(getattr(handler, '__call__', None))):
            raise ValueError('interaction factory must return an async callback')

    def __init__(self, host, writer, limit, handler):
        self.validate_handler(handler)
        self.host, self.handler = host, handler
        self.input = CommandInput(writer, limit)
        self.lock = asyncio.Lock()

    async def emit(self, stream, data=b'', *, eof=False):
        async with self.lock:
            self.input._active = asyncio.current_task()
            try:
                await self.handler(OutputEvent(self.host, stream, data, eof), self.input)
            except Exception:
                # User exceptions may contain credentials or remote output.
                # The normal transport reports a controlled ERROR, never success.
                raise ValueError('interactive callback failed') from None
            finally:
                self.input._active = None
