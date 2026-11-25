"""Bounded live JSON lines on stderr, isolated from slow terminal writes."""
import asyncio
import json
import sys
import time
from .process_guard import launch_native, release_guardian
from .lifecycle import finish_task


class LiveOutput:
    """One guarded writer per invocation; rate overflow is counted explicitly.

    A stalled pipe raises an I/O error instead of hanging the event loop.
    Remote output is JSON escaped so terminal control sequences stay inert.
    """
    def __init__(self, options):
        self.options = options
        self.process = None
        self.lock = asyncio.Lock()
        self.tokens = float(options.stream_rate)
        self.updated = time.monotonic()
        self.dropped = 0

    async def start(self):
        """Start the guarded writer once, before launching remote commands."""
        async with self.lock:
            if self.process is None:
                async with asyncio.timeout(self.options.report_timeout):
                    self.process = await launch_native(sys.executable, '-m',
                        'swassh.infrastructure.live_output', options=self.options, connected=False,
                        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL)

    async def emit(self, host, channel, text, *, continued=False):
        """Send at most 1024 characters; aggregate rate overflow is observable."""
        now = time.monotonic()
        self.tokens = min(self.options.stream_rate, self.tokens + (now-self.updated)*self.options.stream_rate)
        self.updated = now
        if self.tokens < 1:
            self.dropped += 1
            return
        self.tokens -= 1
        await self._write({'host': host.target, 'stream': channel, 'text': text,
                           'continued': continued})

    async def _write(self, event):
        # The lock bounds asyncio's write buffer across all hosts. Its timeout
        # also bounds a stalled consumer; no queue or unbounded background task.
        async with asyncio.timeout(2):
            async with self.lock:
                if self.process is None or self.process.returncode is not None:
                    raise OSError('live output writer unavailable')
                self.process.stdin.write((json.dumps(event, ensure_ascii=True)+'\n').encode('ascii'))
                await self.process.stdin.drain()

    async def close(self):
        """Flush the final sampling summary or forcibly stop the guarded writer."""
        process = self.process
        if process is None:
            return
        try:
            await self._write({'event': 'stream_finished', 'dropped_events': self.dropped})
            process.stdin.close()
            async with asyncio.timeout(self.options.report_timeout):
                await process.wait()
            if process.returncode:
                raise OSError('live output writer failed')
        finally:
            async def stop():
                if process.returncode is None:
                    process.terminate()
                    try:
                        async with asyncio.timeout(2):
                            await process.wait()
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                release_guardian(process)
                self.process = None
            await finish_task(asyncio.create_task(stop()))


def main():
    """Copy bounded, already escaped parent events; never interpret their text."""
    while line := sys.stdin.buffer.readline(16385):
        if len(line) > 16384 or not line.endswith(b'\n'):
            raise ValueError('live event exceeded protocol budget')
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()


if __name__ == '__main__':
    main()
