"""Single-owner async scopes for binary SSH channels and local-only tunnels."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
import uuid

from ..application.options import Options
from ..application.profiles import ProfileResolver
from ..domain.channels import LocalForward
from ..domain.commands import validate_command
from ..infrastructure.audit import AuditTrail
from ..infrastructure.bastion import independent_invocation
from ..infrastructure.native_budget import native_invocation_budget as invocation_budget
from ..infrastructure.channels import NativeSSHScope, NativeChannel
from ..infrastructure.resources import resource_plan
from .session import _ACTIVE


class _ScopedConnection:
    def __init__(self, host, options, lifetime):
        if options is not None and not isinstance(options,Options):
            raise TypeError('options must be Options')
        options = options if options is not None else Options()
        if options.retries or options.stdin_file or options.pty or options.stream_output or options.progress_interval or options.adaptive:
            raise ValueError('native scopes require retries=0, no stdin file, PTY, live text output or fleet admission overrides')
        self.options=replace(options,concurrency=1)
        self.host,=ProfileResolver(self.options).targets([host])
        self.lifetime=lifetime
        self.used=False
        self.owner=self.stack=self.token=self.native=self.channel=None
        self.run_id=uuid.uuid4().hex

    async def _enter(self, *, command=None, forward=None):
        if self.used or _ACTIVE.get():
            raise RuntimeError('native scopes are single-use and cannot be nested or inherited')
        self.used=True
        self.owner=asyncio.current_task()
        resource_plan(self.options,guarded=True)
        self.stack=AsyncExitStack()
        self.token=_ACTIVE.set(True)
        try:
            self.stack.enter_context(independent_invocation())
            await self.stack.enter_async_context(invocation_budget(self.options))
            self.audit=await self.stack.enter_async_context(AuditTrail(self.options.log_file,self.run_id))
            await self.audit.emit('ssh_scope_opening',{'mode':'tunnel' if forward else 'channel','host':self.host.target})
            await self.audit.flush()
            self.native=NativeSSHScope(self.host,self.options,self.lifetime,command=command,forward=forward)
            self.stack.push_async_callback(self._audit_closed)
            self.stack.push_async_callback(self.native.aclose)
            await self.native.open()
            if command is not None:
                self.channel=NativeChannel(self.native)
                self.stack.push_async_callback(self.channel.aclose)
            await self.audit.emit('ssh_scope_opened',{'mode':'tunnel' if forward else 'channel'})
        except BaseException:
            try:
                await self.stack.aclose()
            finally:
                _ACTIVE.reset(self.token)
                self.token=None
            raise
        return self

    async def _audit_closed(self):
        await self.audit.emit('ssh_scope_closed', {'failure_observed': bool(self.native.failure or
            self.channel is not None and self.channel.failure)})

    async def __aexit__(self,kind,value,traceback):
        if asyncio.current_task() is not self.owner:
            raise RuntimeError('exit a native scope from the task which entered it')
        try:
            return await self.stack.__aexit__(kind,value,traceback)
        finally:
            _ACTIVE.reset(self.token)
            self.token=None


class SSHChannel(_ScopedConnection):
    """Bounded binary command stream with send/read/EOF and complete capture.

    Use ``async with SSHChannel(host, command, options)``. Read stdout and stderr
    concurrently when consuming live output. ``wait`` drains unread fragments
    and returns a ChannelCapture containing all observed bytes. Closing early
    stops native descendants; a remote command may continue on its server.
    """

    def __init__(self,host,command,options=None):
        validate_command(command)
        self.command=command
        # Validate the shared scope settings before reading an option field.
        # The normalized copy also supplies the command deadline exactly once.
        super().__init__(host,options,None)
        self.lifetime=self.options.command_timeout

    async def __aenter__(self):
        return await self._enter(command=self.command)

    def _open(self):
        if self.channel is None:
            raise RuntimeError('enter the SSHChannel context first')
        return self.channel

    async def send(self,data:bytes):
        """Send at most 16384 bytes per call within max_stdin_bytes in total."""
        await self._open().send(data)

    def close_input(self):
        """Send EOF without closing the output streams."""
        self._open().close_input()

    async def read(self,stream='stdout'):
        return await self._open().read(stream)

    async def wait(self):
        return await self._open().wait()


class SSHTunnel(_ScopedConnection):
    """An authenticated local TCP forward with an active lifetime (1..3600 s).

    Readiness proves SSH authentication and local listener creation. It does
    not prove reachability or authentication of the destination service.
    Startup is separately bounded by connect_timeout + report_timeout; the
    native guardian also enforces that total ceiling if the event loop stalls.
    """

    def __init__(self,host,forward:LocalForward,options=None,*,lifetime=300):
        if not isinstance(forward,LocalForward):
            raise TypeError('forward must be a LocalForward')
        self.forward=forward
        super().__init__(host,options,lifetime)

    async def __aenter__(self):
        return await self._enter(forward=self.forward)

    async def wait(self):
        """Wait for termination; an unexpected closure or deadline is an error."""
        if self.native is None or self.native.directory is None:
            raise RuntimeError('enter the SSHTunnel context first')
        await self.native.process.wait()
        if self.native.failure:
            raise OSError(self.native.failure)
        raise OSError('SSH tunnel closed; destination availability is unknown')

    @property
    def is_open(self):
        return bool(self.native is not None and self.native.directory is not None
                    and self.native.process.returncode is None and self.native.failure is None)
