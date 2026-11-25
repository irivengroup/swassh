"""Short-lived I/O guardian: owns admission until all native descendants stop."""
from __future__ import annotations

import json
import math
import os
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from contextlib import contextmanager
from contextvars import ContextVar

from .bastion import SharedBudget, specification, current_reservation

_RELAY=ContextVar('swassh_native_relay',default=None)
_NATIVE_LIFETIME=ContextVar('swassh_native_lifetime',default=None)


@contextmanager
def native_relay(request,lifetime):
    """Scope internal relay metadata without changing the process-call seam."""
    token=_RELAY.set((request,lifetime) if request is not None else None)
    lifetime_token=_NATIVE_LIFETIME.set(lifetime)
    try:
        yield
    finally:
        _NATIVE_LIFETIME.reset(lifetime_token)
        _RELAY.reset(token)


async def launch_native(*argv, options, bandwidth=0, connected=True, max_native_seconds=None, **kwargs):
    """Return an asyncio Process. Its private parent pipe is closed by cleanup."""
    # The guardian's synchronous process entry must not initialize an unused
    # event loop/TLS stack before launching SSH. Only its async caller needs it.
    import asyncio
    from .lifecycle import finish_task
    from ..application.task_ownership import wait_owned
    relay=None
    if scope:=_RELAY.get():
        relay,_=scope
    relay_lifetime=_NATIVE_LIFETIME.get()
    if relay_lifetime is not None:
        max_native_seconds=relay_lifetime if max_native_seconds is None else min(max_native_seconds,relay_lifetime)
    if max_native_seconds is not None and (type(max_native_seconds) not in (int, float)
            or max_native_seconds <= 0 or (type(max_native_seconds) is float and not math.isfinite(max_native_seconds))):
        raise ValueError('native lifetime must be finite and positive')
    kwargs.setdefault("start_new_session", os.name == "posix")
    directory = tempfile.TemporaryDirectory(prefix='swassh-guardian-')
    reader = writer = None
    parent_token = None
    try:
        if os.name == 'posix':
            reader, writer = os.pipe()
            kwargs['pass_fds'] = (reader,)
        else:
            from .windows import ParentProcess
            parent = ParentProcess(os.getpid())
            try:
                parent_token = parent.token
            finally:
                parent.close()
        data = {'argv': list(argv), 'budget': specification(options),
            'connections': (2 if options.jump_host else 1) if connected else 0,
            'bandwidth': bandwidth if connected else 0, 'parent_pid': os.getpid(),
            'parent_token': parent_token, 'parent_fd': reader, 'invocation': current_reservation(),
            'max_native_seconds': max_native_seconds,'relay':relay,
            'admission_wait_limit': max_native_seconds}
        request = Path(directory.name) / 'request.json'
        with request.open('x', encoding='utf-8') as stream:
            request.chmod(0o600)
            json.dump(data, stream, ensure_ascii=True, allow_nan=False)
        # This call is deliberately separate from SSHTransport's direct test seams.
        creating = asyncio.create_task(asyncio.create_subprocess_exec(sys.executable, '-m',
            'swassh.infrastructure.process_guard', str(request), **kwargs))
        try:
            process = await wait_owned(creating)
        except asyncio.CancelledError:
            process = await finish_task(creating)
            async def abort():
                if process.returncode is None:
                    if os.name == 'posix':
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    else:
                        process.terminate()  # Closing the guardian kills its job.
                    try:
                        async with asyncio.timeout(2):
                            await process.wait()
                    except TimeoutError:
                        process.kill()
                        await process.wait()
            await finish_task(asyncio.create_task(abort()))
            raise
        process._swassh_guardian = (writer, directory)
        process._swassh_admission_observation = max_native_seconds is not None
        process._swassh_guardian_started = time.monotonic()
        if reader is not None:
            os.close(reader)
        return process
    except BaseException:
        for fd in (reader, writer):
            if fd is not None:
                os.close(fd)
        directory.cleanup()
        raise


def release_guardian(process):
    state = getattr(process, '_swassh_guardian', None)
    if state:
        writer, directory = state
        process._swassh_guardian = None
        try:
            if writer is not None:
                os.close(writer)
        finally:
            # A close error may follow descriptor release; never retry that fd.
            # The private request directory still belongs to this cleanup.
            directory.cleanup()


def native_metrics(process):
    state = getattr(process, '_swassh_guardian', None)
    if not state:
        return {}
    try:
        with (Path(state[1].name) / 'metrics.json').open('rb') as stream:
            raw = stream.read(1025)
        value = json.loads(raw)
        if (len(raw) > 1024 or set(value) != {'admission_wait_seconds', 'native_seconds'}
                or any(type(v) not in (int, float) or not 0 <= v < 1e12 for v in value.values())):
            return {}
        return value
    except (OSError, ValueError, TypeError):
        return {}


class _GroupAbsence:
    """Require kernel ESRCH within the existing grace; EPERM alone is no proof.

    Darwin excludes zombies while selecting signalable group members and can
    return EPERM until their group is reaped. Probe with signal zero only: a
    live or persistently inaccessible group remains a cleanup failure.
    """

    def __init__(self, group, deadline):
        self.group = group
        self.deadline = deadline

    def _absent(self):
        try:
            os.killpg(self.group, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    def confirmed(self):
        while time.monotonic() < self.deadline:
            if self._absent():
                # A delayed observation must not grant cleanup after expiry.
                return time.monotonic() <= self.deadline
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.025, remaining))
        return False


def _stop_native(process):
    if os.name == 'posix':
        deadline = time.monotonic() + 0.35
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            except PermissionError:
                if _GroupAbsence(process.pid, deadline).confirmed():
                    # Do not send another signal after confirmed disappearance;
                    # the numeric group id could subsequently be reused.
                    break
                raise
            if sig == signal.SIGTERM:
                try:
                    process.wait(timeout=0.35)
                except subprocess.TimeoutExpired:
                    pass
    elif process.poll() is None:
        process.kill()
    process.wait()


def main(path):
    with open(path, 'rb') as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError('guardian request too large')
    data = json.loads(raw)
    required = {'argv', 'budget', 'connections', 'bandwidth', 'parent_pid', 'parent_token', 'parent_fd', 'invocation'}
    if (not isinstance(data, dict) or not required <= set(data)
            or set(data) - required - {'max_native_seconds','relay','admission_wait_limit'} or not isinstance(data['argv'], list)
            or not data['argv'] or any(not isinstance(v, str) or '\0' in v for v in data['argv'])):
        raise ValueError('invalid guardian request')
    lifetime = data.get('max_native_seconds')
    if lifetime is not None and (type(lifetime) not in (int, float) or lifetime <= 0
            or (type(lifetime) is float and not math.isfinite(lifetime))):
        raise ValueError('invalid guardian lifetime')
    queue_limit = data.get('admission_wait_limit')
    if queue_limit is not None:
        try:
            if type(queue_limit) not in (int, float) or queue_limit <= 0 or not math.isfinite(queue_limit):
                raise ValueError
        except (ValueError, OverflowError):
            raise ValueError('invalid guardian admission limit') from None
    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    parent = None
    if os.name == 'posix':
        fd = data['parent_fd']
        if type(fd) is not int or fd < 3:
            raise ValueError('invalid guardian control pipe')
        def alive():
            return not stopped and not select.select([fd], [], [], 0)[0]
    else:
        from .windows import KillJob, ParentProcess
        job = KillJob()  # Join before spawning any descendant; retain the handle.
        parent = ParentProcess(data['parent_pid'], data['parent_token'])
        def alive():
            return not stopped and parent.alive()
    pool = lease = process = relay = None
    exit_code = 125
    started = None
    entered = time.monotonic()
    try:
        if not alive():
            return 125
        if data['connections'] or data['invocation']:
            pool = SharedBudget(data['budget'])
            lease = pool.ticket(connections=data['connections'], bandwidth=data['bandwidth'], parent=data['invocation'], activate=True)
            queued_at = None
            while not lease.poll():
                if not alive():
                    return 125
                if queue_limit is not None:
                    from .admission_deadline import publish_admission
                    if queued_at is None:
                        queued_at = time.monotonic()
                        publish_admission(Path(path).parent, 'queued', 0.0)
                    remaining = (entered + queue_limit) - time.monotonic()
                    if remaining <= 0:
                        publish_admission(Path(path).parent, 'expired', queue_limit)
                        return 125
                    time.sleep(min(lease.retry_after, remaining))
                else:
                    time.sleep(lease.retry_after)
            queue_seconds = time.monotonic() - queued_at if queued_at is not None else 0.0
        else:
            queue_seconds = 0.0
        if not alive():
            return 125
        if queue_limit is not None:
            from .admission_deadline import publish_admission
            if time.monotonic() - entered >= queue_limit:
                publish_admission(Path(path).parent, 'expired', queue_limit)
                return 125
        argv=data['argv']
        if data.get('relay') is not None:
            if os.name!='posix' or data['connections']!=1 or pool is None:
                raise ValueError('guardian relay requires one admitted POSIX connection')
            from .socket_relay import GuardianRelay
            relay=GuardianRelay(data['relay'],pool)
            argv=relay.arguments(argv)
        if queue_limit is not None:
            # Local resource/relay preparation is admission, not remote SSH
            # execution. Publish its completion immediately before native spawn.
            if time.monotonic() - entered >= queue_limit:
                publish_admission(Path(path).parent, 'expired', queue_limit)
                return 125
            publish_admission(Path(path).parent, 'admitted', queue_seconds)
        started = time.monotonic()
        # The parent supplies DEVNULL, a bounded input pipe, or an interactive TTY.
        # Inherit that descriptor without reading ahead or mixing in credentials.
        process = subprocess.Popen(argv, stdin=sys.stdin,
            stdout=sys.stdout, stderr=sys.stderr, close_fds=True,
            start_new_session=os.name == 'posix')
        if os.name == 'posix':
            # The native child owns a separate group; relay terminal resizes
            # without weakening termination or the parent-death guardian.
            def resize(signum, frame):
                try:
                    os.killpg(process.pid, signal.SIGWINCH)
                except ProcessLookupError:
                    pass
            signal.signal(signal.SIGWINCH, resize)
        while process.poll() is None:
            if relay is not None and relay.failed.is_set():
                if relay.connection_failure is not None and '-E' in data['argv']:
                    from .filesystem import open_private_append
                    diagnostic=data['argv'][data['argv'].index('-E')+1]
                    marker=('connection timed out' if relay.connection_failure=='timeout' else 'connection refused')
                    # The private diagnostic channel is trusted, unlike remote
                    # stderr. Record only the proven pre-connect classification,
                    # without endpoint, exception text, credentials or command.
                    with open_private_append(diagnostic) as stream:
                        stream.write('swassh guardian: '+marker+' before authentication\n')
                return 125
            if not alive():
                return 125
            # A blocked parent output/event loop must not keep a persistent
            # connection alive beyond its declared lifetime.
            limit = data.get('max_native_seconds')
            if limit is not None and time.monotonic() - started >= limit:
                return 125
            time.sleep(0.025)
        exit_code = process.returncode if process.returncode >= 0 else 128 - process.returncode
        return exit_code
    finally:
        metrics = {'admission_wait_seconds': (started or time.monotonic()) - entered,
            'native_seconds': time.monotonic() - started if started is not None else 0.0}
        metrics_path = Path(path).parent / 'metrics.json'
        try:
            with metrics_path.open('x', encoding='utf-8') as stream:
                metrics_path.chmod(0o600)
                json.dump(metrics, stream, allow_nan=False)
        except OSError:
            pass  # A lost metric can never prevent descendant cleanup.
        if os.name == 'nt':
            # Terminate the job including this guardian before its OS-lock lease
            # can be released. No descendant can outlive a reclaimed client slot.
            sys.stdout.flush()
            sys.stderr.flush()
            job.terminate(exit_code)
        if process is not None:
            _stop_native(process)
        if relay is not None:
            relay.close()
        if lease:
            lease.close()
        if pool:
            pool.close()
        if parent:
            parent.close()
        # Windows closes the job at OS process exit, killing surviving descendants.
        # Its lease MUST remain held until that happens: see Windows exit below.


if __name__ == '__main__':
    try:
        code = main(sys.argv[1])
    except (OSError, ValueError, sqlite3.Error, RuntimeError):
        # Never echo the command, paths, credentials or exception details.
        sys.stderr.write('swassh: native guardian admission or process error\n')
        code = 125
    raise SystemExit(code)
