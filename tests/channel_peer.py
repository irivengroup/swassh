"""Synthetic executable for isolated guardian tests; never implements an SSH server."""
from pathlib import Path
import sys
import time
import threading


class ReadinessCallback:
    """Use the real validator once, with the original three-second bound.

    This peer is already a synthetic executable. A third Python interpreter
    tested subprocess cold startup rather than this guardian's scope lifecycle.
    Native callback entrypoint tests remain separate and unchanged.
    """
    TIMEOUT = 3.0

    def run(self, envelope):
        complete = threading.Event()
        failure = []
        finished = []

        def record():
            try:
                from swassh.infrastructure.native_ready import NativeReady
                NativeReady.record(envelope)
            except BaseException as error:
                failure.append(error)
            finally:
                finished.append(time.monotonic())
                complete.set()

        deadline = time.monotonic() + self.TIMEOUT
        worker = threading.Thread(target=record, daemon=True)
        worker.start()
        complete.wait(max(0., deadline-time.monotonic()))
        worker.join(max(0., deadline-time.monotonic()))
        if worker.is_alive() or not finished or finished[0] > deadline:
            raise TimeoutError('synthetic readiness callback exceeded its deadline')
        if failure:
            raise failure[0]


def main():
    arguments=sys.argv[1:]
    diagnostic=Path(arguments[arguments.index('-E')+1])
    command=arguments[-1]
    if command=='deny':
        diagnostic.write_text('Permission denied (publickey).\n')
        return 255
    text='Authenticated to synthetic-host using publickey.\n'
    if '-L' in arguments:
        forward=arguments[arguments.index('-L')+1]
        # Parsing this controlled fixture is deliberately independent of the
        # production LocalForward; it does not create a listener or destination.
        if forward.startswith('['):
            address,rest=forward[1:].split(']:',1)
        else:
            address,rest=forward.split(':',1)
        port=rest.split(':',1)[0]
        text+=f'Local forwarding listening on {address} port {port}.\n'
    diagnostic.write_text(text)
    # The synthetic authenticated peer honors the same fixed post-auth callback
    # as native Windows OpenSSH. It never acknowledges a denied identity.
    for argument in arguments:
        if argument.startswith('LocalCommand='):
            envelope = argument.rsplit(' ', 1)[-1]
            ReadinessCallback().run(envelope)
    if '-L' in arguments or command=='hang':
        time.sleep(30)
    elif command=='flood':
        sys.stdout.buffer.write(b'x'*131072); sys.stdout.buffer.flush()
    elif command=='large-output':
        sys.stdout.buffer.write(b'x'*1048576); sys.stdout.buffer.flush()
        time.sleep(30)
    elif command=='diagnostic-flood':
        # Confirmed channel entry releases the fault; no scheduler assumption.
        if sys.stdin.buffer.readline(32) != b'diagnostic-flood\n':
            return 125
        diagnostic.write_bytes(b'x'*131073)
        time.sleep(30)
    else:
        data=sys.stdin.buffer.read()
        sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        sys.stderr.buffer.write(b'synthetic-stderr'); sys.stderr.buffer.flush()
    with diagnostic.open('a') as stream:
        stream.write('Exit status 0\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
