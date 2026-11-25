"""One guardian-owned loopback connection, with durable bidirectional shaping."""
import math
import shlex
import socket
import sys
import threading

from ..domain.endpoints import Endpoint
from .bandwidth import SQLiteByteBudget


class GuardianRelay:
    """Keep original SSH addressing/trust through ProxyUseFdpass.

    Admission has already committed before construction. A single local client
    is accepted; both directions debit the same existing durable token bucket.
    All buffers, threads and socket waits are bounded and owned by the guardian.
    """
    def __init__(self,request,coordinator):
        if (not isinstance(request,dict) or not {'host','port','connect_timeout'}<=set(request)
                or set(request)-{'host','port','connect_timeout','connector'}):
            raise ValueError('invalid guardian relay request')
        self.endpoint=Endpoint(request['host'],request['port'])
        timeout=request['connect_timeout']
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0:
            raise ValueError('invalid guardian relay timeout')
        self.timeout=timeout
        self.connector=request.get('connector')
        if self.connector is not None:
            import os
            import stat
            from pathlib import Path
            if not isinstance(self.connector,str):
                raise ValueError('invalid guardian connector path')
            path=Path(self.connector)
            if not path.is_absolute():
                raise ValueError('invalid guardian connector path')
            info=path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode&0o022 or info.st_uid not in {0,os.geteuid()}:
                raise ValueError('unsafe guardian connector')
        self.stop=threading.Event()
        self.failed=threading.Event()
        self.connected=threading.Event()
        self.connection_failure=None
        self.client=self.remote=None
        self.workers=[]
        self.budget=SQLiteByteBudget(None,coordinator=coordinator)
        try:
            self.listener=socket.socket()
            self.listener.bind(('127.0.0.1',0))
            self.listener.listen(1)
            self.listener.settimeout(0.05)
            self.port=self.listener.getsockname()[1]
            owner=threading.Thread(target=self._accept,name='swassh-guardian-relay',daemon=True)
            self.workers.append(owner)
            owner.start()
        except BaseException:
            if hasattr(self,'listener'):self.listener.close()
            self.budget.close()
            raise

    def arguments(self,argv):
        """Keep hostname, port and certificates untouched in OpenSSH's config."""
        arguments=([sys.executable,'-m','swassh.infrastructure.relay_connect',str(self.port)]
                   if self.connector is None else [self.connector,'-F','-I','16384','-O','16384',
                        '-w',str(math.ceil(self.timeout)),'127.0.0.1',str(self.port)])
        command=shlex.join(arguments)
        return [argv[0],'-o','ProxyCommand='+command.replace('%','%%'),
                '-o','ProxyUseFdpass=yes',*argv[1:]]

    @staticmethod
    def _configure(connection):
        connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,16384)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
        connection.settimeout(0.05)

    def _accept(self):
        try:
            while not self.stop.is_set():
                try:
                    client,_=self.listener.accept()
                    break
                except TimeoutError:
                    continue
            else:return
            self.client=client
            self.listener.close()
            self._configure(client)
            try:
                self.remote=socket.create_connection((self.endpoint.hostname,self.endpoint.port),timeout=self.timeout)
            except OSError as error:
                # No target socket existed and no SSH byte could reach it.
                # This is the only relay failure safe for pre-auth retries.
                self.connection_failure='timeout' if isinstance(error,TimeoutError) else 'unreachable'
                raise
            if self.stop.is_set():
                self.remote.close()
                return
            self._configure(self.remote)
            self.connected.set()
            upload=threading.Thread(target=self._forward,args=(client,self.remote),
                                    name='swassh-guardian-upload',daemon=True)
            self.workers.append(upload)
            upload.start()
            self._forward(self.remote,client)
        except Exception:
            if not self.stop.is_set():self.failed.set()
            self.stop.set()

    def _forward(self,source,destination):
        try:
            while not self.stop.is_set():
                try:
                    data=source.recv(self.budget.chunk_size)
                except TimeoutError:
                    self.budget.idle()
                    continue
                if not data:
                    destination.shutdown(socket.SHUT_WR)
                    return
                if hasattr(socket,'TCP_QUICKACK'):
                    source.setsockopt(socket.IPPROTO_TCP,socket.TCP_QUICKACK,1)
                for piece in self.budget.chunks(data,self.stop):
                    offset=0
                    while offset<len(piece) and not self.stop.is_set():
                        try:
                            count=destination.send(piece[offset:])
                        except TimeoutError:
                            continue
                        if count<=0:raise OSError('guardian relay output closed')
                        offset+=count
        except Exception:
            if not self.stop.is_set():self.failed.set()
            self.stop.set()

    def close(self):
        """Stop byte flow before releasing the guardian's admission lease."""
        self.stop.set()
        self.listener.close()
        for connection in (self.client,self.remote):
            if connection is not None:
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                connection.close()
        for worker in self.workers:
            worker.join(3.1)
        if any(worker.is_alive() for worker in self.workers):
            # A blocked resolver/storage call must not let its lease be reused.
            # The guardian's process boundary releases descriptors at OS exit.
            raise RuntimeError('guardian relay did not stop within its bound')
        # An accept/connect may have completed concurrently with shutdown.
        # Reclaim that last descriptor before the admission lease is released.
        for connection in (self.client,self.remote):
            if connection is not None:connection.close()
        self.budget.close()
