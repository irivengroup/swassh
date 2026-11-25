"""Internal OpenSSH ProxyCommand: bounded encrypted stdio/TCP byte relay.

No SSH parsing, authentication or encryption happens here. OpenSSH retains its
strict trust and credentials. The guardian owns this descendant and its sockets.
The token bucket caps delivered encrypted payload, with one shared <=16 KiB
burst; TCP/kernel buffering and unrelated host traffic remain outside that cap.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import os
import socket
import sys
import threading
import time
from types import SimpleNamespace

from ..domain.endpoints import Endpoint
from .bandwidth import SQLiteByteBudget
from .bastion import specification
from .json_data import _unique_object, _invalid_constant

REQUEST_FIELDS={'schema_version','host','port','budget-root','connections','connect-rate',
                'memory-bytes','bandwidth-kib','connect-timeout','lifetime'}


def request_arguments(arguments):
    """Decode one bounded literal JSON envelope before ordinary CLI validation.

    Base64 is shell-safe transport, not encryption or authentication. It keeps
    percent signs, scopes and path punctuation out of ProxyCommand expansion.
    """
    if '--request' not in arguments:
        return arguments
    if len(arguments)!=2 or arguments[0]!='--request' or len(arguments[1])>32768:
        raise ValueError('invalid encrypted-byte request envelope')
    try:
        raw=base64.b64decode(arguments[1],altchars=b'-_',validate=True)
        if len(raw)>16384:
            raise ValueError('request exceeds its budget')
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_object,parse_constant=_invalid_constant)
        if not isinstance(data,dict) or set(data)!=REQUEST_FIELDS:
            raise ValueError('request field mismatch')
        if type(data['schema_version']) is not int or data.pop('schema_version')!=1:
            raise ValueError('unsupported request version')
        for name in ('host','budget-root'):
            if not isinstance(data[name],str): raise ValueError('request text field mismatch')
        for name in ('port','connections','memory-bytes','bandwidth-kib'):
            if type(data[name]) is not int: raise ValueError('request integer field mismatch')
        for name in ('connect-rate','connect-timeout','lifetime'):
            if type(data[name]) not in (int,float): raise ValueError('request numeric field mismatch')
        return [part for name,value in data.items() for part in ('--'+name,str(value))]
    except (ValueError,UnicodeError,binascii.Error,RecursionError,TypeError):
        raise ValueError('invalid encrypted-byte request envelope') from None


def proxy_command(host,options,*,lifetime=None):
    """Quote only validated endpoints, a trusted interpreter and a private root."""
    import shlex
    import subprocess
    spec=specification(options)
    lifetime=options.command_timeout if lifetime is None else lifetime
    if type(lifetime) not in (int,float) or not math.isfinite(lifetime) or lifetime<=0:
        raise ValueError('encrypted-byte relay lifetime must be finite and positive')
    data={'schema_version':1,'host':host.hostname,'port':host.port,
          'budget-root':os.path.abspath(os.path.expanduser(spec['directory'])),
          'connections':spec['policy'][0],'connect-rate':spec['policy'][1],
          'memory-bytes':spec['policy'][2],'bandwidth-kib':spec['policy'][3],
          'connect-timeout':options.connect_timeout,'lifetime':lifetime}
    raw=json.dumps(data,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('utf-8')
    if len(raw)>16384: raise ValueError('encrypted-byte request exceeds its budget')
    arguments=[sys.executable,'-m','swassh.infrastructure.tcp_proxy','--request',
               base64.urlsafe_b64encode(raw).decode('ascii')]
    if os.name=='nt':
        # cmd.exe expansion is different from argv quoting. Refuse paths whose
        # metacharacters would require a shell expansion rather than guessing.
        if any(character in sys.executable for character in '%!&|<>^\r\n\0'):
            raise ValueError('encrypted-byte relay requires a literal Windows interpreter path without shell metacharacters')
        command=subprocess.list2cmdline(arguments)
    else:
        command=shlex.join(arguments)
    return command.replace('%','%%')


class TCPRelay:
    """Two directions, one socket and at most one bounded chunk per direction."""
    def __init__(self,connection,budget,*,input_fd=0,output_fd=1):
        self.connection,self.budget=connection,budget
        self.input_fd,self.output_fd=input_fd,output_fd
        self.stop=threading.Event()
        self.failed=False

    def _upload(self):
        try:
            while not self.stop.is_set():
                data=os.read(self.input_fd,self.budget.chunk_size)
                if not data:
                    self.connection.shutdown(socket.SHUT_WR)
                    return
                if not self.budget.take(len(data),self.stop):
                    return
                self.connection.sendall(data)
        except Exception:
            self.failed=True
            self.stop.set()
            try: self.connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def run(self):
        # Raw os.read avoids buffered-stream locks at interpreter shutdown when
        # a remote EOF leaves this daemon waiting for OpenSSH's stdin to close.
        upload=threading.Thread(target=self._upload,name='swassh-encrypted-upload',daemon=True)
        upload.start()
        try:
            while not self.stop.is_set():
                data=self.connection.recv(self.budget.chunk_size)
                if not data:
                    break
                # A ProxyCommand introduces application-level durable admission
                # between reads. On Linux, acknowledge the record promptly so
                # a peer using Nagle need not wait for the delayed-ACK timer.
                # QUICKACK is a per-read hint and does not bypass byte charging.
                if hasattr(socket,'TCP_QUICKACK'):
                    self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_QUICKACK,1)
                if not self.budget.take(len(data),self.stop):
                    break
                position=0
                while position<len(data):
                    written=os.write(self.output_fd,data[position:])
                    if written<=0:
                        raise OSError('encrypted-byte relay output closed')
                    position+=written
        finally:
            self.stop.set()
            try: self.connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.connection.close()
        return 1 if self.failed else 0


def _legacy_arguments(arguments):
    """Retain the diagnostic CLI while the native envelope avoids its imports."""
    import argparse
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--host',required=True)
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--budget-root',required=True)
    parser.add_argument('--connections',required=True,type=int)
    parser.add_argument('--connect-rate',required=True,type=float)
    parser.add_argument('--memory-bytes',required=True,type=int)
    parser.add_argument('--bandwidth-kib',required=True,type=int)
    parser.add_argument('--connect-timeout',required=True,type=float)
    parser.add_argument('--lifetime',required=True,type=float)
    return parser.parse_args(arguments)


def _arguments(arguments):
    if '--request' not in arguments:
        return _legacy_arguments(arguments)
    literal=request_arguments(arguments)
    converters={'port':int,'connections':int,'memory_bytes':int,'bandwidth_kib':int,
                'connect_rate':float,'connect_timeout':float,'lifetime':float}
    fields={}
    for name,value in zip(literal[::2],literal[1::2]):
        key=name[2:].replace('-','_')
        fields[key]=converters.get(key,str)(value)
    return SimpleNamespace(**fields)


def main(argv=None):
    budget=connection=relay=None
    done=threading.Event()
    try:
        args=_arguments(list(sys.argv[1:] if argv is None else argv))
        host=Endpoint(args.host,args.port)
        for duration in (args.connect_timeout,args.lifetime):
            if not math.isfinite(duration) or duration<=0:
                raise ValueError('relay deadlines must be finite and positive')
        if os.name=='nt':
            import msvcrt
            for descriptor in (0,1,2):
                msvcrt.setmode(descriptor,os.O_BINARY)
        def deadline():
            end=time.monotonic()+args.lifetime
            while not done.wait(min(1.0,max(0.0,end-time.monotonic()))):
                if time.monotonic()>=end:
                    os._exit(124)
        threading.Thread(target=deadline,name='swassh-relay-deadline',daemon=True).start()
        budget=SQLiteByteBudget({'directory':args.budget_root,'policy':[
            args.connections,args.connect_rate,args.memory_bytes,args.bandwidth_kib]})
        connection=socket.create_connection((host.hostname,host.port),timeout=args.connect_timeout)
        # OpenSSH cannot configure the TCP socket behind ProxyCommand. Its
        # handshake consists of short request/response records; do not combine
        # Nagle buffering with the peer's delayed acknowledgements.
        connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,16384)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
        connection.settimeout(None)
        relay=TCPRelay(connection,budget)
        return relay.run()
    except Exception:
        try:
            os.write(2,b'swassh: encrypted-byte relay failed; no direct connection fallback\n')
        except OSError:
            pass  # The nonzero exit remains authoritative if stderr was closed.
        return 125
    finally:
        done.set()
        if connection is not None: connection.close()
        # The uploader can still own the connection when remote EOF arrives.
        # Process exit closes its private SQLite descriptor; do not close a
        # connection underneath a currently executing transaction in that thread.
        if budget is not None and relay is None:
            budget.close()


if __name__=='__main__':
    status=main()
    sys.stderr.flush()
    # A daemon may be blocked in raw stdin or a cancelled local transaction.
    # This private helper is a process boundary: OS exit closes descriptors and
    # SQLite recovers any uncommitted journal before another helper can debit.
    os._exit(status)
