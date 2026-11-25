"""POSIX-only OpenSSH ProxyUseFdpass connector to its guardian-owned relay.

Only a loopback ephemeral port is accepted. The socket descriptor goes to
OpenSSH; this helper never receives keys, commands or decrypted channel data.
"""
import array
import socket
import sys


class NativeConnector:
    """Select a trusted connector after bounded help and real-socket probes.

    Absence of this optional optimization selects the Python fdpass connector.
    Once selected, a runtime failure never switches connector or target paths.
    """
    _cache={}

    @classmethod
    def find(cls):
        import os
        import shutil
        from pathlib import Path
        if os.name!='posix':return None
        for name in ('nc.openbsd','nc'):
            path=shutil.which(name)
            if path is None:continue
            path=str(Path(path).resolve(strict=True))
            # Cache capabilities, never permission or ancestry authorization.
            info=cls._trusted_info(path)
            identity=(path,info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            if identity not in cls._cache:
                if len(cls._cache)>=64:cls._cache.clear()
                cls._cache[identity]=cls._supports(path) and cls._nodelay(path)
            if cls._cache[identity]:return path
        return None

    @staticmethod
    def _trusted_info(path):
        """Recheck live ancestry and file permissions even on a capability hit."""
        import os
        import stat
        from pathlib import Path
        from .filesystem import PinnedDirectory
        with PinnedDirectory(Path(path).parent) as directory:
            # Never wait for a writer while inspecting an untrusted special file.
            descriptor=directory.open(Path(path).name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            try:info=os.fstat(descriptor)
            finally:os.close(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode&0o022
                or info.st_uid not in {0,os.geteuid()}):
            raise ValueError('native relay connector must be a trusted executable')
        return info

    @staticmethod
    def _supports(path):
        import os
        import re
        import select
        import subprocess
        import time
        NativeConnector._trusted_info(path)
        process=subprocess.Popen([path,'-h'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
        output=bytearray()
        try:
            end=time.monotonic()+1
            while len(output)<=8192:
                remaining=end-time.monotonic()
                if remaining<=0:return False
                if not select.select([process.stdout],[],[],remaining)[0]:return False
                data=os.read(process.stdout.fileno(),min(4096,8193-len(output)))
                if not data:break
                output.extend(data)
            if len(output)>8192:return False
            return b'OpenBSD' in output and all(re.search(rb'(?m)^\s*-'+flag+rb'\b',output)
                                               for flag in (b'F',b'I',b'O'))
        finally:
            try:
                NativeConnector._stop_probe(process)
            finally:
                # The pipe is owned even when terminating or joining fails.
                process.stdout.close()

    @staticmethod
    def _nodelay(path):
        """Require TCP_NODELAY on the actual descriptor delivered by a helper.

        OpenSSH does not perform its direct-connect socket setup on fdpass.
        An nc help banner proves syntax, not the socket's short-record latency
        contract. This bounded loopback-only preflight sends no SSH byte and
        opens no target connection. Unsupported helpers select Python before
        a command starts; there is never a fallback after target execution.
        """
        import os
        import subprocess
        descriptors=array.array('i')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0))
            listener.listen(1)
            parent,child=socket.socketpair()
            with parent,child:
                parent.settimeout(1)
                process=subprocess.Popen([path,'-F','-I','16384','-O','16384','-w','1',
                    '127.0.0.1',str(listener.getsockname()[1])],stdin=subprocess.DEVNULL,
                    stdout=child,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
                child.close()
                try:
                    try:
                        data,controls,flags,_=parent.recvmsg(1,socket.CMSG_SPACE(4*descriptors.itemsize))
                        for level,kind,value in controls:
                            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                                descriptors.frombytes(value[:len(value)-len(value)%descriptors.itemsize])
                        if len(data)!=1 or len(descriptors)!=1 or flags:
                            return False
                        # A malformed helper can pass a non-socket fd. Keep
                        # ownership until the socket constructor accepts it.
                        connection=socket.socket(fileno=descriptors[-1])
                        descriptors.pop()
                        with connection:
                            # Darwin returns the enabled flag bit (4), Linux 1.
                            # Both are true; a disabled socket must still fail.
                            enabled=bool(connection.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY))
                        process.wait(timeout=1)
                        return enabled and process.returncode==0
                    except (OSError,subprocess.TimeoutExpired):
                        return False
                finally:
                    try:
                        for descriptor in descriptors:os.close(descriptor)
                    finally:
                        NativeConnector._stop_probe(process)

    @staticmethod
    def _stop_probe(process):
        """Reap the probe leader and stop its private group even after its exit.

        A wrapper can leave children holding a pipe or control socket. Reaping
        its leader alone does not end their lifetime. Every probe is started in
        its own session, so this cleanup never signals the caller's group.
        """
        import os
        import signal
        try:
            if process.poll() is None:process.kill()
            process.wait(timeout=2)
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass


def main(arguments):
    """Pass one connected descriptor, or fail without a direct-target fallback."""
    if len(arguments)!=1 or not arguments[0].isascii() or not arguments[0].isdigit():
        raise ValueError('invalid guardian relay port')
    port=int(arguments[0])
    if not 1<=port<=65535:
        raise ValueError('invalid guardian relay port')
    with socket.create_connection(('127.0.0.1',port),timeout=3) as connection:
        # OpenSSH receives an already-connected socket through fdpass; its
        # direct-connect TCP setup is not run on this path. Preserve prompt
        # short-record delivery on the local leg as well as the remote leg.
        connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,16384)
        connection.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16384)
        connection.settimeout(None)
        with socket.socket(fileno=1) as channel:
            if channel.sendmsg([b'\0'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                      array.array('i',[connection.fileno()]))])!=1:
                raise OSError('guardian relay descriptor not delivered')
    return 0


if __name__=='__main__':
    try:
        result=main(sys.argv[1:])
    except (ValueError,OSError):
        sys.stderr.write('swassh: guardian relay connection failed\n')
        result=125
    raise SystemExit(result)
