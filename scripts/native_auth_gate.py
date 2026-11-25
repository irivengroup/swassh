"""Qualify password and Kerberos in private mount, PID and network namespaces.

Requires Linux root, unshare, iproute2, OpenSSH and MIT Kerberos tools already
installed. No host accounts, credentials, tickets or services are modified.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

# Qualification tools come from the installed system, never caller PATH.
_SYSTEM_TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


class AuthenticationGate:
    """Enter isolation before making any changes to the authentication fixture."""
    @staticmethod
    def _system_tool(name):
        """Resolve only qualification prerequisites in explicit system directories."""
        if name not in {'mount', 'ip', 'unshare'}:
            raise ValueError('unknown authentication prerequisite')
        executable = shutil.which(name, path=_SYSTEM_TOOL_PATH)
        if executable is None:
            raise RuntimeError('authentication prerequisite unavailable: ' + name)
        return executable

    def isolated(self, directory):
        if os.getpid() != 1:
            raise RuntimeError('isolated entry requires a fresh PID namespace')
        os.environ['PATH'] = _SYSTEM_TOOL_PATH
        root = Path(directory)
        upper, work = root/'upper', root/'work'
        upper.mkdir()
        work.mkdir()
        subprocess.run([self._system_tool('mount'), '-t', 'overlay', 'overlay', '-o',
            f'lowerdir=/etc,upperdir={upper},workdir={work}', '/etc'], check=True)
        subprocess.run([self._system_tool('mount'), '-t', 'tmpfs', '-o', 'mode=0700', 'tmpfs', '/root'], check=True)
        subprocess.run([self._system_tool('ip'), 'link', 'set', 'lo', 'up'], check=True)
        from auth_fixture import provision_realm
        os.environ.update(provision_realm(root))
        from native_network_gate import NativeNetworkGate
        return NativeNetworkGate().run('test_native_auth.py')

    def run(self):
        if not sys.platform.startswith('linux') or os.geteuid() != 0:
            raise RuntimeError('native authentication qualification requires Linux root and private namespace support')
        with tempfile.TemporaryDirectory(prefix='swassh-auth-qa-') as directory:
            return subprocess.run([self._system_tool('unshare'), '--mount', '--pid', '--net', '--fork',
                '--kill-child', '--mount-proc', '--propagation', 'private',
                sys.executable, str(Path(__file__).resolve()), '--isolated', directory], timeout=180,
                env=dict(os.environ, PATH=_SYSTEM_TOOL_PATH)).returncode


if __name__ == '__main__':
    gate = AuthenticationGate()
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        raise SystemExit(gate.isolated(sys.argv[2]))
    raise SystemExit(gate.run())
