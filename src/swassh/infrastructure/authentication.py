"""Explicit native authentication modes; SWASSH never receives a password."""
import os
from pathlib import Path
import shutil
import stat
from .filesystem import PinnedDirectory


class Authentication:
    """Configure OpenSSH and an optional administrator-provided askpass helper."""
    @staticmethod
    def directives(options):
        method = options.auth_method
        lines = [f"  BatchMode {'no' if method == 'password' else 'yes'}",
                 f"  PasswordAuthentication {'yes' if method == 'password' else 'no'}",
                 f"  PubkeyAuthentication {'yes' if method == 'publickey' else 'no'}",
                 '  KbdInteractiveAuthentication no', '  NumberOfPasswordPrompts 1',
                 '  PreferredAuthentications ' + ('gssapi-with-mic' if method == 'gssapi' else method)]
        # Do not emit unsupported GSSAPI directives for legacy clients unless
        # explicitly requested. No fallback to weaker methods or delegation.
        if method == 'gssapi':
            lines += ['  GSSAPIAuthentication yes', '  GSSAPIDelegateCredentials no']
        return lines

    @staticmethod
    def provider(options):
        """Locate a regular trusted executable without running it or reading secrets."""
        executable = shutil.which(options.askpass_executable or '')
        if executable is None:
            raise ValueError('askpass provider executable unavailable')
        path = Path(executable).absolute()
        with PinnedDirectory(path.parent) as directory:
            fd = directory.open(path.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            try:
                info = os.fstat(fd)
            finally:
                os.close(fd)
        if not stat.S_ISREG(info.st_mode) or (os.name == 'posix' and info.st_mode & 0o022):
            raise ValueError('askpass provider must be a regular executable without shared write access')
        return str(path)

    @classmethod
    def environment(cls, options, target):
        """Keep credential acquisition separate from command stdin and arguments."""
        env = dict(os.environ, LC_ALL='C', LANG='C', SSH_ASKPASS_REQUIRE='never')
        env.pop('SSH_ASKPASS', None)
        if options.auth_method == 'password' or target.auth_method == 'password':
            env.update(SSH_ASKPASS=cls.provider(options), SSH_ASKPASS_REQUIRE='force')
            env.setdefault('DISPLAY', 'swassh:0')
        return env
