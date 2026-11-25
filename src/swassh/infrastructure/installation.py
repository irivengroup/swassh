"""Explicit user PATH setup, independent from pip's deliberately passive wheel install."""

import importlib.metadata
import json
import ntpath
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import sysconfig
import uuid

from .filesystem import AtomicOutput, PinnedDirectory, private_directory


class PathConfigurator:
    """Append a quoted PATH entry, with private backups and no shell execution."""

    def __init__(self, scripts: Path, home: Path, shell: str):
        self.scripts = Path(scripts).absolute()
        self.home = Path(home).absolute()
        self.shell = Path(shell).name
        if any(ord(char) < 32 or ord(char) == 127 for char in str(self.scripts)):
            raise ValueError('script directory contains control characters')
        if os.name == 'posix' and ':' in str(self.scripts):
            raise ValueError('script directory contains a colon, which PATH cannot represent')

    def profiles(self) -> list[Path]:
        """Select the actual login and interactive startup files for a POSIX shell."""
        if self.shell == 'bash':
            login = next((name for name in ('.bash_profile', '.bash_login', '.profile')
                          if (self.home / name).exists()), '.profile')
            return [self.home / login, self.home / '.bashrc']
        if self.shell == 'zsh':
            if os.environ.get('ZDOTDIR'):
                raise ValueError('custom ZDOTDIR requires manual PATH configuration')
            return [self.home / '.zprofile', self.home / '.zshrc']
        if self.shell in {'sh', 'dash', 'ksh', 'ksh93'}:
            return [self.home / '.profile']
        raise ValueError('unsupported login shell; configure PATH manually')

    def command(self) -> str:
        """POSIX command for the already-open shell (a child cannot change it)."""
        # An empty PATH component searches the current directory. Do not add
        # one when PATH is unset/empty; also support shells using set -u.
        return 'export PATH="${PATH:+${PATH}:}"' + shlex.quote(str(self.scripts))

    def configure(self) -> list[Path]:
        """Save each changed profile before atomic replacement; return backup paths.

        Refuse aliases, special files and untrusted owners. Existing content is
        retained verbatim. Backups remain available if a later profile fails.
        """
        profiles = self.profiles()
        marker = '# SWASSH PATH ' + str(self.scripts)
        block = ('\n' + marker + '\ncase ":${PATH-}:" in\n  *:'
                 + shlex.quote(str(self.scripts)) + ':*) ;;\n  *) '
                 + self.command() + ' ;;\nesac\n')
        legacy = ('\n' + marker + '\ncase ":$PATH:" in\n  *:'
                  + shlex.quote(str(self.scripts)) + ':*) ;;\n  *) export PATH="$PATH":'
                  + shlex.quote(str(self.scripts)) + ' ;;\nesac\n')
        backups = []
        for profile in profiles:
            with PinnedDirectory(profile.parent) as parent:
                try:
                    descriptor = parent.open(profile.name, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)
                                             | getattr(os, 'O_NOFOLLOW', 0))
                except FileNotFoundError:
                    original, mode = '', 0o600
                else:
                    with os.fdopen(descriptor, 'r', encoding='utf-8', newline='') as stream:
                        info = os.fstat(stream.fileno())
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                or info.st_size > 1024 * 1024
                                or (hasattr(os, 'geteuid') and
                                    (info.st_uid != os.geteuid() or info.st_mode & 0o022))):
                            raise ValueError('profile must be a private regular file owned by this user')
                        original, mode = stream.read(), stat.S_IMODE(info.st_mode)
                if block in original:
                    continue
                if legacy in original:
                    updated = original.replace(legacy, block)
                elif marker in original.splitlines():
                    raise ValueError('SWASSH PATH block is incomplete or modified; inspect the profile')
                else:
                    updated = original + block
                if original:
                    backup = profile.with_name(profile.name + '.swassh-backup-' + uuid.uuid4().hex)
                    with AtomicOutput(backup) as stream:
                        stream.write(original)
                    backups.append(backup)
                with AtomicOutput(profile) as stream:
                    stream.write(updated)
                    if hasattr(os, 'fchmod'):
                        os.fchmod(stream.fileno(), mode)
        return backups


class WindowsPathConfigurator:
    """Persist only the current user's PATH, preserving its registry type.

    A private JSON backup precedes every write. The injectable registry and key
    allow native tests to use a disposable key instead of the user's real PATH.
    """

    def __init__(self, scripts, home, *, registry=None, key='Environment'):
        if registry is None:
            import winreg
            registry = winreg
        self.registry, self.key = registry, key
        self.scripts, self.home = str(scripts), Path(home)
        if (not ntpath.isabs(self.scripts) or not ntpath.splitdrive(self.scripts)[0]
                or ';' in self.scripts or '"' in self.scripts
                or any(ord(char) < 32 or ord(char) == 127 for char in self.scripts)):
            raise ValueError('Windows script directory must be absolute without separators or controls')

    def configure(self):
        """Return a backup path after a change, or None if already configured."""
        from .bastion import FileLock
        registry = self.registry
        folder = private_directory(self.home / '.swassh' / 'path-backups', tighten=True)
        lock = FileLock(folder / 'configuration.lock')
        try:
            if not lock.acquire():
                raise ValueError('another SWASSH PATH configuration is in progress')
            with registry.CreateKeyEx(registry.HKEY_CURRENT_USER, self.key, 0,
                                      registry.KEY_QUERY_VALUE | registry.KEY_SET_VALUE) as handle:
                try:
                    original, kind = registry.QueryValueEx(handle, 'Path')
                    existed = True
                except FileNotFoundError:
                    original, kind, existed = '', registry.REG_EXPAND_SZ, False
                if kind not in (registry.REG_SZ, registry.REG_EXPAND_SZ) or not isinstance(original, str):
                    raise ValueError('Windows user PATH must be a registry string')
                if kind == registry.REG_EXPAND_SZ and '%' in self.scripts:
                    raise ValueError('literal percent cannot be added safely to an expandable Windows PATH')
                if any(ord(char) < 32 or ord(char) == 127 for char in original):
                    raise ValueError('Windows user PATH contains control characters')
                target = ntpath.normcase(ntpath.normpath(self.scripts))
                values = (ntpath.expandvars(original) if kind == registry.REG_EXPAND_SZ else original).split(';')
                if any(value and ntpath.normcase(ntpath.normpath(value.strip('"'))) == target for value in values):
                    return None
                updated = original + (';' if original and not original.endswith(';') else '') + self.scripts
                if len(updated.encode('utf-16-le')) // 2 >= 32767:
                    raise ValueError('Windows user PATH exceeds environment capacity')
                backup = folder / ('path-' + uuid.uuid4().hex + '.json')
                with AtomicOutput(backup) as stream:
                    json.dump({'key': self.key, 'name': 'Path', 'existed': existed,
                               'type': kind, 'value': original}, stream, ensure_ascii=True)
                    stream.write('\n')
                registry.SetValueEx(handle, 'Path', 0, kind, updated)
                return backup
        finally:
            lock.close()


def notify_windows_environment():
    """Notify Explorer, bounding each recipient's wait; report broadcast failure."""
    import ctypes
    from ctypes import wintypes
    function = ctypes.WinDLL('user32', use_last_error=True).SendMessageTimeoutW
    function.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t,
                         wintypes.LPCWSTR, wintypes.UINT, wintypes.UINT,
                         ctypes.POINTER(ctypes.c_size_t)]
    function.restype = ctypes.c_ssize_t
    result = ctypes.c_size_t()
    if not function(0xffff, 0x001a, 0, 'Environment', 2, 2000, ctypes.byref(result)):
        print('PATH saved; environment notification did not complete. Sign out and back in.', file=sys.stderr)


def installed_scripts() -> Path:
    """Find the actual console entrypoint, including pip --user installations."""
    try:
        distribution = importlib.metadata.distribution('swassh')
    except importlib.metadata.PackageNotFoundError as exc:
        raise ValueError('install the SWASSH wheel before configuring PATH') from exc
    for file in distribution.files or ():
        if file.name in {'swassh', 'swassh.exe'}:
            entry = Path(distribution.locate_file(file)).resolve()
            if entry.is_file():
                return entry.parent
    path = Path(sysconfig.get_path('scripts'))
    if not (path / ('swassh.exe' if os.name == 'nt' else 'swassh')).is_file():
        raise ValueError('installed swassh console entrypoint not found')
    return path


def setup_path(*, allow_venv=False) -> None:
    """Configure future user sessions; never pretend to mutate the parent shell."""
    if sys.prefix != sys.base_prefix and not allow_venv:
        raise ValueError('activate the virtual environment instead of persisting its PATH')
    scripts = installed_scripts()
    visible = shutil.which('swassh')
    if visible and Path(visible).resolve().parent != scripts.resolve():
        raise ValueError('another SWASSH installation precedes this one in PATH; resolve the conflict or use its Python explicitly')
    if any(value and os.path.normcase(os.path.abspath(value)) == os.path.normcase(str(scripts))
           for value in os.get_exec_path()):
        print('SWASSH script directory is already in PATH; no change required.')
        return
    if os.name == 'nt':
        backup = WindowsPathConfigurator(scripts, Path.home()).configure()
        if backup is not None:
            notify_windows_environment()
            print(f'Windows user PATH saved. Backup: {backup}')
        else:
            print('Windows user PATH already configured.')
        print('Open a new terminal; existing shells retain their environment. Use python -m swassh meanwhile.')
        return
    configurator = PathConfigurator(scripts, Path.home(), os.environ.get('SHELL', 'sh'))
    backups = configurator.configure()
    print('PATH configured for future shell sessions. Run in the current shell:')
    print(configurator.command())
    for backup in backups:
        print(f'Profile backup: {backup}')
