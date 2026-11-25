"""Local file boundaries: reject links, special files and shared writable staging."""
from __future__ import annotations
import errno
import os
import stat
from contextlib import nullcontext
from pathlib import Path


def is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _trusted_directory(path: Path) -> None:
    info = path.lstat()
    if is_link(info):
        if os.name != 'posix' or info.st_uid not in {0, os.geteuid()}:
            raise ValueError('untrusted link or reparse point in output ancestry')
        return  # Its containing directory and resolved target are checked separately.
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('output ancestor must be a directory')
    if os.name == 'posix':
        if info.st_uid not in {0, os.geteuid()}:
            raise ValueError('output ancestor must be owned by this account or root')
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if info.st_mode & 0o022 and not sticky_root:
            raise ValueError('output ancestor must not be shared writable')


def trusted_parents(path: str | Path) -> None:
    """Validate before creation; preserve trusted macOS /var and /tmp aliases."""
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        if parent.exists() or parent.is_symlink():
            _trusted_directory(parent)
    resolved = path.parent.resolve(strict=False)
    for parent in (*reversed(resolved.parents), resolved):
        if parent.exists() or parent.is_symlink():
            _trusted_directory(parent)


def _open_directory(path: str | Path) -> int:
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ValueError('expected a directory descriptor')
        return fd
    except BaseException:
        os.close(fd)
        raise


def sync_directory(path: str | Path) -> bool:
    """Sync POSIX directory entries when supported; never swallow storage errors."""
    if os.name != 'posix':
        return False
    fd = _open_directory(path)
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                return False
            raise
        return True
    finally:
        os.close(fd)


def private_directory(path: Path, *, tighten: bool = False) -> Path:
    # The final component must never be a link, including trusted aliases.
    if path.is_symlink():
        raise ValueError("staging directory must not be a link")
    with PinnedDirectory(path, create=True, private=True, tighten=tighten) as directory:
        return directory.path


def open_private_append(path: str | Path, *, directory=None):
    """Open a private regular file, optionally in an already pinned parent.

    Reusing the live parent retains ancestry protection across a batch without
    repeating the same walk. File type, link count and ownership stay per-file.
    The caller owns a supplied directory; this operation never closes it.
    """
    path = Path(path).absolute()
    if directory is not None and (directory.path != path.parent or directory._closed):
        raise ValueError('append directory must be the live pinned parent')
    with (PinnedDirectory(path.parent) if directory is None else nullcontext(directory)) as parent:
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = parent.open(path.name, flags, 0o600)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENXIO}:
                raise ValueError("audit path must be a regular file, not a link") from None
            raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("audit path must be a regular file without hard links")
        if os.name == "posix":
            if info.st_uid != os.geteuid():
                raise ValueError("audit file must be owned by this account")
            os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


class PinnedDirectory:
    """Resolve/create through verified descriptors; keep the destination pinned.

    POSIX system aliases owned by root/current UID are resolved with a bounded
    link count. Windows forbids all reparse points and denies ancestry renames.
    """
    def __init__(self, path, *, create=False, private=False, tighten=False):
        self.path = Path(path).absolute()
        self.fd = None
        self.handles = []
        self._closed = False
        self._private = private
        try:
            if os.name == 'posix':
                self._posix(create)
                info = os.fstat(self.fd)
                if private and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
                    raise ValueError('private directory must be owned by this account and not shared writable')
                if tighten:
                    if self.path == Path('/') or info.st_uid != os.geteuid():
                        raise ValueError('cannot tighten root or another account directory')
                    os.fchmod(self.fd, 0o700)
            else:
                from .windows import DirectoryHandle, protect_directory
                parts = [*reversed(self.path.parents), self.path]
                for part in parts:
                    created = create and not part.exists()
                    if created:
                        try:
                            part.mkdir(mode=0o700)
                        except FileExistsError:
                            pass
                    self.handles.append(DirectoryHandle(part))
                    if created:
                        # Validate ownership and protect each new component before
                        # creating a child inside it, including a raced mkdir.
                        protect_directory(part)
                if private:
                    protect_directory(self.path)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(info):
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            raise ValueError('untrusted output directory')
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise ValueError('output directory must not be shared writable')

    def _posix(self, create):
        # Normalize lexical dot components, never resolve links before pinning.
        pending = list(self.path.parts[1:])
        resolved = Path('/')
        fd = _open_directory('/')
        links = 0
        try:
            self._check(os.fstat(fd))
            while pending:
                part = pending.pop(0)
                if part in {'', '.'}:
                    continue
                if part == '..':
                    # Restart at root for a normalized parent path.
                    pending = list(resolved.parent.parts[1:]) + pending
                    os.close(fd)
                    fd = _open_directory('/')
                    resolved = Path('/')
                    continue
                try:
                    before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode):
                    if not pending and self._private:
                        raise ValueError("private directory must not be an alias")
                    links += 1
                    if links > 40 or before.st_uid not in {0, os.geteuid()}:
                        raise ValueError('untrusted output alias')
                    target = Path(os.readlink(part, dir_fd=fd))
                    alias = target if target.is_absolute() else resolved / target
                    pending = list(alias.parts[1:]) + pending
                    os.close(fd)
                    fd = _open_directory('/')
                    resolved = Path('/')
                    continue
                flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
                child = os.open(part, flags, dir_fd=fd)
                try:
                    after = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        raise ValueError('directory changed while pinning')
                    self._check(after)
                    current = os.stat(part, dir_fd=fd, follow_symlinks=False)
                    if is_link(current) or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
                        raise ValueError('directory entry changed while pinning')
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
                resolved /= part
            self.path, self.fd = resolved, fd
            fd = None
        finally:
            if fd is not None:
                os.close(fd)

    def open(self, name, flags, mode=0o600):
        self._name(name)
        if self.fd is not None:
            return os.open(name, flags, mode, dir_fd=self.fd)
        from .windows import open_file_without_reparse
        return open_file_without_reparse(self.path / name, flags)

    @staticmethod
    def _name(name):
        if not isinstance(name, str) or name in {'', '.', '..'} or '/' in name or '\\' in name:
            raise ValueError('expected a literal directory entry')
        if os.name == 'nt' and (':' in name or name.endswith((' ', '.'))
                or name.split('.', 1)[0].upper() in {'CON', 'PRN', 'AUX', 'NUL',
                    *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}):
            raise ValueError('Windows stream and device names are not regular entries')

    def replace(self, source, destination):
        self._name(source)
        self._name(destination)
        if self.fd is not None:
            os.replace(source, destination, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        else:
            os.replace(self.path / source, self.path / destination)
        self.sync()

    def unlink(self, name):
        self._name(name)
        try:
            if self.fd is not None:
                os.unlink(name, dir_fd=self.fd)
            else:
                (self.path / name).unlink()
        except FileNotFoundError:
            pass

    def sync(self):
        if self.fd is not None:
            try:
                os.fsync(self.fd)
            except OSError as exc:
                if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                    raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for handle in reversed(self.handles):
            handle.close()
        self.handles.clear()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class AtomicOutput:
    """Private relative temporary and atomic publication into a pinned directory."""
    def __init__(self, destination):
        import uuid
        destination = Path(destination).absolute()
        self.directory = PinnedDirectory(destination.parent)
        self.name = destination.name
        self.temporary = '.swassh-' + uuid.uuid4().hex + '.tmp'
        self.stream = None
        fd = None
        try:
            fd = self.directory.open(self.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.stream = os.fdopen(fd, 'w', encoding='utf-8', newline='')
            if os.name == 'nt':
                from .windows import protect_directory
                # Same owner and private DACL policy applies to regular files.
                protect_directory(self.directory.path / self.temporary)
        except BaseException:
            try:
                if self.stream is not None:
                    self.stream.close()
                elif fd is not None:
                    os.close(fd)
            finally:
                try:
                    self.directory.unlink(self.temporary)
                finally:
                    self.directory.close()
            raise

    def __enter__(self):
        return self.stream

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                self.stream.flush()
                os.fsync(self.stream.fileno())
            self.stream.close()
            if exc_type is None:
                self.directory.replace(self.temporary, self.name)
        finally:
            try:
                if not self.stream.closed:
                    self.stream.close()
            finally:
                try:
                    self.directory.unlink(self.temporary)
                finally:
                    # Storage errors remain visible without retaining ancestry
                    # handles that prevent later writes or Windows renames.
                    self.directory.close()
