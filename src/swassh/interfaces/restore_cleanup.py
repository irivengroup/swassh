"""Remove a verified, incomplete workflow restore under a Linux folder lock."""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

from ..infrastructure.bastion import FileLock
from ..infrastructure.filesystem import PinnedDirectory


SQLITE_NAME = "workflows.sqlite"
MAX_SQLITE_BYTES = 128 * 1024 * 1024


class CleanupBusy(RuntimeError):
    """Another maintenance operation holds the lock for this destination."""


@contextmanager
def locked_destination(target):
    """Keep the same lock inode across creation and removal of the target."""
    with PinnedDirectory(target.parent, private=True) as parent:
        key = hashlib.sha256(os.fsencode(target.name)).hexdigest()
        lock = FileLock(parent.path / f".swassh-restore-{key}.lock", directory=parent)
        try:
            if not lock.acquire():
                raise CleanupBusy("volume verrouillé")
            yield parent
        finally:
            lock.close()


def _mount_id(fd):
    text = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    match = re.search(r"^mnt_id:\s+(\d+)$", text, flags=re.MULTILINE)
    if match is None:
        raise ValueError("Cannot identify the mount of the cleanup directory")
    return match[1]


def _check_entry(fd, name, expected):
    actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if not os.path.samestat(actual, expected):
        raise ValueError("Cleanup entry changed while it was verified")


class PartialRestore:
    """Own the protected parent, and remove only the verified partial SQLite."""

    def __init__(self, parent, name):
        self.parent = parent
        self.name = name

    def remove(self, expected):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        folder = self.parent.open(self.name, flags | os.O_DIRECTORY)
        try:
            info = os.fstat(folder)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("Partial restore must be a private directory owned by the current account")
            if _mount_id(folder) != _mount_id(self.parent.fd):
                raise ValueError("Refusing to clean a mount point")
            if os.listdir(folder) != [SQLITE_NAME]:
                raise ValueError("Partial restore must contain only workflows.sqlite")
            fd = os.open(SQLITE_NAME, flags | os.O_NONBLOCK, dir_fd=folder)
            with os.fdopen(fd, "rb") as handle:
                database = os.fstat(handle.fileno())
                if not stat.S_ISREG(database.st_mode) or database.st_nlink != 1 or database.st_uid != os.geteuid():
                    raise ValueError("Partial SQLite must be an owned regular file without hard links")
                if not 0 < database.st_size <= MAX_SQLITE_BYTES:
                    raise ValueError("Partial SQLite size is outside the workflow limit")
                if hashlib.file_digest(handle, "sha256").hexdigest() != expected:
                    raise ValueError("Partial SQLite SHA-256 differs from the trusted digest")
                _check_entry(folder, SQLITE_NAME, database)
                _check_entry(self.parent.fd, self.name, info)
                os.unlink(SQLITE_NAME, dir_fd=folder)
            os.fsync(folder)
            _check_entry(self.parent.fd, self.name, info)
            os.rmdir(self.name, dir_fd=self.parent.fd)
            self.parent.sync()
        finally:
            os.close(folder)


def clean(path, expected):
    """Clean one incomplete restore. The operator must have stopped its worker."""
    if not sys.platform.startswith("linux"):
        raise ValueError("Restore cleanup requires Linux")
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        raise ValueError("Expected a 64-digit SHA-256 fingerprint")
    target = Path(path).absolute()
    if not target.name:
        raise ValueError("Expected a partial restore directory")
    with locked_destination(target) as parent:
        PartialRestore(parent, target.name).remove(expected.lower())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="Incomplete restore directory on a local Linux filesystem")
    parser.add_argument("--sha256", required=True, help="Trusted SHA-256 of the partial workflows.sqlite")
    args = parser.parse_args(argv)
    try:
        clean(args.directory, args.sha256)
    except CleanupBusy as error:
        print(error, file=sys.stderr)
        return 75
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2
    return 0
