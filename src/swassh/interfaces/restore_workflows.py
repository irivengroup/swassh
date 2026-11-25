"""Restore a SWASSH workflow snapshot into a new Linux directory."""

import argparse
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import tempfile

from ..infrastructure.database.migration.workflows_v1 import APPLICATION_ID, WorkflowSchema
from ..infrastructure.filesystem import PinnedDirectory
from ..infrastructure.json_data import _unique_object
from .restore_cleanup import CleanupBusy, MAX_SQLITE_BYTES, SQLITE_NAME, locked_destination


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_DIRECTORIES = 16_384
READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


@contextmanager
def regular_file(descriptor):
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Expected a regular backup file without hard links")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            yield stream
    finally:
        os.close(descriptor)


def load_manifest(path):
    """Read the operator's bounded JSON mapping of relative paths to SHA-256."""
    with regular_file(os.open(path, READ_FLAGS)) as manifest:
        raw = manifest.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Backup manifest exceeds the size limit")
    files = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(files, dict) or SQLITE_NAME not in files:
        raise ValueError("Backup inventory must include workflows.sqlite")
    for name, checksum in files.items():
        path = PurePosixPath(name)
        if (not path.parts or path.is_absolute() or path.as_posix() != name
                or ".." in path.parts or "\\" in name or "\0" in name):
            raise ValueError("Invalid backup member path")
        if name not in {SQLITE_NAME, "workflow.jsonl"} and path.parent.parts[:1] != ("runs",):
            raise ValueError("Unexpected workflow snapshot member")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-fA-F]{64}", checksum) is None:
            raise ValueError("Invalid backup member SHA-256")
    return {PurePosixPath(name): checksum.lower() for name, checksum in files.items()}


def copy_verified(directory, target, name, expected, budget):
    """Stream one private regular file, with a bounded size and a verified digest."""
    digest = hashlib.sha256()
    total = 0
    with regular_file(directory.open(name, READ_FLAGS)) as source, target.open("xb") as output:
        while block := source.read(min(1024 * 1024, budget - total + 1)):
            total += len(block)
            if total > budget:
                raise ValueError("Backup exceeds the restore size limit")
            digest.update(block)
            output.write(block)
        if digest.hexdigest() != expected:
            raise ValueError("Backup SHA-256 verification failed")
        os.chmod(target, 0o600)
        output.flush()
        os.fsync(output.fileno())
    return total


def validate_database(database):
    """Use SQLite read-only checks on the copied snapshot, without recovery side effects."""
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        identity = (db.execute("PRAGMA application_id").fetchone()[0],
                    db.execute("PRAGMA user_version").fetchone()[0])
        if identity != (APPLICATION_ID, 1) or db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise ValueError("Invalid workflow SQLite snapshot")
        WorkflowSchema.up(db)


class WorkflowRestore:
    """Stage verified bytes privately and claim a fresh destination under the lock."""

    def __init__(self, source, files):
        self.source = Path(source).absolute()
        self.files = files

    def stage(self, payload):
        pending = [PurePosixPath(".")]
        visited = []
        found = set()
        budget = MAX_SNAPSHOT_BYTES
        while pending:
            folder = pending.pop()
            visited.append(folder)
            requested = self.source / folder
            with PinnedDirectory(requested, private=True) as directory:
                if directory.path != requested:
                    raise ValueError("Backup directory differs from the trusted inventory")
                output = payload / folder
                output.mkdir(mode=0o700)
                with os.scandir(directory.path) as entries:
                    for entry in entries:
                        member = folder / entry.name
                        if member in self.files:
                            limit = min(budget, MAX_SQLITE_BYTES) if member == PurePosixPath(SQLITE_NAME) else budget
                            budget -= copy_verified(directory, output / entry.name, entry.name, self.files[member], limit)
                            found.add(member)
                        elif member.parts[0] == "runs" and entry.is_dir(follow_symlinks=False):
                            # A pending step can own an empty report directory.
                            if len(visited) + len(pending) >= MAX_SNAPSHOT_DIRECTORIES:
                                raise ValueError("Backup exceeds the restore directory limit")
                            pending.append(member)
                        else:
                            raise ValueError("Backup directory differs from the trusted inventory")
        if found != self.files.keys():
            raise ValueError("Backup inventory is missing a declared file")
        validate_database(payload / SQLITE_NAME)
        for folder in reversed(visited):
            with PinnedDirectory(payload / folder) as directory:
                directory.sync()

    def write(self, parent, name):
        if os.path.lexists(parent.path / name):
            raise ValueError("Restore requires a new directory")
        # Staging and destination share a filesystem. Only validated bytes move
        # into the reservation made exclusively with mkdir while locked.
        with tempfile.TemporaryDirectory(prefix=".swassh-restore-", dir=parent.path) as scratch:
            payload = Path(scratch) / "snapshot"
            self.stage(payload)
            os.mkdir(name, mode=0o700, dir_fd=parent.fd)
            try:
                os.rename(payload, name, dst_dir_fd=parent.fd)
            except OSError:
                os.rmdir(name, dir_fd=parent.fd)
                raise
            parent.sync()


def restore(source, target, manifest):
    """Restore one backup with the worker stopped and the destination lock held."""
    if not sys.platform.startswith("linux"):
        raise ValueError("Workflow restore requires Linux")
    target = Path(target).absolute()
    PinnedDirectory._name(target.name)
    with locked_destination(target) as parent:
        WorkflowRestore(source, load_manifest(manifest)).write(parent, target.name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", help="Private directory containing the offline snapshot")
    parser.add_argument("directory", help="New workflow state directory on a local Linux filesystem")
    parser.add_argument("--manifest", required=True, help="Trusted JSON file of relative paths and SHA-256 digests")
    args = parser.parse_args(argv)
    try:
        restore(args.backup, args.directory, args.manifest)
    except CleanupBusy as error:
        print(error, file=sys.stderr)
        return 75
    except (OSError, ValueError, sqlite3.Error, RecursionError) as error:
        print(error, file=sys.stderr)
        return 2
    return 0
