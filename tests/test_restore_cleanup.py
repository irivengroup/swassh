"""Verify exact-path cleanup, non-destructive rejection and lock contention."""

from contextlib import redirect_stderr
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from swassh.interfaces import restore_cleanup as cleanup
from swassh.infrastructure.filesystem import PinnedDirectory

CONTENT = b"partial SQLite fixture"
SHA256 = hashlib.sha256(CONTENT).hexdigest()


class RestoreCleanupCliTests(unittest.TestCase):
    def test_success_and_exit_codes(self):
        error = io.StringIO()
        with patch.object(cleanup, "clean") as clean, redirect_stderr(error):
            self.assertEqual(cleanup.main(["partial", "--sha256", SHA256]), 0)
            clean.assert_called_once_with("partial", SHA256)
            for failure, code in ((cleanup.CleanupBusy("volume verrouillé"), 75),
                                  (ValueError("bad digest"), 2), (OSError("unavailable"), 2)):
                clean.side_effect = failure
                self.assertEqual(cleanup.main(["partial", "--sha256", SHA256]), code)
                self.assertIn(str(failure), error.getvalue())

    def test_platform_and_argument_guards(self):
        with patch.object(sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                cleanup.clean("partial", SHA256)
        with patch.object(sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "64-digit"):
                cleanup.clean("partial", "wrong")
            with self.assertRaisesRegex(ValueError, "partial restore directory"):
                cleanup.clean(Path(Path.cwd().anchor), SHA256)

    def test_without_procfs_mount_identifier(self):
        with patch.object(Path, "read_text", return_value="flags: 0\n"):
            with self.assertRaisesRegex(ValueError, "Cannot identify"):
                cleanup._mount_id(10)


@unittest.skipIf(sys.platform.startswith("linux"), "Linux exercises these contracts with real file descriptors")
class PortableRestorePolicyTests(unittest.TestCase):
    """Exercise Linux' cleanup policy across runtimes without calling Linux syscalls."""

    def setUp(self):
        self.folder = SimpleNamespace(st_uid=42, st_mode=stat.S_IFDIR | 0o700)
        self.db = SimpleNamespace(st_uid=42, st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=len(CONTENT))
        self.parent = Mock(fd=10, path=Path.cwd())
        self.parent.open.return_value = 20
        self.fs = Mock(wraps=os, O_RDONLY=os.O_RDONLY, O_NOFOLLOW=0x20000, O_CLOEXEC=0x80000,
                       O_DIRECTORY=0x10000, O_NONBLOCK=0x800)
        self.fs.geteuid = Mock(return_value=42)
        self.fs.fstat.side_effect = lambda fd: self.folder if fd == 20 else self.db
        self.fs.listdir.return_value = [cleanup.SQLITE_NAME]
        self.fs.open.return_value = 30
        self.fs.fdopen.side_effect = self.database_reader
        self.fs.path = Mock()
        self.fs.path.samestat.side_effect = lambda actual, expected: actual is expected
        self.fs.stat.side_effect = lambda name, **options: self.db if name == cleanup.SQLITE_NAME else self.folder
        for operation in (self.fs.fsync, self.fs.unlink, self.fs.rmdir, self.fs.close):
            operation.return_value = None
        self.lock = Mock()
        self.lock.acquire.return_value = True
        parent_context = self.enterContext(patch.object(cleanup, "PinnedDirectory"))
        parent_context.return_value.__enter__.return_value = self.parent
        self.enterContext(patch.object(cleanup, "FileLock", return_value=self.lock))
        self.enterContext(patch.object(cleanup, "os", self.fs))
        self.enterContext(patch.object(sys, "platform", "linux"))
        self.mount = self.enterContext(patch.object(Path, "read_text", return_value="mnt_id:\t123\n"))

    @staticmethod
    def database_reader(fd, mode):
        data = io.BytesIO(CONTENT)
        data.fileno = lambda: fd
        return data

    def test_only_lock_owner_can_remove_the_checked_database(self):
        self.lock.acquire.return_value = False
        with self.assertRaisesRegex(cleanup.CleanupBusy, "volume verrouillé"):
            cleanup.clean("partial", SHA256)
        self.parent.open.assert_not_called()
        self.fs.unlink.assert_not_called()
        self.lock.close.assert_called_once()

        self.lock.acquire.return_value = True
        cleanup.clean("partial", SHA256.upper())
        self.fs.unlink.assert_called_once_with(cleanup.SQLITE_NAME, dir_fd=20)
        self.fs.rmdir.assert_called_once_with("partial", dir_fd=10)
        self.parent.sync.assert_called_once()
        self.assertEqual(self.lock.close.call_count, 2)

    def test_unsafe_inputs_fail_before_any_removal(self):
        for subject, field, value, message in (
            (self.folder, "st_uid", 43, "private directory"),
            (self.folder, "st_mode", 0o777, "private directory"),
            (self.db, "st_mode", stat.S_IFIFO, "owned regular file"),
            (self.db, "st_nlink", 2, "without hard links"),
            (self.db, "st_uid", 43, "owned regular file"),
            (self.db, "st_size", 0, "size is outside"),
            (self.db, "st_size", cleanup.MAX_SQLITE_BYTES + 1, "size is outside"),
        ):
            with self.subTest(field=field, value=value), patch.object(subject, field, value):
                with self.assertRaisesRegex(ValueError, message):
                    cleanup.clean("partial", SHA256)

        self.mount.side_effect = ["mnt_id:\t12\n", "mnt_id:\t13\n"]
        with self.assertRaisesRegex(ValueError, "mount point"):
            cleanup.clean("partial", SHA256)
        self.mount.side_effect = None
        self.fs.listdir.return_value = [cleanup.SQLITE_NAME, "audit.jsonl"]
        with self.assertRaisesRegex(ValueError, "contain only"):
            cleanup.clean("partial", SHA256)
        self.fs.listdir.return_value = [cleanup.SQLITE_NAME]
        with self.assertRaisesRegex(ValueError, "trusted digest"):
            cleanup.clean("partial", "0" * 64)
        self.fs.path.samestat.side_effect = None
        self.fs.path.samestat.return_value = False
        with self.assertRaisesRegex(ValueError, "entry changed"):
            cleanup.clean("partial", SHA256)
        self.fs.unlink.assert_not_called()
        self.fs.rmdir.assert_not_called()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux directory descriptor operations")
class LinuxRestoreCleanupTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.parent = Path(root.name)
        self.target = self.parent / "partial"
        self.target.mkdir(mode=0o700)
        self.db = self.target / cleanup.SQLITE_NAME
        self.db.write_bytes(CONTENT)

    def test_cleanup_and_lock_is_scoped_to_the_destination(self):
        key = hashlib.sha256(os.fsencode(self.target.name)).hexdigest()
        second = self.parent / "another"
        second.mkdir()
        (second / cleanup.SQLITE_NAME).write_bytes(CONTENT)
        with PinnedDirectory(self.parent, private=True) as parent:
            owner = cleanup.FileLock(parent.path / f".swassh-restore-{key}.lock", directory=parent)
            try:
                self.assertTrue(owner.acquire())
                with self.assertRaisesRegex(cleanup.CleanupBusy, "volume verrouillé"):
                    cleanup.clean(self.target, SHA256)
                self.assertEqual(self.db.read_bytes(), CONTENT)
                cleanup.clean(second, SHA256)
                self.assertFalse(second.exists())
            finally:
                owner.close()
        cleanup.clean(self.target, SHA256.upper())
        self.assertFalse(self.target.exists())
        self.assertTrue((self.parent / f".swassh-restore-{key}.lock").is_file())

    def test_wrong_hash_and_extra_entries_are_refused(self):
        with self.assertRaisesRegex(ValueError, "differs from the trusted digest"):
            cleanup.clean(self.target, "0" * 64)
        extra = self.target / "audit.jsonl"
        extra.touch()
        with self.assertRaisesRegex(ValueError, "contain only"):
            cleanup.clean(self.target, SHA256)
        self.assertEqual(self.db.read_bytes(), CONTENT)
        self.assertTrue(extra.is_file())

    def test_unsafe_paths_are_refused(self):
        alias = self.parent / "alias"
        alias.symlink_to(self.target, target_is_directory=True)
        with self.assertRaises(OSError):
            cleanup.clean(alias, SHA256)
        self.target.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "private directory"):
            cleanup.clean(self.target, SHA256)
        self.target.chmod(0o700)
        with patch.object(cleanup, "_mount_id", side_effect=["one", "two"]):
            with self.assertRaisesRegex(ValueError, "mount point"):
                cleanup.clean(self.target, SHA256)
        self.assertEqual(self.db.read_bytes(), CONTENT)

    def test_wrong_owner_is_refused(self):
        with PinnedDirectory(self.parent) as parent, patch.object(os, "geteuid", return_value=-1):
            with self.assertRaisesRegex(ValueError, "owned by the current account"):
                cleanup.PartialRestore(parent, self.target.name).remove(SHA256)

        uid = os.geteuid()
        with PinnedDirectory(self.parent) as parent, patch.object(os, "geteuid", side_effect=[uid, -1]):
            with self.assertRaisesRegex(ValueError, "owned regular file"):
                cleanup.PartialRestore(parent, self.target.name).remove(SHA256)
        self.assertEqual(self.db.read_bytes(), CONTENT)

    def test_unexpected_sqlite_type_link_or_size_does_not_get_removed(self):
        self.db.unlink()
        os.mkfifo(self.db)
        with self.assertRaisesRegex(ValueError, "regular file"):
            cleanup.clean(self.target, SHA256)
        self.db.unlink()
        original = self.parent / "original"
        original.write_bytes(CONTENT)
        os.link(original, self.db)
        with self.assertRaisesRegex(ValueError, "without hard links"):
            cleanup.clean(self.target, SHA256)
        self.assertEqual(original.read_bytes(), CONTENT)
        self.db.unlink()
        self.db.touch()
        with self.assertRaisesRegex(ValueError, "size is outside"):
            cleanup.clean(self.target, SHA256)
        self.db.write_bytes(CONTENT)
        with patch.object(cleanup, "MAX_SQLITE_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "size is outside"):
                cleanup.clean(self.target, SHA256)
        self.assertEqual(self.db.read_bytes(), CONTENT)

    def test_changes_to_the_checked_entry_are_detected(self):
        with patch.object(os.path, "samestat", return_value=False):
            with self.assertRaisesRegex(ValueError, "entry changed"):
                cleanup.clean(self.target, SHA256)
        self.assertEqual(self.db.read_bytes(), CONTENT)
