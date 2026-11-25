"""Verify the Linux restore command, exact snapshot contents and refusal boundaries."""

from contextlib import closing, nullcontext, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from swassh.infrastructure.database.migration.workflows_v1 import WorkflowSchema
from swassh.interfaces import restore_workflows as restore


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DirectoryFixture:
    """Use local files on non-Linux hosts while substituting descriptor-relative calls."""

    _name = staticmethod(restore.PinnedDirectory._name)

    def __init__(self, path, **options):
        self.path = self.fd = Path(path)

    def __enter__(self):
        return self

    def __exit__(self, *error):
        return None

    def open(self, name, flags):
        return os.open(self.path / name, flags)

    def sync(self):
        self.path.stat()


class RestoreWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.backup = self.root / "backup"
        self.backup.mkdir(mode=0o700)
        self.target = self.root / "restored"
        self.manifest = self.root / "snapshot.json"
        self.database = self.backup / restore.SQLITE_NAME
        with closing(sqlite3.connect(self.database)) as db:
            WorkflowSchema.up(db)
            db.commit()
        self.report = self.backup / "runs/one/step/report.json"
        self.report.parent.mkdir(parents=True)
        self.report.write_text("{}", encoding="utf-8")
        self.files = {restore.SQLITE_NAME: digest(self.database),
                      "runs/one/step/report.json": digest(self.report)}
        self.write_manifest(self.files)
        if not sys.platform.startswith("linux"):
            shim = Mock(wraps=os)
            # TemporaryDirectory and the staged files use the real OS. These
            # three calls model Linux's descriptor-relative directory commit.
            def mkdir(name, mode, *, dir_fd):
                (dir_fd / name).mkdir(mode=mode)

            def rmdir(name, *, dir_fd):
                (dir_fd / name).rmdir()

            def rename(source, name, *, dst_dir_fd):
                target = dst_dir_fd / name
                target.rmdir()
                source.rename(target)

            shim.mkdir.side_effect = mkdir
            shim.rmdir.side_effect = rmdir
            shim.rename.side_effect = rename
            self.enterContext(patch.object(restore, "os", shim))
            self.enterContext(patch.object(restore, "PinnedDirectory", DirectoryFixture))
            self.enterContext(patch.object(restore, "locked_destination",
                                           lambda target: nullcontext(DirectoryFixture(target.parent))))
            self.enterContext(patch.object(sys, "platform", "linux"))

    def write_manifest(self, data):
        self.manifest.write_text(json.dumps(data), encoding="utf-8")

    def restore(self):
        restore.restore(self.backup, self.target, self.manifest)

    def verify_no_staging(self):
        self.assertEqual(list(self.root.glob(".swassh-restore-*/")), [])

    def test_verified_snapshot_commits_and_a_second_restore_preserves_it(self):
        pending = self.backup / "runs/one/pending"
        pending.mkdir()
        self.write_manifest({name: sha.upper() for name, sha in self.files.items()})
        self.restore()
        self.assertEqual({item.relative_to(self.target).as_posix(): digest(item)
                          for item in self.target.rglob("*") if item.is_file()}, self.files)
        self.assertTrue((self.target / pending.relative_to(self.backup)).is_dir())
        with self.assertRaisesRegex(ValueError, "new directory"):
            self.restore()
        self.assertEqual(self.target.joinpath(restore.SQLITE_NAME).read_bytes(), self.database.read_bytes())
        self.verify_no_staging()

    def test_manifest_rejects_invalid_entries_before_creating_the_target(self):
        key = restore.SQLITE_NAME
        checksum = self.files[key]
        for name in ("", "/outside", "runs//report", "runs/../report", "runs/bad\\path", "runs/bad\0path",
                     "workflows.sqlite-wal", "worker.lock"):
            with self.subTest(name=name):
                self.write_manifest({key: checksum, name: checksum})
                with self.assertRaisesRegex(ValueError, "backup member path|Unexpected workflow snapshot member"):
                    self.restore()
                self.assertFalse(self.target.exists())
        for value in (None, "0" * 63):
            self.write_manifest({key: value})
            with self.assertRaisesRegex(ValueError, "member SHA-256"):
                self.restore()
        for manifest in ([], {"workflow.jsonl": checksum}):
            self.write_manifest(manifest)
            with self.assertRaisesRegex(ValueError, "must include"):
                self.restore()
        self.manifest.write_text(f'{{"{key}":"{checksum}","{key}":"{checksum}"}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            self.restore()
        with patch.object(restore, "MAX_MANIFEST_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "manifest exceeds"):
                self.restore()
        self.assertFalse(self.target.exists())
        self.verify_no_staging()

    def test_changed_or_oversized_snapshots_leave_the_new_destination_absent(self):
        original = self.database.read_bytes()
        self.database.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "SHA-256 verification failed"):
            self.restore()
        self.assertFalse(self.target.exists())
        self.database.write_bytes(original)
        with patch.object(restore, "MAX_SQLITE_BYTES", len(original) - 1):
            with self.assertRaisesRegex(ValueError, "restore size limit"):
                self.restore()
        unexpected = self.backup / "extra"
        unexpected.touch()
        with self.assertRaisesRegex(ValueError, "directory differs"):
            self.restore()
        unexpected.unlink()
        unexpected = self.backup / "runs/extra.json"
        unexpected.touch()
        with self.assertRaisesRegex(ValueError, "directory differs"):
            self.restore()
        unexpected.unlink()
        with patch.object(restore, "MAX_SNAPSHOT_DIRECTORIES", 1):
            with self.assertRaisesRegex(ValueError, "directory limit"):
                self.restore()
        self.report.unlink()
        with self.assertRaisesRegex(ValueError, "missing a declared file"):
            self.restore()
        os.link(self.database, self.report)
        with self.assertRaisesRegex(ValueError, "without hard links"):
            self.restore()
        self.assertFalse(self.target.exists())
        self.verify_no_staging()

    def test_checked_inventory_never_admits_untrusted_directory_aliases(self):
        original = restore.PinnedDirectory
        # Report an unexpected path from the pinning boundary. The restore
        # must reject it before listing a substitute directory.
        with original(self.backup) as pinned:
            alias = Mock(wraps=pinned)
            alias.path = self.root / "other"
            context = nullcontext(alias)
            with patch.object(restore, "PinnedDirectory", side_effect=[context]) as pins:
                operation = restore.WorkflowRestore(self.backup, restore.load_manifest(self.manifest))
                with self.assertRaisesRegex(ValueError, "directory differs"):
                    operation.stage(self.target)
                pins.assert_called_once_with(self.backup, private=True)
        self.assertFalse(self.target.exists())

    def test_invalid_workflow_sqlite_is_refused_even_with_its_correct_digest(self):
        with closing(sqlite3.connect(self.database)) as db:
            db.execute("PRAGMA application_id=0")
            db.commit()
        self.write_manifest(self.files | {restore.SQLITE_NAME: digest(self.database)})
        with self.assertRaisesRegex(ValueError, "Invalid workflow SQLite snapshot"):
            self.restore()
        self.assertFalse(self.target.exists())
        self.verify_no_staging()

    def test_quick_check_must_report_ok_before_workflow_schema_validation(self):
        connection = Mock()
        connection.execute.side_effect = (
            Mock(), Mock(**{"fetchone.return_value": (restore.APPLICATION_ID,)}),
            Mock(**{"fetchone.return_value": (1,)}),
            Mock(**{"fetchall.return_value": [("malformed index",)]}),
        )
        with patch.object(sqlite3, "connect", return_value=connection), patch.object(WorkflowSchema, "up") as schema:
            with self.assertRaisesRegex(ValueError, "Invalid workflow SQLite snapshot"):
                restore.validate_database(self.database)
            schema.assert_not_called()
            connection.close.assert_called_once()

    def test_nonregular_file_and_failed_commit_do_not_publish(self):
        info = os.stat(self.manifest)
        with patch.object(restore.os, "fstat", return_value=self.backup.stat()):
            with self.assertRaisesRegex(ValueError, "regular backup file"):
                restore.load_manifest(self.manifest)
        self.assertEqual(self.manifest.stat().st_ino, info.st_ino)
        with patch.object(restore.os, "rename", side_effect=OSError("injected rename failure")):
            with self.assertRaisesRegex(OSError, "injected rename failure"):
                self.restore()
        self.assertFalse(self.target.exists())
        self.assertEqual(digest(self.database), self.files[restore.SQLITE_NAME])
        self.verify_no_staging()

    def test_cli_reports_refusal_and_preserves_its_exit_contract(self):
        with patch.object(sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, "requires Linux"):
                self.restore()
        arguments = [str(self.backup), str(self.target), "--manifest", str(self.manifest)]
        errors = io.StringIO()
        with redirect_stderr(errors), patch.object(restore, "restore") as perform:
            self.assertEqual(restore.main(arguments), 0)
            perform.assert_called_once_with(str(self.backup), str(self.target), str(self.manifest))
            for failure, expected in ((restore.CleanupBusy("volume verrouillé"), 75),
                                      (OSError("unreadable"), 2), (ValueError("invalid"), 2),
                                      (sqlite3.DatabaseError("corrupt"), 2), (RecursionError("bad JSON"), 2)):
                perform.side_effect = failure
                self.assertEqual(restore.main(arguments), expected)
                self.assertIn(str(failure), errors.getvalue())
