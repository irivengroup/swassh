"""Failed OS-lock construction must release its already opened file handle."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from swassh.infrastructure.audit import _WriterLock
from swassh import Options
from swassh.infrastructure.convergence import SQLiteConvergenceJournal
from swassh.infrastructure.bandwidth import SQLiteByteBudget
import os
import stat


class LockConstructionCleanupTests(unittest.TestCase):
    def test_early_file_errors_release_the_handle_before_propagating(self):
        for operation in ('fileno', 'write', 'flush', 'seek'):
            stream = MagicMock()
            getattr(stream, operation).side_effect = OSError('synthetic file failure')
            with self.subTest(operation=operation), \
                    patch('swassh.infrastructure.audit._private_open', return_value=stream), \
                    patch('swassh.infrastructure.audit.os.fstat', return_value=SimpleNamespace(st_size=0)):
                with self.assertRaises(OSError):
                    _WriterLock(Path('unused-lock-boundary'))
                stream.close.assert_called_once_with()


class DatabaseConstructionCleanupTests(unittest.TestCase):
    """Both failures are synthetic boundary I/O; no real file or database opens."""
    def test_secondary_rollback_failure_cannot_skip_connection_close(self):
        root=Path(os.path.abspath('synthetic-unit-root'))
        for module in ('convergence','bandwidth'):
            db=MagicMock()
            db.execute.side_effect=OSError('synthetic initialization failure')
            db.rollback.side_effect=OSError('synthetic rollback failure')
            coordinator=MagicMock(directory=root,policy=[32,20,512*1024**2,10240])
            prefix='swassh.infrastructure.'+module
            with self.subTest(module=module):
                with patch(prefix+'.open_private_append',return_value=MagicMock()), \
                        patch(prefix+'.sqlite3.connect',return_value=db), \
                        patch.object(Path,'stat',return_value=SimpleNamespace(st_size=0,st_mode=stat.S_IFREG|0o600)):
                    if module=='convergence':
                        with patch(prefix+'.private_directory',return_value=root):
                            journal=SQLiteConvergenceJournal(Options(),directory=root)
                            with self.assertRaisesRegex(OSError,'rollback failure'): journal._open()
                    else:
                        # The byte adapter now acquires an OS mutex before
                        # opening SQLite. Keep this unit test entirely at its
                        # synthetic I/O boundaries; real locks/crash recovery
                        # are exercised in test_bandwidth integration tests.
                        with patch(prefix+'.SharedBudget',return_value=coordinator), \
                                patch(prefix+'.FileLock') as mutex:
                            mutex.return_value.acquire.return_value=True
                            with self.assertRaisesRegex(OSError,'rollback failure'): SQLiteByteBudget({})
                            mutex.return_value.close.assert_called_once_with()
                db.close.assert_called_once_with()
